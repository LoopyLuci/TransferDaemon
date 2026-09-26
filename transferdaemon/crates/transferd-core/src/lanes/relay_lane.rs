//! UDP relay lane — sends and receives chunks via the blind `relayd` relay server.
//!
//! Wire layout inside `ForwardMsg::ciphertext` (the relay forwards this opaquely):
//!   [prefix: 1 byte][sender_token: 32 bytes][nonce: 12][gcm_tag: 16][padded ciphertext]
//!
//! `prefix` distinguishes handshake payloads (`0x01`) from encrypted chunks
//! (`0x02`). `sender_token` lets the recipient identify which session key to
//! use for decryption. The plaintext is power-of-two padded before encryption so
//! the relay only ever sees fixed-grid ciphertext sizes (CONTEXT.md #5).

use crate::lanes::relay_client::{RelayClient, PREFIX_CHUNK};
use crate::transport::{Chunk, LaneMetrics, TransportError, TransportLane, WireChunk};
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use transferd_crypto::{DmiDecryptor, DmiEncryptor};

// ---------------------------------------------------------------------------
// RelayLane
// ---------------------------------------------------------------------------

/// A `TransportLane` that routes chunks through a blind UDP relay server.
///
/// Encrypts with `send_key`, decrypts with `recv_key` (the peer's direction).
/// Owns a `RelayClient` that handles PoW, registration (when `self_token` is
/// `Some`) and keepalive. A background task feeds `recv()`.
pub struct RelayLane {
    id: u32,
    metrics: Arc<LaneMetrics>,
    client: Arc<RelayClient>,
    /// Token that routes our outbound messages to the peer.
    forward_token: [u8; 32],
    /// Token the relay uses to route inbound messages to us (prefix marker).
    self_token: [u8; 32],
    seq: AtomicU64,
    encryptor: Arc<Mutex<DmiEncryptor>>,
    inbox: Mutex<mpsc::Receiver<Chunk>>,
    alive: Arc<AtomicBool>,
}

impl RelayLane {
    /// Creates a relay lane to the peer registered under `forward_token`.
    ///
    /// - `self_token`: our own token, placed in every outbound frame so the peer
    ///   can identify us. `[0u8; 32]` is not allowed (a zero token is ambiguous).
    /// - `send_key` / `recv_key`: per-direction AES keys.
    /// - `self_token` is registered with the relay when `register` is `true`.
    pub async fn new(
        id: u32,
        relay_addr: std::net::SocketAddr,
        self_token: [u8; 32],
        forward_token: [u8; 32],
        send_key: &[u8; 32],
        recv_key: &[u8; 32],
        register: bool,
    ) -> Result<Self, std::io::Error> {
        let client = Arc::new(RelayClient::bind(relay_addr).await?);

        if register {
            client.register(self_token).await?;
            client.spawn_keepalive_loop(self_token);
        }

        let encryptor = Arc::new(Mutex::new(DmiEncryptor::new(send_key)));
        let decryptor = Arc::new(Mutex::new(DmiDecryptor::new(recv_key)));
        let alive = Arc::new(AtomicBool::new(true));
        let metrics = Arc::new(LaneMetrics::default());
        // Default metrics: ~10 Mbps, 20 ms RTT
        metrics.bandwidth_bps.store(10_000_000, Ordering::Relaxed);
        metrics.rtt_ms.store(20_000, Ordering::Relaxed); // stored as µs (×1000)

        let (tx, rx) = mpsc::channel::<Chunk>(256);

        // Background receive task: decode DeliveredMsg datagrams addressed to us.
        {
            let socket = client.socket();
            let decryptor = decryptor.clone();
            let alive = alive.clone();
            let metrics = metrics.clone();
            tokio::spawn(async move {
                recv_task(socket, decryptor, tx, alive, metrics).await;
            });
        }

        Ok(Self {
            id,
            metrics,
            client,
            forward_token,
            self_token,
            seq: AtomicU64::new(0),
            encryptor,
            inbox: Mutex::new(rx),
            alive,
        })
    }

    /// The underlying relay client (for handshake or raw access by the daemon).
    pub fn client(&self) -> &Arc<RelayClient> {
        &self.client
    }
}

#[async_trait]
impl TransportLane for RelayLane {
    fn id(&self) -> u32 { self.id }
    fn metrics(&self) -> Arc<LaneMetrics> { self.metrics.clone() }
    fn capacity(&self) -> usize { if self.alive.load(Ordering::Relaxed) { 64 } else { 0 } }
    fn is_alive(&self) -> bool { self.alive.load(Ordering::Relaxed) }

    async fn send(&self, chunk: Chunk) -> Result<(), TransportError> {
        // Serialize + pad the chunk plaintext to the next power-of-two grid.
        let wire = WireChunk::from(&chunk);
        let raw = bincode::serialize(&wire)
            .map_err(|_| TransportError::ProtocolViolation)?;
        let plaintext = pad_plaintext(&raw);

        let gsn = chunk.gsn.0;
        let nonce = DmiEncryptor::nonce_for(gsn, chunk.key_epoch);
        let aad = (plaintext.len() as u64).to_le_bytes();

        let (gcm_tag, ciphertext) = {
            let enc = self.encryptor.lock().await;
            let mut buf = plaintext;
            let tag = enc
                .encrypt_detached(&mut buf, &nonce, &aad)
                .map_err(|_| TransportError::Encrypted)?;
            (tag, buf)
        };

        // Frame: [0x02][sender_token: 32][nonce: 12][tag: 16][ciphertext]
        let mut payload = Vec::with_capacity(1 + 32 + 12 + 16 + ciphertext.len());
        payload.push(PREFIX_CHUNK);
        payload.extend_from_slice(&self.self_token);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&gcm_tag);
        payload.extend_from_slice(&ciphertext);

        self.client
            .send_forward(self.forward_token, &payload)
            .await
            .map_err(|e| TransportError::LinkDown(e.to_string()))?;

        let _ = self.seq.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>> {
        self.inbox.lock().await.recv().await.map(Ok)
    }

    async fn try_recv(&mut self) -> Option<Result<Chunk, TransportError>> {
        use tokio::sync::mpsc::error::TryRecvError;
        match self.inbox.lock().await.try_recv() {
            Ok(chunk) => Some(Ok(chunk)),
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Background receive task
// ---------------------------------------------------------------------------

async fn recv_task(
    socket: Arc<tokio::net::UdpSocket>,
    decryptor: Arc<Mutex<DmiDecryptor>>,
    tx: mpsc::Sender<Chunk>,
    alive: Arc<AtomicBool>,
    metrics: Arc<LaneMetrics>,
) {
    let mut buf = vec![0u8; 65536];
    while alive.load(Ordering::Relaxed) {
        let Ok((len, _)) = socket.recv_from(&mut buf).await else { break };
        let frame = &buf[..len];
        let Some((&tag, body)) = frame.split_first() else { continue };
        if tag != relayd::protocol::Tag::Ack as u8 {
            continue;
        }
        let Ok(delivered) = bincode::deserialize::<relayd::protocol::DeliveredMsg>(body) else {
            continue;
        };
        // Bare ack (only sender_seq) is too short to contain a chunk.
        if delivered.ciphertext.len() <= 33 {
            continue;
        }
        // Layout: [0x02][sender_token:32][nonce:12][tag:16][ciphertext]
        let raw = &delivered.ciphertext;
        if raw[0] != PREFIX_CHUNK {
            continue; // handshake or unknown — not our lane's chunk
        }
        if raw.len() < 1 + 32 + 28 {
            continue;
        }
        let Ok(nonce) = <[u8; 12]>::try_from(&raw[33..45]) else { continue };
        let Ok(gcm_tag) = <[u8; 16]>::try_from(&raw[45..61]) else { continue };
        let mut ct = raw[61..].to_vec();

        let dec_result = {
            let dec = decryptor.lock().await;
            let aad = (ct.len() as u64).to_le_bytes();
            dec.decrypt_verify(&mut ct, &nonce, &gcm_tag, &aad)
        };
        if dec_result.is_err() {
            metrics.record_error(10);
            continue;
        }

        let Some(plaintext) = unpad_plaintext(&ct) else { continue };
        let Ok(wire) = bincode::deserialize::<WireChunk>(&plaintext) else { continue };
        let chunk = Chunk::from(wire);

        if tx.send(chunk).await.is_err() {
            break; // receiver dropped
        }
    }
}

// ---------------------------------------------------------------------------
// Power-of-two padding (hides message sizes from the relay)
// ---------------------------------------------------------------------------

/// Pad `data` to the next power of two with a 4-byte LE length header.
fn pad_plaintext(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut power = 32usize;
    while power < data.len() + 4 {
        power *= 2;
    }
    let mut out = Vec::with_capacity(power);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    out.resize(power, 0);
    out
}

/// Strip the length header + padding added by `pad_plaintext`.
fn unpad_plaintext(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
    if 4 + len > data.len() {
        return None;
    }
    Some(data[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_roundtrip() {
        for size in [1, 10, 28, 100, 512, 2000, 100_000] {
            let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let padded = pad_plaintext(&data);
            assert!(padded.len().is_power_of_two(), "len {} must be power of two", padded.len());
            assert_eq!(unpad_plaintext(&padded).unwrap(), data);
        }
    }
}