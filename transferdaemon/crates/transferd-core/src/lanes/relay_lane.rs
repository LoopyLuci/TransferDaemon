//! UDP relay lane — sends and receives chunks via the blind `relayd` relay server.
//!
//! Wire layout inside `ForwardMsg::ciphertext`:
//!   [nonce: 12 bytes][gcm_tag: 16 bytes][bincode(WireChunk): N bytes]
//!
//! The relay is agnostic to this layout; it forwards the bytes opaquely.

use crate::transport::{Chunk, LaneMetrics, TransportError, TransportLane, WireChunk};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use transferd_crypto::{DmiDecryptor, DmiEncryptor};

// ---------------------------------------------------------------------------
// Inline wire types — identical layout to relayd::protocol structs.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct RegisterMsg {
    session_token: [u8; 32],
    pow_nonce: u64,
    seq: u32,
}

#[derive(Serialize, Deserialize)]
struct ForwardMsg {
    session_token: [u8; 32],
    pow_nonce: u64,
    sender_seq: u16,
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct DeliveredMsg {
    sender_seq: u16,
    ciphertext: Vec<u8>,
}

const TAG_REGISTER: u8 = 0x01;
const TAG_FORWARD: u8  = 0x02;
const TAG_ACK: u8      = 0x06; // relay uses Ack tag for both AckMsg and DeliveredMsg

fn encode_frame<T: Serialize>(tag: u8, msg: &T) -> Vec<u8> {
    let body = bincode::serialize(msg).unwrap_or_default();
    let mut frame = Vec::with_capacity(1 + body.len());
    frame.push(tag);
    frame.extend_from_slice(&body);
    frame
}

// ---------------------------------------------------------------------------
// RelayLane
// ---------------------------------------------------------------------------

/// A `TransportLane` that routes chunks through a blind UDP relay server.
///
/// One `RelayLane` covers both roles:
/// - **Sender side**: calls `send()`, which wraps the encrypted chunk in a `ForwardMsg`
///   addressed to the recipient's `forward_token`.
/// - **Receiver side**: a background task feeds `recv()` by decoding `DeliveredMsg`
///   datagrams arriving from the relay.
pub struct RelayLane {
    id: u32,
    metrics: Arc<LaneMetrics>,
    socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    /// Token placed in `ForwardMsg.session_token` — routes to the registered peer.
    forward_token: [u8; 32],
    seq: AtomicU64,
    encryptor: Arc<Mutex<DmiEncryptor>>,
    /// Decoded chunks waiting to be consumed by `recv()`.
    inbox: Mutex<mpsc::Receiver<Chunk>>,
    alive: Arc<AtomicBool>,
}

impl RelayLane {
    /// Creates a relay lane and optionally registers `self_token` with the relay.
    ///
    /// - `self_token`: the token the relay uses to route inbound messages *to us*.
    ///   Pass `None` for a send-only lane that never receives.
    /// - `forward_token`: the token the relay uses to route our outbound messages
    ///   *to the peer* (= the peer's registered `self_token`).
    /// - `difficulty`: PoW difficulty; use `0` in tests.
    pub async fn new(
        id: u32,
        relay_addr: SocketAddr,
        self_token: Option<[u8; 32]>,
        forward_token: [u8; 32],
        session_key: &[u8; 32],
        difficulty: u32,
    ) -> Result<Self, std::io::Error> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let encryptor = Arc::new(Mutex::new(DmiEncryptor::new(session_key)));
        let decryptor = Arc::new(Mutex::new(DmiDecryptor::new(session_key)));
        let alive = Arc::new(AtomicBool::new(true));
        let metrics = Arc::new(LaneMetrics::default());
        // Default metrics: ~10 Mbps, 20 ms RTT
        metrics.bandwidth_bps.store(10_000_000, Ordering::Relaxed);
        metrics.rtt_ms.store(20_000, Ordering::Relaxed); // stored as µs (×1000)

        // Register our own token with the relay so the peer can forward to us.
        if let Some(self_tok) = self_token {
            let pow_nonce = solve_pow(difficulty, &[0u8; 16], &self_tok);
            let reg = encode_frame(
                TAG_REGISTER,
                &RegisterMsg { session_token: self_tok, pow_nonce, seq: 0 },
            );
            socket.send_to(&reg, relay_addr).await?;
            // Drain the challenge/ack response (fire-and-forget in tests).
            let mut tmp = [0u8; 512];
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                socket.recv_from(&mut tmp),
            ).await;
        }

        let (tx, rx) = mpsc::channel::<Chunk>(256);

        // Background receive task.
        {
            let socket = socket.clone();
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
            socket,
            relay_addr,
            forward_token,
            seq: AtomicU64::new(0),
            encryptor,
            inbox: Mutex::new(rx),
            alive,
        })
    }
}

#[async_trait]
impl TransportLane for RelayLane {
    fn id(&self) -> u32 { self.id }
    fn metrics(&self) -> Arc<LaneMetrics> { self.metrics.clone() }
    fn capacity(&self) -> usize { if self.alive.load(Ordering::Relaxed) { 64 } else { 0 } }
    fn is_alive(&self) -> bool { self.alive.load(Ordering::Relaxed) }

    async fn send(&self, chunk: Chunk) -> Result<(), TransportError> {
        // Serialize the chunk.
        let wire = WireChunk::from(&chunk);
        let plaintext = bincode::serialize(&wire)
            .map_err(|_| TransportError::ProtocolViolation)?;

        // Encrypt: [nonce(12) | gcm_tag(16) | ciphertext].
        // AAD = plaintext length as little-endian u64 (simple, reconstructible from ciphertext length).
        let gsn = chunk.gsn.0;
        let nonce = DmiEncryptor::nonce_for(gsn, chunk.key_epoch);
        let aad = (plaintext.len() as u64).to_le_bytes();

        let (gcm_tag, ciphertext) = {
            let enc = self.encryptor.lock().await;
            let mut buf = plaintext.clone();
            let tag = enc.encrypt_detached(&mut buf, &nonce, &aad)
                .map_err(|_| TransportError::Encrypted)?;
            (tag, buf)
        };

        let mut payload = Vec::with_capacity(12 + 16 + ciphertext.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&gcm_tag);
        payload.extend_from_slice(&ciphertext);

        let seq = (self.seq.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
        let fwd = encode_frame(
            TAG_FORWARD,
            &ForwardMsg {
                session_token: self.forward_token,
                pow_nonce: 0, // difficulty=0 in relay, or pre-solved
                sender_seq: seq,
                ciphertext: payload,
            },
        );

        self.socket
            .send_to(&fwd, self.relay_addr)
            .await
            .map_err(|e| TransportError::LinkDown(e.to_string()))?;

        Ok(())
    }

    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>> {
        self.inbox.lock().await.recv().await.map(Ok)
    }
}

// ---------------------------------------------------------------------------
// Background receive task
// ---------------------------------------------------------------------------

async fn recv_task(
    socket: Arc<UdpSocket>,
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
        if tag != TAG_ACK { continue; }

        // The relay sends DeliveredMsg and AckMsg both with TAG_ACK.
        // DeliveredMsg has a non-empty ciphertext Vec; AckMsg has only sender_seq.
        let Ok(delivered) = bincode::deserialize::<DeliveredMsg>(body) else { continue };
        if delivered.ciphertext.len() <= 28 {
            // Too short to contain nonce(12)+tag(16)+any data — it's a bare Ack.
            continue;
        }

        // Decrypt: payload = [nonce(12) | gcm_tag(16) | encrypted_chunk]
        let raw = &delivered.ciphertext;
        if raw.len() < 28 { continue; }
        let nonce: [u8; 12] = raw[..12].try_into().unwrap();
        let gcm_tag: [u8; 16] = raw[12..28].try_into().unwrap();
        let mut ct = raw[28..].to_vec();

        let dec_result = {
            let dec = decryptor.lock().await;
            // AAD = ciphertext length as u64 LE (same as sender).
            let aad = (ct.len() as u64).to_le_bytes();
            dec.decrypt_verify(&mut ct, &nonce, &gcm_tag, &aad)
        };

        if dec_result.is_err() {
            metrics.record_error(10);
            continue;
        }

        let Ok(wire) = bincode::deserialize::<WireChunk>(&ct) else { continue };
        let chunk = Chunk::from(wire);

        if tx.send(chunk).await.is_err() {
            break; // receiver dropped
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal PoW solver (difficulty=0 → nonce=0 always works)
// ---------------------------------------------------------------------------

fn solve_pow(difficulty: u32, challenge: &[u8; 16], token: &[u8; 32]) -> u64 {
    if difficulty == 0 { return 0; }
    for nonce in 0u64.. {
        let mut h = blake3::Hasher::new();
        h.update(challenge);
        h.update(token);
        h.update(&nonce.to_le_bytes());
        let hash = h.finalize();
        let bytes = hash.as_bytes();
        let full = (difficulty / 8) as usize;
        let tail = difficulty % 8;
        let ok = bytes[..full.min(bytes.len())].iter().all(|&b| b == 0)
            && (tail == 0 || full >= bytes.len() || bytes[full] >> (8 - tail) == 0);
        if ok { return nonce; }
    }
    0
}
