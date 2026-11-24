//! WebSocket relay lane — routes chunks through a blind WS relay (`relayd-ws`
//! or the Cloudflare Worker). Same chunk framing as the UDP relay lane; only
//! the transport is WebSocket, so it works where UDP is blocked.

use crate::lanes::relay_ws_client::RelayWsClient;
use crate::lanes::relay_client::PREFIX_CHUNK;
use crate::transport::{Chunk, LaneMetrics, TransportError, TransportLane, WireChunk};
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use transferd_crypto::DmiEncryptor;

/// A `TransportLane` that routes chunks through a WebSocket relay server.
///
/// Encrypts with `send_key`; the relay forwards opaque frames to the peer.
/// Registration + inbound are owned by the relay hub.
pub struct RelayWsLane {
    id: u32,
    metrics: Arc<LaneMetrics>,
    client: Arc<RelayWsClient>,
    forward_token: [u8; 32],
    self_token: [u8; 32],
    seq: AtomicU64,
    encryptor: Arc<Mutex<DmiEncryptor>>,
    inbox: Mutex<mpsc::Receiver<Chunk>>,
    alive: Arc<AtomicBool>,
}

impl RelayWsLane {
    pub async fn new(
        id: u32,
        client: Arc<RelayWsClient>,
        self_token: [u8; 32],
        forward_token: [u8; 32],
        send_key: &[u8; 32],
    ) -> Self {
        let encryptor = Arc::new(Mutex::new(DmiEncryptor::new(send_key)));
        let alive = Arc::new(AtomicBool::new(true));
        let metrics = Arc::new(LaneMetrics::default());
        metrics.bandwidth_bps.store(10_000_000, Ordering::Relaxed);
        metrics.rtt_ms.store(20_000, Ordering::Relaxed);

        let (_tx, rx) = mpsc::channel::<Chunk>(256);

        Self {
            id,
            metrics,
            client,
            forward_token,
            self_token,
            seq: AtomicU64::new(0),
            encryptor,
            inbox: Mutex::new(rx),
            alive,
        }
    }

    pub fn client(&self) -> &Arc<RelayWsClient> {
        &self.client
    }
}

#[async_trait]
impl TransportLane for RelayWsLane {
    fn id(&self) -> u32 { self.id }
    fn metrics(&self) -> Arc<LaneMetrics> { self.metrics.clone() }
    fn capacity(&self) -> usize { if self.alive.load(Ordering::Relaxed) { 64 } else { 0 } }
    fn is_alive(&self) -> bool { self.alive.load(Ordering::Relaxed) }

    async fn send(&self, chunk: Chunk) -> Result<(), TransportError> {
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

/// Power-of-two padding with a 4-byte LE length header (matches RelayLane).
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