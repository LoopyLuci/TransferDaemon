use crate::types::{Gsn, SessionId};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone)]
pub struct Chunk {
    pub gsn: Gsn,
    pub session_id: SessionId,
    pub payload: Bytes,
    pub key_epoch: u8,
    /// When true, the ATE will mirror this chunk on a second lane for redundancy.
    pub qos_critical: bool,
}

pub struct LaneMetrics {
    pub rtt_ms: AtomicU64,
    pub bandwidth_bps: AtomicU64,
    pub active_chunks: AtomicU64,
    pub errors_total: AtomicU64,
    alive: AtomicBool,
}

impl Default for LaneMetrics {
    fn default() -> Self {
        Self {
            rtt_ms: AtomicU64::new(0),
            bandwidth_bps: AtomicU64::new(0),
            active_chunks: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
            alive: AtomicBool::new(true), // lanes start alive
        }
    }
}

impl LaneMetrics {
    pub fn new_alive() -> Self { Self::default() }

    pub fn update_rtt(&self, rtt_ms: f64) {
        self.rtt_ms.store((rtt_ms * 1000.0) as u64, Ordering::Relaxed);
    }
    pub fn update_bandwidth(&self, bps: f64) {
        self.bandwidth_bps.store(bps as u64, Ordering::Relaxed);
    }
    pub fn inc_active(&self) { self.active_chunks.fetch_add(1, Ordering::Relaxed); }
    pub fn dec_active(&self) { self.active_chunks.fetch_sub(1, Ordering::Relaxed); }

    /// Increments the error counter and marks the lane dead if it exceeds `threshold`.
    pub fn record_error(&self, threshold: u64) {
        let errs = self.errors_total.fetch_add(1, Ordering::Relaxed) + 1;
        if errs >= threshold {
            self.alive.store(false, Ordering::Relaxed);
        }
    }

    pub fn mark_dead(&self) { self.alive.store(false, Ordering::Relaxed); }
    pub fn is_healthy(&self) -> bool { self.alive.load(Ordering::Relaxed) }
}

#[async_trait]
pub trait TransportLane: Send + Sync {
    fn id(&self) -> u32;
    fn metrics(&self) -> Arc<LaneMetrics>;
    async fn send(&self, chunk: Chunk) -> Result<(), TransportError>;
    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>>;
    fn capacity(&self) -> usize;
    fn is_alive(&self) -> bool;
}

/// Chunk serialized for the wire (inside encrypted lane frames).
///
/// Both `RelayLane` and `TcpLane` use this layout so encrypted payloads are
/// interchangeable — the ATE can switch lanes without re-encoding.
#[derive(Serialize, Deserialize)]
pub struct WireChunk {
    pub gsn: u64,
    pub session_id: [u8; 16],
    pub payload: Vec<u8>,
    pub key_epoch: u8,
    pub qos_critical: bool,
}

impl From<&Chunk> for WireChunk {
    fn from(c: &Chunk) -> Self {
        WireChunk {
            gsn: c.gsn.0,
            session_id: c.session_id.0,
            payload: c.payload.to_vec(),
            key_epoch: c.key_epoch,
            qos_critical: c.qos_critical,
        }
    }
}

impl From<WireChunk> for Chunk {
    fn from(w: WireChunk) -> Self {
        Chunk {
            gsn: Gsn(w.gsn),
            session_id: SessionId(w.session_id),
            payload: Bytes::from(w.payload),
            key_epoch: w.key_epoch,
            qos_critical: w.qos_critical,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("Link down: {0}")]
    LinkDown(String),
    #[error("Lane saturated")]
    Saturated,
    #[error("Protocol violation")]
    ProtocolViolation,
    #[error("Encryption error")]
    Encrypted,
}
