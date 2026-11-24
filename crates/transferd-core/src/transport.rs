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

/// Control-plane messages exchanged over a lane (acks, RTT pings).
///
/// Transport-level acks are how the sender learns a chunk was delivered — they
/// advance the send base, free the in-flight budget, and drive the retransmit
/// timer. Ping/pong gives real RTT measurement for the ATE and the UI.
#[derive(Debug, Clone)]
pub enum ControlMsg {
    /// Delivery acknowledgement for a chunk.
    Ack { session_id: [u8; 16], gsn: u64 },
    /// Echo reply to a ping (carries the original nonce + send timestamp).
    Pong { nonce: [u8; 8], sent_ts: u64 },
}

/// Lane metrics shared between the transport and the health monitor.
pub struct LaneMetrics {
    pub rtt_ms: AtomicU64,
    pub bandwidth_bps: AtomicU64,
    pub active_chunks: AtomicU64,
    pub errors_total: AtomicU64,
    alive: AtomicBool,
    /// Total bytes sent since construction (for bandwidth estimation).
    bytes_sent: AtomicU64,
}

impl Default for LaneMetrics {
    fn default() -> Self {
        Self {
            rtt_ms: AtomicU64::new(0),
            bandwidth_bps: AtomicU64::new(0),
            active_chunks: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
            alive: AtomicBool::new(true), // lanes start alive
            bytes_sent: AtomicU64::new(0),
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

    /// Reconcile the in-flight counter down to a bounded value (e.g. the
    /// session's outstanding, unacked chunk count) once acks have been applied.
    /// Never raises it — increments come from `inc_active`.
    pub fn set_active(&self, n: u64) {
        self.active_chunks.fetch_min(n, Ordering::Relaxed);
    }

    /// Record bytes sent over this lane (for bandwidth estimation).
    pub fn record_sent_bytes(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Total bytes sent since construction.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Increments the error counter and marks the lane dead if it exceeds `threshold`.
    pub fn record_error(&self, threshold: u64) {
        let errs = self.errors_total.fetch_add(1, Ordering::Relaxed) + 1;
        if errs >= threshold {
            self.alive.store(false, Ordering::Relaxed);
        }
    }

    pub fn mark_dead(&self) { self.alive.store(false, Ordering::Relaxed); }
    /// Mark the lane alive again (after a successful probe or healthy send).
    pub fn mark_alive(&self) {
        self.alive.store(true, Ordering::Relaxed);
        self.errors_total.store(0, Ordering::Relaxed);
    }
    pub fn is_healthy(&self) -> bool { self.alive.load(Ordering::Relaxed) }
}

#[async_trait]
pub trait TransportLane: Send + Sync {
    fn id(&self) -> u32;
    fn metrics(&self) -> Arc<LaneMetrics>;
    async fn send(&self, chunk: Chunk) -> Result<(), TransportError>;
    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>>;
    /// Non-blocking receive: returns a buffered chunk immediately, or `None`
    /// when nothing is pending. Lanes that cannot drain non-blockingly may
    /// leave this as the default (returns `None`).
    async fn try_recv(&mut self) -> Option<Result<Chunk, TransportError>> { None }
    /// Drain buffered control-plane messages (acks, pongs). Default: none.
    async fn try_recv_control(&mut self) -> Option<ControlMsg> { None }
    /// Whether this lane supports RTT pings (and their interval).
    fn ping_interval(&self) -> Option<std::time::Duration> { None }
    /// Send an RTT probe. Default: no-op.
    async fn ping(&self) {}
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
