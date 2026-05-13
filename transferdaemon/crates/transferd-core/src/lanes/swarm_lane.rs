//! SwarmLane — BitTorrent / IPFS decentralized transport (stub).
//!
//! ## Design (not yet implemented)
//!
//! On the **sender** side:
//! 1. Accumulate chunks into a virtual file (piece size = chunk payload size).
//! 2. Compute the info-hash over all pieces.
//! 3. Start seeding via `librqbit` (BitTorrent) or publish to IPFS.
//! 4. Broadcast the magnet URI / CID to the receiver out-of-band (e.g. via RelayLane).
//!
//! On the **receiver** side:
//! 1. Receive the magnet URI / CID.
//! 2. Download pieces from the swarm into the ReassemblyWindow.
//! 3. Each piece maps to a GSN via `gsn = piece_index`.
//!
//! ## Dependencies (to add when implementing)
//!
//! ```toml
//! librqbit = "7"           # BitTorrent
//! rust-ipfs = "0.11"       # IPFS (optional feature)
//! ```
//!
//! ## Why this matters
//!
//! The SwarmLane turns TransferDaemon into a seeder: once a file is published,
//! any number of receivers can download it simultaneously without burdening the sender.
//! The ATE will prefer this lane for large files over slow WAN links.

use crate::transport::{Chunk, LaneMetrics, TransportError, TransportLane};
use async_trait::async_trait;
use std::sync::Arc;

/// Placeholder for the BitTorrent / IPFS lane.
///
/// `send()` and `recv()` always return errors until the swarm client is wired in.
pub struct SwarmLane {
    id: u32,
    metrics: Arc<LaneMetrics>,
    /// Content identifier (info-hash or IPFS CID) for the active transfer.
    #[allow(dead_code)]
    content_id: [u8; 32],
}

impl SwarmLane {
    /// Creates a stub that is not yet connected to any swarm.
    pub fn new_stub(id: u32, content_id: [u8; 32]) -> Self {
        Self { id, metrics: Arc::new(LaneMetrics::default()), content_id }
    }
}

#[async_trait]
impl TransportLane for SwarmLane {
    fn id(&self) -> u32 { self.id }
    fn metrics(&self) -> Arc<LaneMetrics> { self.metrics.clone() }
    fn capacity(&self) -> usize { 0 } // stub — never selected by ATE
    fn is_alive(&self) -> bool { false }

    async fn send(&self, _chunk: Chunk) -> Result<(), TransportError> {
        Err(TransportError::LinkDown("SwarmLane not yet implemented".into()))
    }

    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>> {
        Some(Err(TransportError::LinkDown("SwarmLane not yet implemented".into())))
    }
}
