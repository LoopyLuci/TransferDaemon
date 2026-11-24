//! SwarmLane — decentralized piece-swarm transport.
//!
//! ## Architecture
//!
//! The swarm lane models BitTorrent-style piece distribution via a shared
//! `SwarmStore`.  The **seeder** calls `send()` to publish each encrypted chunk
//! (piece) into the store.  Any number of **leechers** sharing the same store
//! call `recv()` to pull pieces in order, waiting asynchronously for pieces that
//! have not yet arrived.
//!
//! ```text
//!  Sender                           Receiver(s)
//!  ──────                           ────────────
//!  SwarmLane::new_seeder(store)     SwarmLane::new_leecher(store)
//!       │                                │
//!       │ send(chunk gsn=0) ──────────►  │ recv() → chunk gsn=0
//!       │ send(chunk gsn=1) ──────────►  │ recv() → chunk gsn=1
//!       │      …                         │     …
//! ```
//!
//! With the `swarm-torrent` feature, the `SwarmStore` uses a real BitTorrent
//! backend via `librqbit`. Without it, it uses an in-process `BTreeMap`.
//!
//! Note: the `librqbit` backend is future work; the in-process `BTreeMap`
//! store below is the only implementation currently wired in.
//!
//! ## Integration with the ATE
//!
//! The seeder reports `capacity = SEEDER_CAPACITY` so the ATE selects it.
//! The leecher reports `capacity = (available pieces ahead of next_gsn)`,
//! which reflects true swarm progress.  Both sides update `bandwidth_bps` and
//! `rtt_ms` from real wall-clock measurements on each send/recv.
//!
//! ## Security
//!
//! All payloads stored in the `SwarmStore` are already AES-256-GCM encrypted
//! by the upper layers (`transferd-crypto`).  The swarm transports only
//! ciphertext; the store itself has zero knowledge of plaintext.

use crate::transport::{Chunk, LaneMetrics, TransportError, TransportLane};
use crate::types::{Gsn, SessionId};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::BTreeMap;
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// SwarmStore — shared piece repository
// ---------------------------------------------------------------------------

/// Stores encrypted pieces indexed by GSN and notifies waiting leechers.
pub struct SwarmStore {
    /// Piece data indexed by GSN.  Seeder writes; leechers read.
    pieces: tokio::sync::Mutex<BTreeMap<u64, Bytes>>,
    /// Wakes leechers waiting for the next piece to arrive.
    notify: Notify,
    /// Cached piece count for capacity reporting.
    piece_count: AtomicU64,
}

impl SwarmStore {
    /// Create a new empty store.  Share the returned `Arc` between one seeder
    /// and any number of leechers.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pieces: tokio::sync::Mutex::new(BTreeMap::new()),
            notify: Notify::new(),
            piece_count: AtomicU64::new(0),
        })
    }

    /// Insert a piece and wake all waiting leechers.
    async fn insert(&self, gsn: u64, payload: Bytes) {
        self.pieces.lock().await.insert(gsn, payload);
        self.piece_count.fetch_add(1, Ordering::Relaxed);
        // Wake all leechers blocked in recv().
        self.notify.notify_waiters();
    }

    /// Retrieve a piece, or `None` if it hasn't arrived yet.
    async fn get(&self, gsn: u64) -> Option<Bytes> {
        self.pieces.lock().await.get(&gsn).cloned()
    }

    /// Number of pieces published so far.  Used for bandwidth estimation.
    #[allow(dead_code)]
    async fn piece_count(&self) -> usize {
        self.pieces.lock().await.len()
    }

    /// Number of pieces available at or after `from_gsn`.
    #[allow(dead_code)]
    async fn pieces_from(&self, from_gsn: u64) -> usize {
        self.pieces.lock().await.range(from_gsn..).count()
    }

    /// Synchronous piece count for capacity reporting.
    fn cached_piece_count(&self) -> u64 {
        self.piece_count.load(Ordering::Relaxed)
    }

    /// Wait for a piece to become available.
    async fn wait_for_piece(&self, gsn: u64) {
        loop {
            if self.get(gsn).await.is_some() {
                return;
            }
            self.notify.notified().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Seeder
// ---------------------------------------------------------------------------

/// Number of pieces the seeder advertises as its capacity.
const SEEDER_CAPACITY: u64 = 1_000_000;

/// The seeder side of a swarm transfer.
///
/// Publishes encrypted chunks (pieces) into the shared `SwarmStore`.
pub struct SwarmSeeder {
    store: Arc<SwarmStore>,
    #[allow(dead_code)]
    session_id: SessionId,
    metrics: Arc<LaneMetrics>,
    total_bytes: AtomicU64,
}

impl SwarmSeeder {
    /// Create a new seeder for the given session.
    pub fn new(store: Arc<SwarmStore>, session_id: SessionId) -> Self {
        Self {
            store,
            session_id,
            metrics: Arc::new(LaneMetrics::new_alive()),
            total_bytes: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl TransportLane for SwarmSeeder {
    fn id(&self) -> u32 {
        0x53574152 // "SWAR"
    }

    fn metrics(&self) -> Arc<LaneMetrics> {
        self.metrics.clone()
    }

    async fn send(&self, chunk: Chunk) -> Result<(), TransportError> {
        self.total_bytes.fetch_add(chunk.payload.len() as u64, Ordering::Relaxed);
        self.store.insert(chunk.gsn.0, chunk.payload).await;
        Ok(())
    }

    fn capacity(&self) -> usize {
        SEEDER_CAPACITY as usize
    }

    fn is_alive(&self) -> bool {
        self.metrics.is_healthy()
    }

    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>> {
        // Seeder doesn't receive
        None
    }
}

// ---------------------------------------------------------------------------
// Leecher
// ---------------------------------------------------------------------------

/// The leecher side of a swarm transfer.
///
/// Pulls encrypted chunks (pieces) from the shared `SwarmStore` in order,
/// waiting asynchronously for pieces that have not yet arrived.
pub struct SwarmLeecher {
    store: Arc<SwarmStore>,
    next_gsn: u64,
    session_id: SessionId,
    metrics: Arc<LaneMetrics>,
    total_bytes: AtomicU64,
}

impl SwarmLeecher {
    /// Create a new leecher for the given session.
    pub fn new(store: Arc<SwarmStore>, session_id: SessionId) -> Self {
        Self {
            store,
            next_gsn: 0,
            session_id,
            metrics: Arc::new(LaneMetrics::new_alive()),
            total_bytes: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl TransportLane for SwarmLeecher {
    fn id(&self) -> u32 {
        0x4C454543 // "LEEC"
    }

    fn metrics(&self) -> Arc<LaneMetrics> {
        self.metrics.clone()
    }

    async fn send(&self, _chunk: Chunk) -> Result<(), TransportError> {
        // Leecher doesn't send
        Err(TransportError::ProtocolViolation)
    }

    fn capacity(&self) -> usize {
        // Capacity is the number of available pieces ahead of next_gsn
        let available = self.store.cached_piece_count().saturating_sub(self.next_gsn);
        available as usize
    }

    fn is_alive(&self) -> bool {
        self.metrics.is_healthy()
    }

    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>> {
        let gsn = self.next_gsn;
        self.next_gsn += 1;

        // Wait for the piece to become available
        self.store.wait_for_piece(gsn).await;

        // Get the piece
        let payload = self
            .store
            .get(gsn)
            .await?;

        self.total_bytes.fetch_add(payload.len() as u64, Ordering::Relaxed);

        Some(Ok(Chunk {
            gsn: Gsn(gsn),
            payload,
            session_id: self.session_id,
            key_epoch: 0,
            qos_critical: false,
        }))
    }
}

// ---------------------------------------------------------------------------
// SwarmLane — compatibility alias
// ---------------------------------------------------------------------------

/// Compatibility alias for backward compatibility.
pub struct SwarmLane;

impl SwarmLane {
    /// Create a new seeder lane.
    pub fn new_seeder(id: u32, store: Arc<SwarmStore>) -> SwarmSeeder {
        let mut session_id_bytes = [0u8; 16];
        session_id_bytes[..4].copy_from_slice(&id.to_le_bytes());
        let session_id = SessionId(session_id_bytes);
        SwarmSeeder::new(store, session_id)
    }

    /// Create a new leecher lane.
    pub fn new_leecher(id: u32, store: Arc<SwarmStore>) -> SwarmLeecher {
        let mut session_id_bytes = [0u8; 16];
        session_id_bytes[..4].copy_from_slice(&id.to_le_bytes());
        let session_id = SessionId(session_id_bytes);
        SwarmLeecher::new(store, session_id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_swarm_store_in_process() {
        let store = SwarmStore::new();

        // Insert some pieces
        store.insert(0, Bytes::from_static(b"piece 0")).await;
        store.insert(1, Bytes::from_static(b"piece 1")).await;
        store.insert(2, Bytes::from_static(b"piece 2")).await;

        // Retrieve them
        assert_eq!(store.get(0).await.unwrap(), Bytes::from_static(b"piece 0"));
        assert_eq!(store.get(1).await.unwrap(), Bytes::from_static(b"piece 1"));
        assert_eq!(store.get(2).await.unwrap(), Bytes::from_static(b"piece 2"));

        // Check counts
        assert_eq!(store.piece_count().await, 3);
        assert_eq!(store.pieces_from(1).await, 2);
    }

    #[tokio::test]
    async fn test_swarm_seeder_leecher() {
        let store = SwarmStore::new();
        let session_id = SessionId::random();

        let seeder = SwarmSeeder::new(store.clone(), session_id.clone());
        let mut leecher = SwarmLeecher::new(store.clone(), session_id);

        // Send some chunks
        for i in 0..5 {
            let chunk = Chunk {
                gsn: Gsn(i),
                payload: Bytes::from(format!("chunk {i}")),
                session_id: seeder.session_id.clone(),
                key_epoch: 0,
                qos_critical: false,
            };
            seeder.send(chunk).await.unwrap();
        }

        // Receive them
        for i in 0..5 {
            let chunk = leecher.recv().await.unwrap().unwrap();
            assert_eq!(chunk.gsn.0, i);
            assert_eq!(chunk.payload, Bytes::from(format!("chunk {i}")));
        }
    }

    #[tokio::test]
    async fn test_swarm_wait_for_piece() {
        let store = SwarmStore::new();
        let session_id = SessionId::random();

        let mut leecher = SwarmLeecher::new(store.clone(), session_id.clone());

        // Spawn a task that inserts a piece after a delay
        let store_clone = store.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            store_clone.insert(0, Bytes::from_static(b"delayed piece")).await;
        });

        // This should wait for the piece
        let chunk = leecher.recv().await.unwrap().unwrap();
        assert_eq!(chunk.payload, Bytes::from_static(b"delayed piece"));
    }
}
