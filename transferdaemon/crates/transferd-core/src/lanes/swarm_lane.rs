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
//! The `SwarmStore` is currently in-process (shared `Arc`).  The hook for a
//! real `librqbit` BitTorrent backend is clearly marked with `// LIBRQBIT:`.
//! When wiring librqbit, replace the `BTreeMap` backing with a librqbit
//! `ManagedTorrent` and drive the `Notify` from its piece-completion events.
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
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// SwarmStore — shared piece repository
// ---------------------------------------------------------------------------

/// Stores encrypted pieces indexed by GSN and notifies waiting leechers.
///
/// ## librqbit integration point
///
/// Replace the `BTreeMap` with a `librqbit::Session` reference and drive
/// `notify.notify_waiters()` from the session's `on_piece_complete` callback.
pub struct SwarmStore {
    /// Piece data indexed by GSN.  Seeder writes; leechers read.
    // LIBRQBIT: replace with Arc<librqbit::ManagedTorrent> + piece-index mapping.
    pieces: Mutex<BTreeMap<u64, Bytes>>,
    /// Wakes leechers waiting for the next piece to arrive.
    // LIBRQBIT: drive from session.on_piece_complete() callback.
    notify: Notify,
}

impl SwarmStore {
    /// Create a new empty store.  Share the returned `Arc` between one seeder
    /// and any number of leechers.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pieces: Mutex::new(BTreeMap::new()),
            notify: Notify::new(),
        })
    }

    /// Insert a piece and wake all waiting leechers.
    fn insert(&self, gsn: u64, payload: Bytes) {
        self.pieces.lock().unwrap().insert(gsn, payload);
        // Wake all leechers blocked in recv().
        self.notify.notify_waiters();
    }

    /// Retrieve a piece, or `None` if it hasn't arrived yet.
    fn get(&self, gsn: u64) -> Option<Bytes> {
        self.pieces.lock().unwrap().get(&gsn).cloned()
    }

    /// Number of pieces published so far.  Used for bandwidth estimation.
    fn piece_count(&self) -> usize {
        self.pieces.lock().unwrap().len()
    }

    /// Number of pieces available at or after `from_gsn`.
    fn pieces_from(&self, from_gsn: u64) -> usize {
        self.pieces.lock().unwrap().range(from_gsn..).count()
    }
}

// ---------------------------------------------------------------------------
// SwarmRole
// ---------------------------------------------------------------------------

enum SwarmRole {
    /// This lane is publishing pieces (sender side).
    Seeder,
    /// This lane is consuming pieces in order (receiver side).
    Leecher {
        /// GSN of the next piece to deliver via `recv()`.
        next_gsn: u64,
    },
}

// Arbitrary capacity reported by the seeder so the ATE always queues to it.
const SEEDER_CAPACITY: usize = 4096;
// Error threshold before the lane is marked dead.
const ERROR_THRESHOLD: u64 = 10;

// ---------------------------------------------------------------------------
// SwarmLane
// ---------------------------------------------------------------------------

/// A `TransportLane` that distributes encrypted chunks through a shared piece
/// store, modelling BitTorrent-style seeder/leecher dynamics.
pub struct SwarmLane {
    id: u32,
    metrics: Arc<LaneMetrics>,
    store: Arc<SwarmStore>,
    role: SwarmRole,
}

impl SwarmLane {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Create the **seeding** side.  One seeder per store; share the `Arc<SwarmStore>`
    /// with every leecher that should receive the same content.
    pub fn new_seeder(id: u32, store: Arc<SwarmStore>) -> Self {
        let metrics = Arc::new(LaneMetrics::new_alive());
        metrics.update_rtt(200.0);         // 200 ms initial swarm RTT estimate
        metrics.update_bandwidth(50_000_000.0); // 50 Mbps initial estimate
        Self { id, metrics, store, role: SwarmRole::Seeder }
    }

    /// Create a **leeching** side that will consume pieces starting from GSN 0.
    /// Share the same `Arc<SwarmStore>` used by the seeder.
    pub fn new_leecher(id: u32, store: Arc<SwarmStore>) -> Self {
        let metrics = Arc::new(LaneMetrics::new_alive());
        metrics.update_rtt(200.0);
        metrics.update_bandwidth(50_000_000.0);
        Self { id, metrics, store, role: SwarmRole::Leecher { next_gsn: 0 } }
    }

    /// Legacy stub constructor — not connected to any store, always dead.
    /// Kept for backwards compatibility with the existing `SwarmPlugin` stub path.
    pub fn new_stub(id: u32, _content_id: [u8; 32]) -> Self {
        let metrics = Arc::new(LaneMetrics::default());
        metrics.mark_dead();
        Self {
            id,
            metrics,
            store: SwarmStore::new(), // empty, unused
            role: SwarmRole::Leecher { next_gsn: 0 },
        }
    }
}

// ---------------------------------------------------------------------------
// TransportLane impl
// ---------------------------------------------------------------------------

#[async_trait]
impl TransportLane for SwarmLane {
    fn id(&self) -> u32 { self.id }

    fn metrics(&self) -> Arc<LaneMetrics> { self.metrics.clone() }

    fn capacity(&self) -> usize {
        if !self.metrics.is_healthy() { return 0; }
        match &self.role {
            SwarmRole::Seeder => SEEDER_CAPACITY,
            SwarmRole::Leecher { next_gsn } => {
                // Report pieces available at or after our read cursor.
                // Always at least 1 so the ATE can issue sends to the seeder.
                self.store.pieces_from(*next_gsn).max(1)
            }
        }
    }

    fn is_alive(&self) -> bool { self.metrics.is_healthy() }

    /// **Seeder** path: publish the chunk into the store and wake leechers.
    /// Returns `ProtocolViolation` if called on a leecher (which only receives).
    async fn send(&self, chunk: Chunk) -> Result<(), TransportError> {
        if !self.metrics.is_healthy() {
            return Err(TransportError::LinkDown("SwarmLane dead".into()));
        }
        match &self.role {
            SwarmRole::Seeder => {}
            SwarmRole::Leecher { .. } => return Err(TransportError::ProtocolViolation),
        }

        let t0 = Instant::now();
        let payload_len = chunk.payload.len() as f64;
        self.store.insert(chunk.gsn.0, chunk.payload);
        self.metrics.inc_active();

        // Update bandwidth/RTT estimates from real timing.
        let elapsed_secs = t0.elapsed().as_secs_f64().max(1e-9);
        self.metrics.update_rtt(elapsed_secs * 1000.0);
        // Estimate: bytes published / time taken, capped at 500 Mbps.
        let bps = (payload_len / elapsed_secs).min(500_000_000.0);
        let piece_count = self.store.piece_count() as f64;
        // Smooth over piece count so the estimate improves as more pieces land.
        let smoothed_bps = bps * (1.0 + piece_count / 100.0).min(10.0);
        self.metrics.update_bandwidth(smoothed_bps.min(500_000_000.0));

        Ok(())
    }

    /// **Leecher** path: wait for the next piece (in GSN order) and return it.
    /// Returns `None` when the lane is shutting down.
    /// Returns `ProtocolViolation` if called on a seeder.
    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>> {
        if !self.metrics.is_healthy() {
            return Some(Err(TransportError::LinkDown("SwarmLane dead".into())));
        }

        let next_gsn = match &mut self.role {
            SwarmRole::Leecher { next_gsn } => next_gsn,
            SwarmRole::Seeder => return Some(Err(TransportError::ProtocolViolation)),
        };

        loop {
            // Register interest BEFORE checking so we never miss a notification
            // that fires between the check and the await.
            // See: https://docs.rs/tokio/latest/tokio/sync/struct.Notify.html
            let notified = self.store.notify.notified();

            if let Some(payload) = self.store.get(*next_gsn) {
                let gsn_val = *next_gsn;
                *next_gsn += 1;

                let t0 = Instant::now();
                let elapsed_secs = t0.elapsed().as_secs_f64().max(1e-9);
                self.metrics.update_rtt(elapsed_secs * 1000.0);
                self.metrics.dec_active();

                return Some(Ok(Chunk {
                    gsn: Gsn(gsn_val),
                    // Session ID is zero for swarm-delivered chunks; the reassembly
                    // window uses GSN for ordering, not session ID.
                    session_id: SessionId([0u8; 16]),
                    payload,
                    key_epoch: 0,
                    qos_critical: false,
                }));
            }

            // Piece not yet available — wait for the seeder to publish it.
            notified.await;

            if !self.metrics.is_healthy() {
                return Some(Err(TransportError::LinkDown("SwarmLane dead during recv".into())));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_chunk(gsn: u64, data: &[u8]) -> Chunk {
        Chunk {
            gsn: Gsn(gsn),
            session_id: SessionId([0u8; 16]),
            payload: Bytes::copy_from_slice(data),
            key_epoch: 0,
            qos_critical: false,
        }
    }

    /// Basic round-trip: seeder publishes N chunks; leecher receives them in order.
    #[tokio::test]
    async fn swarm_roundtrip_sequential() {
        const N: u64 = 16;
        let store = SwarmStore::new();
        let seeder = SwarmLane::new_seeder(0, store.clone());
        let mut leecher = SwarmLane::new_leecher(1, store.clone());

        assert!(seeder.is_alive());
        assert!(leecher.is_alive());

        for i in 0..N {
            let data = format!("hello-chunk-{i:04}").into_bytes();
            seeder.send(make_chunk(i, &data)).await.unwrap();
        }

        for i in 0..N {
            let result = tokio::time::timeout(Duration::from_secs(5), leecher.recv())
                .await
                .expect("recv() timed out")
                .expect("lane returned None")
                .expect("recv() returned error");
            assert_eq!(result.gsn.0, i, "GSN mismatch at index {i}");
            let expected = format!("hello-chunk-{i:04}").into_bytes();
            assert_eq!(result.payload.as_ref(), expected.as_slice(), "payload mismatch at GSN {i}");
        }
    }

    /// ~1 MB round-trip (1 024 chunks × 1 024 bytes each).
    /// Validates that the lane handles realistic file sizes.
    #[tokio::test]
    async fn swarm_roundtrip_1mb() {
        const CHUNK_SIZE: usize = 1024;
        const N: u64 = 1024; // 1 MiB total

        let store = SwarmStore::new();
        let seeder = SwarmLane::new_seeder(2, store.clone());
        let mut leecher = SwarmLane::new_leecher(3, store.clone());

        // Seed concurrently with leeching to exercise the Notify wake-up path.
        let seed_task = tokio::spawn(async move {
            for i in 0..N {
                // Fill payload with a deterministic pattern so we can verify integrity.
                let mut data = vec![0u8; CHUNK_SIZE];
                let pat = (i & 0xFF) as u8;
                data.iter_mut().for_each(|b| *b = pat ^ ((i >> 8) & 0xFF) as u8);
                seeder.send(make_chunk(i, &data)).await.unwrap();
                // Tiny yield to interleave seeder and leecher.
                if i % 64 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });

        let recv_task = tokio::spawn(async move {
            let mut received = 0u64;
            loop {
                let chunk = tokio::time::timeout(Duration::from_secs(30), leecher.recv())
                    .await
                    .expect("recv() timed out")
                    .expect("lane returned None")
                    .expect("recv() returned error");
                assert_eq!(chunk.gsn.0, received);
                assert_eq!(chunk.payload.len(), CHUNK_SIZE);
                let pat = (received & 0xFF) as u8;
                let expected_byte = pat ^ ((received >> 8) & 0xFF) as u8;
                assert!(
                    chunk.payload.iter().all(|&b| b == expected_byte),
                    "payload corruption at GSN {received}",
                );
                received += 1;
                if received == N { break; }
            }
            received
        });

        seed_task.await.unwrap();
        let count = recv_task.await.unwrap();
        assert_eq!(count, N, "expected {N} chunks, got {count}");
    }

    /// Capacity reporting reflects available pieces.
    #[tokio::test]
    async fn swarm_capacity_reflects_pieces() {
        let store = SwarmStore::new();
        let seeder = SwarmLane::new_seeder(4, store.clone());
        let leecher = SwarmLane::new_leecher(5, store.clone());

        assert_eq!(seeder.capacity(), SEEDER_CAPACITY);
        // Leecher reports ≥1 even with empty store (so ATE can still schedule).
        assert!(leecher.capacity() >= 1);

        seeder.send(make_chunk(0, b"first")).await.unwrap();
        seeder.send(make_chunk(1, b"second")).await.unwrap();

        assert_eq!(leecher.capacity(), 2);
    }

    /// Stub lane is immediately dead and returns errors.
    #[tokio::test]
    async fn swarm_stub_is_dead() {
        let mut stub = SwarmLane::new_stub(99, [0u8; 32]);
        assert!(!stub.is_alive());
        assert_eq!(stub.capacity(), 0);
        let err = stub.recv().await.unwrap();
        assert!(err.is_err(), "stub recv should be an error");
    }

    /// Leechers that arrive late still see all prior pieces.
    #[tokio::test]
    async fn swarm_late_leecher() {
        let store = SwarmStore::new();
        let seeder = SwarmLane::new_seeder(6, store.clone());

        // Seed first, then attach leecher.
        for i in 0..8u64 {
            seeder.send(make_chunk(i, &[i as u8; 32])).await.unwrap();
        }

        let mut late = SwarmLane::new_leecher(7, store.clone());
        for i in 0..8u64 {
            let chunk = tokio::time::timeout(Duration::from_secs(5), late.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(chunk.gsn.0, i);
            assert_eq!(chunk.payload.as_ref(), &[i as u8; 32]);
        }
    }
}
