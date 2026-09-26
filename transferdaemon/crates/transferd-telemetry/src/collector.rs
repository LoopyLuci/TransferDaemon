use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::time::Instant;

use tokio::sync::{broadcast, Mutex};
use zeroize::Zeroizing;

use crate::events::TelemetryEvent;
use crate::health::spawn_health_sampler;
use crate::ring::RingBuffer;
use crate::store;

pub type ActiveSessions = AtomicU32;

const RING_CAP: usize = 100_000;
const BROADCAST_CAP: usize = 256;
const FLUSH_INTERVAL_SECS: u64 = 60;

pub struct TelemetryCollector {
    ring: Arc<Mutex<RingBuffer>>,
    broadcast_tx: broadcast::Sender<TelemetryEvent>,
    pub active_sessions: Arc<ActiveSessions>,
    store_dir: PathBuf,
    device_key: Zeroizing<[u8; 32]>,
    // Dropping this sends `true` through the watch channel, signalling shutdown.
    _shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl TelemetryCollector {
    /// Create and start the collector. `store_dir` is used for the device key
    /// file and encrypted flush files.
    pub fn start(store_dir: &Path) -> Arc<Self> {
        let key_path = store_dir.join("telemetry_key.bin");
        let device_key = store::load_or_create_device_key(&key_path)
            .expect("telemetry: failed to load/create device key");

        let ring = Arc::new(Mutex::new(RingBuffer::new(RING_CAP)));
        let (broadcast_tx, _) = broadcast::channel(BROADCAST_CAP);
        let active_sessions = Arc::new(AtomicU32::new(0));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let started_at = Instant::now();

        let collector = Arc::new(Self {
            ring: Arc::clone(&ring),
            broadcast_tx: broadcast_tx.clone(),
            active_sessions: Arc::clone(&active_sessions),
            store_dir: store_dir.to_path_buf(),
            device_key,
            _shutdown_tx: shutdown_tx,
        });

        // Spawn health sampler.
        let shutdown_rx2 = shutdown_rx.clone();
        tokio::spawn({
            let ring2 = Arc::clone(&ring);
            let tx2 = broadcast_tx.clone();
            let as2 = Arc::clone(&active_sessions);
            async move {
                spawn_health_sampler(ring2, tx2, started_at, as2, shutdown_rx2).await;
            }
        });

        // Spawn periodic flush task.
        tokio::spawn({
            let collector2 = Arc::clone(&collector);
            let mut srx = shutdown_rx;
            async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_secs(FLUSH_INTERVAL_SECS),
                );
                // Skip the first (immediate) tick.
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            collector2.flush_to_disk().await;
                        }
                        _ = srx.changed() => {
                            if *srx.borrow() { break; }
                        }
                    }
                }
            }
        });

        collector
    }

    /// Push a single telemetry event into the ring and broadcast it.
    pub async fn record(&self, event: TelemetryEvent) {
        self.ring.lock().await.push(event.clone());
        let _ = self.broadcast_tx.send(event);
    }

    /// Subscribe to the live event broadcast. Each subscriber receives all
    /// events emitted after this call.
    pub fn subscribe(&self) -> broadcast::Receiver<TelemetryEvent> {
        self.broadcast_tx.subscribe()
    }

    /// Return a snapshot of all events currently in the ring buffer.
    pub async fn replay(&self) -> Vec<TelemetryEvent> {
        self.ring.lock().await.snapshot()
    }

    /// Increment / decrement the active session counter.
    pub fn session_opened(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn session_closed(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    /// Flush ring contents to disk now (called by the periodic task or on
    /// graceful shutdown).
    pub async fn flush_to_disk(&self) {
        let events = self.ring.lock().await.snapshot();
        if let Err(e) = store::flush(&self.store_dir, &self.device_key, &events) {
            tracing::error!("telemetry: flush error: {e}");
        }
    }
}
