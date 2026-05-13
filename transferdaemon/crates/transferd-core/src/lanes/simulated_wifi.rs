use crate::transport::{Chunk, LaneMetrics, TransportError, TransportLane};
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

pub struct SimulatedWiFiLane {
    id: u32,
    metrics: Arc<LaneMetrics>,
    capacity: Arc<AtomicUsize>,
    rtt: Duration,
    bandwidth: f64,
}

impl SimulatedWiFiLane {
    pub fn new(id: u32, rtt: Duration, bandwidth_bps: f64) -> Self {
        let metrics = Arc::new(LaneMetrics::default());
        metrics.rtt_ms.store((rtt.as_millis() as u64) * 1_000, Ordering::SeqCst);
        metrics.bandwidth_bps.store(bandwidth_bps as u64, Ordering::SeqCst);
        Self {
            id,
            metrics,
            capacity: Arc::new(AtomicUsize::new(16)),
            rtt,
            bandwidth: bandwidth_bps,
        }
    }
}

#[async_trait]
impl TransportLane for SimulatedWiFiLane {
    fn id(&self) -> u32 { self.id }
    fn metrics(&self) -> Arc<LaneMetrics> { self.metrics.clone() }
    fn capacity(&self) -> usize { self.capacity.load(Ordering::Relaxed) }

    async fn send(&self, chunk: Chunk) -> Result<(), TransportError> {
        if self.capacity.load(Ordering::Relaxed) == 0 {
            return Err(TransportError::Saturated);
        }
        self.capacity.fetch_sub(1, Ordering::Relaxed);
        sleep(self.rtt / 2).await;
        let tx = Duration::from_secs_f64(chunk.payload.len() as f64 / self.bandwidth.max(1.0));
        sleep(tx).await;
        self.capacity.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>> { None }
    fn is_alive(&self) -> bool { true }
}
