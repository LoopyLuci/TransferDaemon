use std::sync::Mutex;
use std::time::Instant;

/// Token-bucket rate limiter for relay bandwidth.
///
/// Capacity = 1 second of tokens. Tokens refill continuously based on elapsed time.
/// If `capacity_bps == 0` the bucket is disabled (all sends pass immediately).
pub struct TokenBucket {
    inner: Mutex<BucketState>,
}

struct BucketState {
    /// Tokens available (bytes).
    tokens: f64,
    /// Maximum token capacity (bytes = 1 second of bandwidth).
    capacity: f64,
    /// Refill rate in bytes per second.
    rate_bps: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// `bandwidth_kbps == 0` → unlimited.
    pub fn new(bandwidth_kbps: u64) -> Self {
        let rate_bps = if bandwidth_kbps == 0 {
            f64::MAX / 2.0
        } else {
            bandwidth_kbps as f64 * 1000.0 / 8.0
        };
        let capacity = rate_bps.min(1e12); // cap bucket at 1 s of bandwidth
        Self {
            inner: Mutex::new(BucketState {
                tokens: capacity,
                capacity,
                rate_bps,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Update rate at runtime (e.g. when settings change).
    pub fn set_bandwidth_kbps(&self, bandwidth_kbps: u64) {
        let rate_bps = if bandwidth_kbps == 0 {
            f64::MAX / 2.0
        } else {
            bandwidth_kbps as f64 * 1000.0 / 8.0
        };
        let mut g = self.inner.lock().unwrap();
        g.rate_bps = rate_bps;
        g.capacity = rate_bps.min(1e12);
        g.tokens = g.tokens.min(g.capacity);
    }

    /// Try to consume `bytes` tokens. Returns `true` if permitted, `false` if throttled.
    pub fn try_consume(&self, bytes: usize) -> bool {
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(g.last_refill).as_secs_f64();
        g.last_refill = now;
        g.tokens = (g.tokens + elapsed * g.rate_bps).min(g.capacity);
        if g.tokens >= bytes as f64 {
            g.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}
