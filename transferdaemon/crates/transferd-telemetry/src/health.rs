use std::sync::{atomic::Ordering, Arc};
use std::time::Instant;

use tokio::sync::{broadcast, Mutex};

use crate::collector::ActiveSessions;
use crate::events::{SystemHealthEvent, TelemetryEvent};
use crate::ring::RingBuffer;

// Platform-specific CPU + RSS sampling.
#[cfg(target_os = "linux")]
mod platform {
    use std::fs;

    /// Returns (user_ticks, system_ticks, idle_ticks) from /proc/stat line 0.
    fn read_cpu_ticks() -> Option<(u64, u64, u64)> {
        let stat = fs::read_to_string("/proc/stat").ok()?;
        let line = stat.lines().next()?;
        let mut parts = line.split_whitespace();
        parts.next()?; // "cpu"
        let user: u64 = parts.next()?.parse().ok()?;
        let _nice: u64 = parts.next()?.parse().ok()?;
        let system: u64 = parts.next()?.parse().ok()?;
        let idle: u64 = parts.next()?.parse().ok()?;
        Some((user, system, idle))
    }

    pub struct CpuState {
        prev_work: u64,
        prev_total: u64,
    }

    impl CpuState {
        pub fn new() -> Self {
            let (u, s, i) = read_cpu_ticks().unwrap_or((0, 0, 0));
            Self { prev_work: u + s, prev_total: u + s + i }
        }

        pub fn sample(&mut self) -> f32 {
            let (u, s, i) = read_cpu_ticks().unwrap_or((0, 0, 0));
            let work = u + s;
            let total = u + s + i;
            let dwork = work.saturating_sub(self.prev_work) as f32;
            let dtotal = total.saturating_sub(self.prev_total) as f32;
            self.prev_work = work;
            self.prev_total = total;
            if dtotal == 0.0 { 0.0 } else { (dwork / dtotal * 100.0).clamp(0.0, 100.0) }
        }
    }

    pub fn mem_rss_kb() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                return rest.split_whitespace().next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            }
        }
        0
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    pub struct CpuState;
    impl CpuState {
        pub fn new() -> Self { Self }
        pub fn sample(&mut self) -> f32 { 0.0 }
    }
    pub fn mem_rss_kb() -> u64 { 0 }
}

pub async fn spawn_health_sampler(
    ring: Arc<Mutex<RingBuffer>>,
    broadcast_tx: broadcast::Sender<TelemetryEvent>,
    started_at: Instant,
    active_sessions: Arc<ActiveSessions>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut cpu = platform::CpuState::new();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
            }
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let event = TelemetryEvent::SystemHealth(SystemHealthEvent {
                ts,
                cpu_pct: cpu.sample(),
                mem_rss_kb: platform::mem_rss_kb(),
                uptime_secs: started_at.elapsed().as_secs(),
                active_sessions: active_sessions.load(Ordering::Relaxed),
            });
            ring.lock().await.push(event.clone());
            let _ = broadcast_tx.send(event);
        }
    });
}
