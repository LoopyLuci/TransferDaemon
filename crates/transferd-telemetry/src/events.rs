use serde::{Deserialize, Serialize};

/// A single system-health sample, emitted every 5 seconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthEvent {
    /// Unix timestamp (seconds).
    pub ts: u64,
    /// Process CPU utilisation as a percentage (0–100).
    pub cpu_pct: f32,
    /// Resident set size in KiB.
    pub mem_rss_kb: u64,
    /// Seconds since the daemon started.
    pub uptime_secs: u64,
    /// Number of active transfer sessions at sample time.
    pub active_sessions: u32,
}

/// Emitted every time the ATE picks a lane for a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AteLaneEvent {
    /// Unix timestamp (seconds).
    pub ts: u64,
    /// First 8 bytes of the 16-byte SessionId — anonymised.
    pub session_id_hash: [u8; 8],
    /// Global sequence number of the chunk being dispatched.
    pub gsn: u64,
    /// Zero-based index of the selected lane.
    pub selected_lane: u32,
    /// RTT estimate for the selected lane at decision time (milliseconds).
    pub rtt_ms: f64,
    /// Bandwidth estimate for the selected lane (bits per second).
    pub bandwidth_bps: u64,
    /// Active in-flight chunks on the selected lane at decision time.
    pub active_chunks: u64,
    /// Total number of lanes available to this session.
    pub total_lanes: u32,
}

/// Top-level event union stored in the ring buffer and streamed over gRPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelemetryEvent {
    SystemHealth(SystemHealthEvent),
    AteLane(AteLaneEvent),
}

impl TelemetryEvent {
    pub fn ts(&self) -> u64 {
        match self {
            Self::SystemHealth(e) => e.ts,
            Self::AteLane(e) => e.ts,
        }
    }
}
