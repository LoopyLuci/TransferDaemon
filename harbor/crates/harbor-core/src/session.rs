//! Per-connection isolation. Each MCP client connection is a Session: it owns
//! a unique id, a scratch directory, and a running resource account so a
//! runaway session cannot starve the machine or other sessions.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rand::Rng;
use serde::Serialize;

static SESSION_SEQ: AtomicU64 = AtomicU64::new(0);

/// Accounting counters for one session.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SessionUsage {
    pub invocations: u64,
    pub total_output_bytes: u64,
}

/// Isolation + budget for one client connection.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub id: String,
    pub created_secs: u64,
    /// Max total output a session may return before invocations are denied.
    pub max_total_output_bytes: u64,
    /// Max simultaneous in-flight capability invocations.
    pub max_concurrent: usize,
    /// Per-session scratch directory (created lazily).
    pub scratch: PathBuf,
}

impl Session {
    pub fn new(base_scratch: &std::path::Path) -> Self {
        let id: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        let seq = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
        let scratch = base_scratch.join(format!("{id}-{seq}"));
        let _ = std::fs::create_dir_all(&scratch);
        Self {
            id,
            created_secs: Instant::now().elapsed().as_secs(),
            max_total_output_bytes: 64 << 20,
            max_concurrent: 8,
            scratch,
        }
    }

    pub fn age(&self) -> Duration {
        Instant::now().elapsed()
    }
}