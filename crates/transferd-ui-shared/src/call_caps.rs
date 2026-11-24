//! The daemon's call-bandwidth cap (`limits.call_kbps`), cached from the live
//! daemon by the app's refresh loop so the UI's CallManager can enforce it on
//! video/voice calls. `0` = unbounded.

use std::sync::atomic::{AtomicU64, Ordering};

/// Last-known `limits.call_kbps` from the daemon (0 = unbounded).
pub static CALL_KBPS: AtomicU64 = AtomicU64::new(0);

/// Cache the daemon's call-kbps cap into the shared static.
pub fn update_call_kbps(value: Option<String>) {
    let kbps = value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0);
    CALL_KBPS.store(kbps, Ordering::Relaxed);
}

/// The cap as an `Option<u64>` (`None` when unbounded/unknown).
pub fn call_kbps() -> Option<u64> {
    let k = CALL_KBPS.load(Ordering::Relaxed);
    if k == 0 { None } else { Some(k) }
}