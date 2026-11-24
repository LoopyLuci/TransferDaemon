use std::sync::OnceLock;

/// Data carried by the ATE lane-selection hook.
pub struct AteLaneHookData {
    pub session_id: [u8; 16],
    pub gsn: u64,
    pub selected_lane: u32,
    pub rtt_ms: f64,
    pub bandwidth_bps: u64,
    pub active_chunks: u64,
    pub total_lanes: u32,
}

static ATE_HOOK: OnceLock<Box<dyn Fn(AteLaneHookData) + Send + Sync>> = OnceLock::new();

/// Register the global ATE lane-selection hook. May only be called once;
/// subsequent calls are silently ignored (the daemon registers it at startup).
pub fn register_ate_hook(f: impl Fn(AteLaneHookData) + Send + Sync + 'static) {
    let _ = ATE_HOOK.set(Box::new(f));
}

/// Emit an ATE event to the registered hook (no-op if none registered).
pub fn emit_ate(data: AteLaneHookData) {
    if let Some(hook) = ATE_HOOK.get() {
        hook(data);
    }
}
