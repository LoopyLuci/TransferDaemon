//! transferd daemon library — exposes gRPC server construction for tests and mobile.

pub mod grpc;
pub mod state;

use std::sync::Arc;
use parking_lot::Mutex;

pub use state::DaemonState;

/// Convenience: build a fresh shared state.
pub fn new_state() -> Arc<Mutex<DaemonState>> {
    Arc::new(Mutex::new(DaemonState::default()))
}
