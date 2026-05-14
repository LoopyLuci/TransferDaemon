//! transferd daemon library — exposes gRPC server construction for tests and mobile.

pub mod grpc;
pub mod state;

use std::sync::Arc;
use parking_lot::Mutex;

pub use state::DaemonState;

/// Fresh stateless in-memory state (no persistence).
/// Used by integration tests so they run without filesystem access.
pub fn new_state() -> Arc<Mutex<DaemonState>> {
    Arc::new(Mutex::new(DaemonState::default()))
}

/// State backed by the platform-default encrypted store.
///
/// The store file is created on first `create_identity` and loaded on
/// `restore_identity`.  Pass the result of this function to
/// `grpc::add_all_services` in the real daemon binary.
pub fn new_state_persistent() -> Arc<Mutex<DaemonState>> {
    match transferd_store::default_store_path() {
        Ok(path) => Arc::new(Mutex::new(
            DaemonState::with_store(path, transferd_store::StoreParams::production()),
        )),
        Err(e) => {
            eprintln!("transferd: could not determine store path ({e}); running without persistence");
            Arc::new(Mutex::new(DaemonState::default()))
        }
    }
}
