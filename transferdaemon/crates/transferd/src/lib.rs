//! transferd daemon library — exposes gRPC server construction for tests and mobile.

pub mod grpc;
pub mod state;
pub mod update;
pub mod backup;
pub mod peer_manager;
pub mod handshake_manager;
pub mod message_crypto;
pub mod mesh;
pub mod wire;
pub mod transport;
pub mod relay_hub;
pub mod peer_discovery;
pub mod connections;
pub mod limits;
pub mod safety;
pub mod phrase_cache;
pub mod outbox;

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
        Ok(path) => {
            // Keep the recovery phrase in the OS-protected cache (phrase_cache) so a restarted daemon unlocks its
            // store by itself: identity, contacts and relay registrations come back without anyone typing the phrase.
            let state = if phrase_cache::enabled() {
                let cache = path.with_file_name("user_data.phrase");
                DaemonState::with_store_and_phrase(path, transferd_store::StoreParams::production(), cache.clone())
            } else {
                DaemonState::with_store(path, transferd_store::StoreParams::production())
            };
            let state = Arc::new(Mutex::new(state));
            unlock_from_cache(&state);
            state
        }
        Err(e) => {
            tracing::warn!("transferd: could not determine store path ({e}); running without persistence");
            Arc::new(Mutex::new(DaemonState::default()))
        }
    }
}

/// Unlock the store with the cached phrase, if there is one. Returns whether an identity was restored.
pub fn unlock_from_cache(state: &Arc<Mutex<DaemonState>>) -> bool {
    let mut s = state.lock();
    let Some(cache) = s.phrase_path.clone() else { return false };
    let Some(phrase) = phrase_cache::read(&cache) else { return false };
    if s.try_load(&phrase) {
        tracing::info!("transferd: identity restored from the protected phrase cache");
        true
    } else {
        tracing::warn!("transferd: the phrase cache does not open this store (stale); the identity must be restored");
        false
    }
}
