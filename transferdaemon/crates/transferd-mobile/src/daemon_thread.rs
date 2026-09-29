//! Background thread that runs the TransferDaemon gRPC server.

use std::sync::{Arc, OnceLock};
use tokio::runtime::Handle;

/// Handle to the daemon's tokio runtime.
/// Set once when the daemon spawns; used by `grpc_bridge::block_on_daemon`.
pub static RUNTIME_HANDLE: OnceLock<Handle> = OnceLock::new();

/// Settings the mobile app can configure via the `daemon.config` file.
const CONFIG_KEYS: &[&str] = &[
    "TRANSFERD_PORT",
    "TRANSFERD_RELAY_ADDR",
    "TRANSFERD_DHT_BIND",
    "TRANSFERD_DHT_BOOTSTRAP",
    "TRANSFERD_DIFFICULTY",
    "TRANSFERD_BIND_ADDR",
];

/// Read `<config_dir>/TransferDaemon/daemon.config` (`KEY=VALUE` lines) and
/// apply it as env defaults. The explicit process env wins; a missing file is
/// a no-op.
///
/// On Android 13+/MIUI, SELinux marks adb-pushed files under the app's EXTERNAL
/// files dir as `media_rw_data_file`, which the app cannot read — so the config
/// is also looked up at `/data/local/tmp/daemon.config` (an adb-friendly,
/// app-readable location). The first readable file wins.
fn apply_config(config_dir: &Option<std::path::PathBuf>) {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(dir) = config_dir {
        candidates.push(dir.join("TransferDaemon").join("daemon.config"));
    }
    candidates.push(std::path::PathBuf::from("/data/local/tmp/daemon.config"));
    for path in &candidates {
        let Ok(content) = std::fs::read_to_string(path) else { continue };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let (k, v) = (k.trim(), v.trim());
                if CONFIG_KEYS.contains(&k) && !std::env::var(k).is_ok() {
                    std::env::set_var(k, v);
                    eprintln!("[daemon] config: {k}={v}");
                }
            }
        }
        return;
    }
}

pub fn spawn(socket_path: String) {
    spawn_with_config(socket_path, None);
}

/// Spawn the daemon, optionally reading relay/DHT settings from
/// `<config_dir>/TransferDaemon/daemon.config` (the Android app has no way to
/// set process env vars, so settings are shipped as a key-value file).
pub fn spawn_with_config(socket_path: String, config_dir: Option<std::path::PathBuf>) {
    apply_config(&config_dir);
    // Surface the daemon's tracing (relay/DHT/session) on-device: Android
    // routes stderr to logcat under `RustStdoutStderr`.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,transferd_lib=debug")),
        )
        .with_writer(std::io::stderr)
        .try_init();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("daemon tokio runtime");

        // Store the handle before blocking so other threads can queue tasks.
        let handle = rt.handle().clone();
        RUNTIME_HANDLE.set(handle).ok();

        rt.block_on(async move {
            let port: u16 = std::env::var("TRANSFERD_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50051);
            let addr = format!("127.0.0.1:{port}").parse().expect("parse addr");
            eprintln!("[daemon] starting on {addr} (socket hint: {socket_path})");

            // Persist the identity to the app's own directory so it survives
            // process restarts (Android has no env; the store file lives next
            // to the config). Falls back to volatile state if the dir is gone.
            let state = match &config_dir {
                Some(dir) => {
                    let store = dir.join("TransferDaemon").join("user_data.enc");
                    let phrase_path = dir.join("TransferDaemon").join("user_data.phrase");
                    eprintln!("[daemon] persistent store: {}", store.display());
                    let st = Arc::new(parking_lot::Mutex::new(
                        transferd_lib::state::DaemonState::with_store_and_phrase(
                            store,
                            transferd_store::StoreParams::production(),
                            phrase_path.clone(),
                        ),
                    ));
                    // Auto-restore the identity from the cached phrase so a
                    // restarted app keeps its identity (and therefore its relay
                    // token + registrations). The phrase file is written by
                    // create/restore_identity via set_phrase.
                    if phrase_path.exists() {
                        if transferd_lib::unlock_from_cache(&st) {
                            eprintln!("[daemon] identity restored from cached phrase");
                        } else {
                            eprintln!("[daemon] identity restore failed (stale or unreadable phrase cache)");
                        }
                    }
                    st
                }
                None => transferd_lib::new_state(),
            };
            // Raise a platform notification for each new inbound 1:1 message.
            transferd_lib::state::set_inbound_notify(|sender, text, contact_id| {
                crate::notifications::notify_incoming(sender, text, contact_id);
            });
            // Accept direct TCP peer connections on the port after gRPC, exactly
            // like the desktop daemon binary (address + 1). TRANSFERD_BIND_ADDR
            // (default 127.0.0.1) controls the bind: 0.0.0.0 accepts direct
            // LAN/Tailscale peer connections so peers can reach us without a
            // relay (the Tailscale mesh + its DERP fallback carry the traffic).
            let bind_host = std::env::var("TRANSFERD_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".into());
            let transport_addr = std::net::SocketAddr::from((
                bind_host.parse::<std::net::IpAddr>().unwrap_or([127, 0, 0, 1].into()),
                port.saturating_add(1),
            ));
            match transferd_lib::transport::spawn_inbound_listener(
                state.clone(),
                transport_addr,
            )
            .await
            {
                Ok(listening) => {
                    eprintln!("[daemon] transport listener on {transport_addr}");
                    state.lock().peer_listen = Some(listening);
                }
                Err(e) => eprintln!("[daemon] transport listener failed: {e}"),
            }
            // Background transport tick: flush queued messages over active lanes
            // and apply inbound events (acks, read receipts, unsolicited).
            transferd_lib::transport::spawn_transport_tick(state.clone());
            // Register the inbound relay token(s) (UDP/WS) so contacts can reach
            // us via the relay. Mirrors the desktop binary's startup; defers
            // when no identity exists yet (a later identity creation re-triggers
            // it via the gRPC create_identity path).
            tokio::spawn(transferd_lib::relay_hub::spawn_inbound_relay_listener(state.clone()));
            if let Err(e) = transferd_lib::grpc::add_all_services(
                tonic::transport::Server::builder(), state)
                .serve(addr)
                .await
            {
                // AddrInUse means a daemon from a previous NativeActivity lifecycle is still
                // running on this process — safe to ignore; the UI will connect to it.
                eprintln!("[daemon] serve ended: {e}");
            }
        });
    });
}
