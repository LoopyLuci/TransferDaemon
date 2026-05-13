//! TransferDaemon UI — egui/eframe desktop application.
//!
//! Entry point. Starts a tokio runtime in the background (for daemon communication
//! and database writes), then launches the eframe event loop on the main thread.
//!
//! Daemon selection:
//!   - If `TRANSFERD_ADDR` env var is set, connect via gRPC to that address.
//!   - Otherwise try `http://127.0.0.1:50051` with a 500 ms timeout.
//!   - Fall back to `MockDaemon` when the daemon is not reachable.

mod app;
mod daemon;
mod db;
mod grpc_daemon;
mod pages;
mod types;
mod widgets;

use app::TransferDaemonApp;
use daemon::MockDaemon;
use grpc_daemon::GrpcDaemon;
use std::sync::Arc;

fn main() -> eframe::Result<()> {
    // Start a background tokio runtime for async daemon calls.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _guard = rt.enter();

    // Resolve daemon: gRPC if available, otherwise mock.
    let daemon_arc: Arc<dyn daemon::DaemonApi>;
    let daemon_is_live: bool;
    {
        let addr = std::env::var("TRANSFERD_ADDR")
            .unwrap_or_else(|_| "http://127.0.0.1:50051".into());
        match rt.block_on(GrpcDaemon::try_connect(&addr)) {
            Some(g) => {
                eprintln!("[ui] connected to daemon at {addr}");
                daemon_arc = Arc::new(g);
                daemon_is_live = true;
            }
            None => {
                eprintln!("[ui] daemon not reachable — using MockDaemon (offline mode)");
                daemon_arc = Arc::new(MockDaemon::new());
                daemon_is_live = false;
            }
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("TransferDaemon")
            .with_inner_size([420.0, 740.0])
            .with_min_inner_size([360.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "TransferDaemon",
        options,
        Box::new(move |cc| Ok(Box::new(TransferDaemonApp::with_daemon(cc, daemon_arc, daemon_is_live)))),
    )
}
