//! TransferDaemon UI — egui/eframe desktop application.
//!
//! Daemon selection:
//!   - If `TRANSFERD_ADDR` env var is set, connect via gRPC to that address.
//!   - Otherwise try `http://127.0.0.1:50051` with a 500 ms timeout.
//!   - Fall back to `MockDaemon` when the daemon is not reachable.

mod automation;
mod tray;

use transferd_ui_shared::{
    app::TransferDaemonApp,
    daemon::MockDaemon,
    grpc_daemon::GrpcDaemon,
};
use std::sync::Arc;

fn main() -> eframe::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _guard = rt.enter();

    let daemon_arc: Arc<dyn transferd_ui_shared::daemon::DaemonApi>;
    let daemon_is_live: bool;
    {
        let addr = std::env::var("TRANSFERD_ADDR")
            .unwrap_or_else(|_| "http://127.0.0.1:50051".into());
        match rt.block_on(GrpcDaemon::try_connect(&addr)) {
            Some(g) => {
                tracing::info!("[ui] connected to daemon at {addr}");
                daemon_arc = Arc::new(g);
                daemon_is_live = true;
            }
            None => {
                tracing::warn!("[ui] daemon not reachable — using MockDaemon (offline mode)");
                daemon_arc = Arc::new(MockDaemon::new());
                daemon_is_live = false;
            }
        }
    }

    let (tray_tx, tray_rx) = tray::start_tray();

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
        Box::new(move |cc| {
            let mut app = TransferDaemonApp::with_daemon(cc, daemon_arc, daemon_is_live);
            app.set_tray_channels(tray_tx, tray_rx);
            // Answer the daemon control hub's gui.* operations (TRANSFERD_GUI_CONTROL=off to opt out).
            if std::env::var("TRANSFERD_GUI_CONTROL").map(|v| v == "off" || v == "0").unwrap_or(false) {
                Ok(Box::new(app))
            } else {
                Ok(Box::new(automation::wrap(app, &cc.egui_ctx)))
            }
        }),
    )
}
