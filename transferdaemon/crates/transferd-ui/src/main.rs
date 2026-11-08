//! TransferDaemon UI — egui/eframe desktop application.
//!
//! Daemon selection:
//!   - `TRANSFERD_ADDR` (default `http://127.0.0.1:50051`) is the daemon's gRPC address.
//!   - If the daemon is not running yet, the window still uses it: calls connect as soon as it is up, so a daemon
//!     started after the window works without a relaunch.
//!   - `TRANSFERD_MOCK=1` runs the window on the offline `MockDaemon` (demo data) instead.

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
        let mock = std::env::var("TRANSFERD_MOCK").map(|v| v == "1" || v == "true").unwrap_or(false);
        if mock {
            tracing::warn!("[ui] TRANSFERD_MOCK set — using MockDaemon (demo data)");
            daemon_arc = Arc::new(MockDaemon::new());
            daemon_is_live = false;
        } else {
            match rt.block_on(GrpcDaemon::try_connect(&addr)) {
                Some(g) => {
                    tracing::info!("[ui] connected to daemon at {addr}");
                    daemon_arc = Arc::new(g);
                    daemon_is_live = true;
                }
                None => {
                    // Not up yet: keep the handle, which connects as soon as the daemon is listening.
                    tracing::warn!("[ui] daemon not reachable at {addr}; will connect when it is up");
                    daemon_arc = Arc::new(GrpcDaemon::lazy(&addr).expect("daemon address"));
                    daemon_is_live = true;
                }
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
