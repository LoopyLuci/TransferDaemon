//! Platform-specific UI entry point.
//!
//! Runs the full `TransferDaemonApp` on Android via eframe.
//! Wires the file-picker callback so `ChatPage` can trigger the native picker.

#[cfg(target_os = "android")]
pub mod android_logger;
#[cfg(target_os = "android")]
pub mod android_media;

#[cfg(target_os = "android")]
pub fn android_main_impl(app: android_activity::AndroidApp) {
    use transferd_ui_shared::{
        app::TransferDaemonApp,
        daemon::MockDaemon,
        grpc_daemon::GrpcDaemon,
    };
    use std::sync::Arc;
    use winit::platform::android::EventLoopBuilderExtAndroid;

    // ── Logging ───────────────────────────────────────────────────────────────
    let log_base = app
        .external_data_path()
        .or_else(|| app.internal_data_path())
        .unwrap_or_else(|| std::path::PathBuf::from("/data/local/tmp"));
    android_logger::init(&log_base);
    android_logger::log("=== android_main start ===");

    // ── Media capture init ────────────────────────────────────────────────────
    android_media::init(app.clone());

    // ── Start daemon ──────────────────────────────────────────────────────────
    android_logger::log("Spawning daemon thread…");
    crate::daemon_thread::spawn(String::new());

    android_logger::log("Waiting for daemon runtime handle…");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while crate::daemon_thread::RUNTIME_HANDLE.get().is_none() {
        if std::time::Instant::now() > deadline {
            android_logger::log("WARNING: daemon runtime handle timeout");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    android_logger::log("Daemon ready.");

    // ── UI tokio runtime ──────────────────────────────────────────────────────
    let ui_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("UI tokio runtime");
    let _guard = ui_rt.enter();

    // ── Connect to daemon ─────────────────────────────────────────────────────
    let daemon_arc: Arc<dyn transferd_ui_shared::daemon::DaemonApi>;
    let daemon_is_live: bool;
    match ui_rt.block_on(GrpcDaemon::try_connect("http://127.0.0.1:50051")) {
        Some(g) => {
            android_logger::log("Connected to daemon via gRPC");
            daemon_arc = Arc::new(g);
            daemon_is_live = true;
        }
        None => {
            android_logger::log("Daemon not reachable — using MockDaemon");
            daemon_arc = Arc::new(MockDaemon::new());
            daemon_is_live = false;
        }
    }

    // ── File picker callback ──────────────────────────────────────────────────
    let app_for_picker = app.clone();
    let on_attach: Box<dyn Fn() + Send + Sync> = Box::new(move || {
        crate::file_picker::android::launch(&app_for_picker);
    });

    // ── Media capture factory (uses real Camera2 + AudioRecord) ───────────────
    let media_factory: Box<dyn Fn(bool) -> std::sync::Arc<dyn transferd_webrtc::media::MediaCapture> + Send + Sync> =
        Box::new(|video| {
            std::sync::Arc::new(android_media::AndroidMediaCapture::new(video))
        });

    // ── eframe ────────────────────────────────────────────────────────────────
    android_logger::log("Building NativeOptions…");
    let options = eframe::NativeOptions {
        event_loop_builder: Some(Box::new(move |builder| {
            builder.with_android_app(app);
        })),
        ..Default::default()
    };

    android_logger::log("Calling eframe::run_native…");
    match eframe::run_native(
        "TransferDaemon",
        options,
        Box::new(move |cc| {
            android_logger::log("Constructing TransferDaemonApp");
            let mut td_app = TransferDaemonApp::with_daemon(cc, daemon_arc, daemon_is_live);
            // Wire native file picker: trigger on 📎 tap, drain result each frame.
            td_app.chat_page_mut().on_attach = Some(on_attach);
            td_app.poll_file_pick = Some(Box::new(|| crate::file_picker::take()));
            // Wire real camera/mic capture for calls.
            td_app.chat_page_mut().media_factory = Some(media_factory);
            Ok(Box::new(td_app))
        }),
    ) {
        Ok(()) => android_logger::log("eframe::run_native returned"),
        Err(e) => android_logger::log(&format!("eframe::run_native error: {e:?}")),
    }

    android_logger::log("=== android_main exit ===");
}

/// Desktop compatibility stub.
pub fn run_ui(_daemon_addr: &str, _native_window_ptr: usize, _width: u32, _height: u32) {
    #[cfg(target_os = "android")]
    android_logger::log("run_ui() — NativeActivity owns the loop, ignoring");
}
