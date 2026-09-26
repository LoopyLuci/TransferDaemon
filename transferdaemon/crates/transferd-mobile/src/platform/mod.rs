//! Platform-specific UI entry point.
//!
//! Runs the full `TransferDaemonApp` on Android and iOS via eframe.
//! Wires the file-picker callback so `ChatPage` can trigger the native picker.

#[cfg(target_os = "android")]
pub mod android_logger;
#[cfg(target_os = "android")]
pub mod android_media;

#[cfg(target_os = "ios")]
pub mod ios_media;

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

    // ── Keyboard ──────────────────────────────────────────────────────────────
    // KeyboardHelper.attach() (called from CustomNativeActivity.onCreate) sets up
    // a hidden EditText and a Java polling thread that calls shouldShowKeyboard() /
    // shouldHideKeyboard() every 32 ms.  Those are JNI functions in keyboard_input.rs
    // that read the SHOW_KEYBOARD / HIDE_KEYBOARD atomics set by the UI.
    //
    // We do NOT do FindClass here: native pthreads only have the bootstrap class
    // loader, so FindClass for app classes always throws ClassNotFoundException
    // and leaves a pending JVM exception that aborts the process on the next JNI call.

    // ── Start daemon ──────────────────────────────────────────────────────────
    android_logger::log("Spawning daemon thread…");
    crate::daemon_thread::spawn_with_config(String::new(), Some(log_base.clone()));

    android_logger::log("Waiting for daemon runtime handle…");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while crate::daemon_thread::RUNTIME_HANDLE.get().is_none() {
        if std::time::Instant::now() > deadline {
            android_logger::log("WARNING: daemon runtime handle timeout");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
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

    // ── Display density ─────────────────────────────────────────────────────
    // Query the actual device DPI before `app` is moved into event_loop_builder.
    let device_density = query_device_density(&app);
    android_logger::log(&format!("Device display density: {device_density:.2}"));
    // Publish so egui's update() loop can track runtime changes (e.g. the user
    // adjusting "Display size" in Android Settings while the app is running).
    transferd_ui_shared::platform_hooks::DEVICE_PPP
        .store(device_density.to_bits(), std::sync::atomic::Ordering::Relaxed);

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
            // Set pixels_per_point from the NDK-queried density so egui
            // text and layout are sharp at the device's actual DPI.
            // DEVICE_PPP is also monitored each frame in update() to track
            // runtime changes (e.g. user changing Display Size in Settings).
            let detected_ppp = cc.egui_ctx.pixels_per_point();
            cc.egui_ctx.set_pixels_per_point(device_density);
            android_logger::log(&format!(
                "pixels_per_point: eframe={detected_ppp:.2} → override={device_density:.2}"
            ));
            let mut td_app = TransferDaemonApp::with_daemon(cc, daemon_arc, daemon_is_live);
            // Wire the daemon address so TelemetryPage can open its gRPC stream.
            td_app.state.daemon_addr = Some("http://127.0.0.1:50051".to_string());
            // Open local SQLite DB for session persistence, nicknames, and colors.
            let db_path = log_base.join("transferdaemon_ui.db");
            android_logger::log(&format!("Opening local DB at {:?}", db_path));
            td_app.init_db(&db_path);
            // Wire native file picker: trigger on 📎 tap, drain result each frame.
            td_app.chat_page_mut().on_attach = Some(on_attach);
            td_app.poll_file_pick = Some(Box::new(|| crate::file_picker::take()));
            // Wire the OS share-intent bridge (file/text from other apps).
            td_app.poll_share = Some(Box::new(|| {
                match crate::share_bridge::take() {
                    Some((kind, payload)) => {
                        eprintln!("[share] drained by UI: kind={kind} len={}", payload.len());
                        Some((kind, payload))
                    }
                    None => None,
                }
            }));
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

/// Query the device's logical display density via the NDK configuration API.
///
/// `android_app.config().density()` wraps `AConfiguration_getDensity()`, which
/// returns the same `densityDpi` value as `DisplayMetrics.densityDpi` in Java.
/// It correctly reports the hardware DPI bucket on Amazon Fire OS (240) without
/// the `density` float override that Fire OS applies (1.0, wrong).
///
/// Using the NDK path avoids JNI boilerplate and automatically reflects the
/// user's current "Display size" preference from Android Settings.
///
/// Must be called **before** `app` is moved into `event_loop_builder`.
#[cfg(target_os = "android")]
fn query_device_density(app: &android_activity::AndroidApp) -> f32 {
    let dpi = app.config().density().unwrap_or(160);
    android_logger::log(&format!("config density={dpi} dpi"));
    dpi as f32 / 160.0
}

/// iOS entry point.
///
/// Called from Swift via FFI. Initializes the daemon and runs the UI.
#[cfg(target_os = "ios")]
pub fn ios_main() {
    use transferd_ui_shared::{
        app::TransferDaemonApp,
        daemon::MockDaemon,
        grpc_daemon::GrpcDaemon,
    };
    use std::sync::Arc;

    // ── Start daemon ──────────────────────────────────────────────────────────
    crate::daemon_thread::spawn_with_config(String::new(), None);

    // Wait for daemon runtime handle
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while crate::daemon_thread::RUNTIME_HANDLE.get().is_none() {
        if std::time::Instant::now() > deadline {
            eprintln!("[iOS] WARNING: daemon runtime handle timeout");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

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
            daemon_arc = Arc::new(g);
            daemon_is_live = true;
        }
        None => {
            daemon_arc = Arc::new(MockDaemon::new());
            daemon_is_live = false;
        }
    }

    // ── Media capture factory ─────────────────────────────────────────────────
    let media_factory: Box<dyn Fn(bool) -> std::sync::Arc<dyn transferd_webrtc::media::MediaCapture> + Send + Sync> =
        Box::new(|video| {
            std::sync::Arc::new(ios_media::IosMediaCapture::new(video))
        });

    // ── eframe ────────────────────────────────────────────────────────────────
    let options = eframe::NativeOptions::default();

    match eframe::run_native(
        "TransferDaemon",
        options,
        Box::new(move |cc| {
            let mut td_app = TransferDaemonApp::with_daemon(cc, daemon_arc, daemon_is_live);
            td_app.state.daemon_addr = Some("http://127.0.0.1:50051".to_string());
            td_app.chat_page_mut().media_factory = Some(media_factory);
            Ok(Box::new(td_app))
        }),
    ) {
        Ok(()) => {}
        Err(e) => eprintln!("[iOS] eframe::run_native error: {e:?}"),
    }
}

/// Desktop compatibility stub.
pub fn run_ui(_daemon_addr: &str, _native_window_ptr: usize, _width: u32, _height: u32) {
    #[cfg(target_os = "android")]
    android_logger::log("run_ui() — NativeActivity owns the loop, ignoring");
}
