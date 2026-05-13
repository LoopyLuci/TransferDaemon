//! Platform-specific UI entry point.
//!
//! On Android: `android_main_impl` is called from the `android_main` symbol
//! exported in `lib.rs`. It starts the gRPC daemon then runs an eframe loop.
//!
//! On desktop: `run_ui` is a no-op kept for ABI compatibility with tests.

#[cfg(target_os = "android")]
pub mod android_logger;

// ---------------------------------------------------------------------------
// Public entry point (called from lib.rs android_main)
// ---------------------------------------------------------------------------

/// Run the full app: daemon + eframe UI loop.
/// Only compiled for Android; desktop tests never call this path.
#[cfg(target_os = "android")]
pub fn android_main_impl(app: android_activity::AndroidApp) {
    use winit::platform::android::EventLoopBuilderExtAndroid;

    // ── File + logcat logger ──────────────────────────────────────────────
    let log_base = app
        .external_data_path()
        .or_else(|| app.internal_data_path())
        .unwrap_or_else(|| std::path::PathBuf::from("/data/local/tmp"));
    android_logger::init(&log_base);
    android_logger::log("=== android_main start ===");
    android_logger::log(&format!(
        "external_data_path = {:?}",
        app.external_data_path()
    ));

    // ── Start gRPC daemon in background ──────────────────────────────────
    android_logger::log("Spawning daemon thread…");
    crate::daemon_thread::spawn(String::new());
    android_logger::log("Daemon spawned — sleeping 600 ms for port bind…");
    std::thread::sleep(std::time::Duration::from_millis(600));

    // ── Build eframe options ──────────────────────────────────────────────
    // eframe 0.28: pass AndroidApp through the event_loop_builder hook.
    android_logger::log("Building NativeOptions…");
    let options = eframe::NativeOptions {
        event_loop_builder: Some(Box::new(move |builder| {
            builder.with_android_app(app);
        })),
        ..Default::default()
    };

    // ── Run eframe ────────────────────────────────────────────────────────
    android_logger::log("Calling eframe::run_native…");
    match eframe::run_native(
        "TransferDaemon",
        options,
        Box::new(|cc| {
            android_logger::log("eframe app factory — constructing TransferDaemonMobileApp");
            Ok(Box::new(TransferDaemonMobileApp::new(cc)))
        }),
    ) {
        Ok(()) => android_logger::log("eframe::run_native returned — event loop ended"),
        Err(e) => android_logger::log(&format!("eframe::run_native error: {e:?}")),
    }

    android_logger::log("=== android_main exit ===");
}

// ---------------------------------------------------------------------------
// Mobile egui app
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
struct TransferDaemonMobileApp {
    frame: u64,
}

#[cfg(target_os = "android")]
impl TransferDaemonMobileApp {
    fn new(_cc: &eframe::CreationContext) -> Self {
        android_logger::log("TransferDaemonMobileApp created");
        Self { frame: 0 }
    }
}

#[cfg(target_os = "android")]
impl eframe::App for TransferDaemonMobileApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.frame += 1;
        match self.frame {
            1 => android_logger::log("First egui frame rendered ✓"),
            60 => android_logger::log("60 frames rendered — rendering loop is healthy"),
            _ => {}
        }

        ctx.request_repaint();

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(18, 18, 18)))
            .show(ctx, |ui| {
                ui.add_space(48.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("TransferDaemon")
                            .color(egui::Color32::WHITE)
                            .size(30.0)
                            .strong(),
                    );
                    ui.add_space(16.0);
                    ui.label(
                        egui::RichText::new("● Daemon running on 127.0.0.1:50051")
                            .color(egui::Color32::from_rgb(48, 209, 88))
                            .size(14.0),
                    );
                    ui.add_space(32.0);
                    ui.label(
                        egui::RichText::new("Secure P2P file transfer")
                            .color(egui::Color32::from_gray(140))
                            .size(15.0),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(format!("frame {}", self.frame))
                            .color(egui::Color32::from_gray(60))
                            .size(11.0),
                    );
                });
            });
    }
}

// ---------------------------------------------------------------------------
// Desktop compatibility stub
// ---------------------------------------------------------------------------

/// Called from the legacy JNI shim. No-op with NativeActivity.
pub fn run_ui(_daemon_addr: &str, _native_window_ptr: usize, _width: u32, _height: u32) {
    #[cfg(target_os = "android")]
    android_logger::log("run_ui() called — NativeActivity owns the loop, ignoring");
}
