use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::Mutex;

/// Set by the UI when a text input field gains focus.
/// Polled by the Android platform layer to call KeyboardHelper.showKeyboard().
pub static SHOW_KEYBOARD: AtomicBool = AtomicBool::new(false);

/// Set by the UI when no text input field is active.
pub static HIDE_KEYBOARD: AtomicBool = AtomicBool::new(false);

/// egui events injected from the Java KeyboardHelper TextWatcher via JNI.
/// Drained at the start of each egui frame by TransferDaemonApp::update().
pub static INJECTED_EVENTS: Mutex<Vec<egui::Event>> = Mutex::new(Vec::new());

/// System bar insets in pixels (status bar top, nav bar bottom).
/// Updated every 32 ms by KeyboardHelper's Java polling thread via deliverInsets().
pub static SYSTEM_INSET_TOP: AtomicI32 = AtomicI32::new(0);
pub static SYSTEM_INSET_BOTTOM: AtomicI32 = AtomicI32::new(0);

/// Device pixels-per-point (display density). Stored as f32 bits; 0 = not set.
/// Written by the Android platform layer at startup and on `ConfigChanged` events.
/// Read each egui frame by `TransferDaemonApp::update()` so the scale automatically
/// tracks the user's "Display size" preference in Android Settings.
pub static DEVICE_PPP: AtomicU32 = AtomicU32::new(0);

/// Text to copy to the Android clipboard. Set by the UI when `output.copied_text`
/// is non-empty; drained by KeyboardHelper's Java polling thread via getClipboardText().
pub static CLIPBOARD_TEXT: Mutex<Option<String>> = Mutex::new(None);

/// Stored egui context so background JNI threads can request an immediate repaint
/// when keyboard events are pushed into INJECTED_EVENTS.  Without this, typed
/// characters sit in the queue for up to 500 ms waiting for the next scheduled frame.
static EGUI_CTX: Mutex<Option<egui::Context>> = Mutex::new(None);

/// Called once from TransferDaemonApp::with_daemon() to register the egui context.
pub fn register_egui_ctx(ctx: egui::Context) {
    if let Ok(mut g) = EGUI_CTX.lock() {
        *g = Some(ctx);
    }
}

/// Request an immediate egui repaint from any thread (e.g. a JNI callback thread).
/// No-op if the context has not been registered yet.
pub fn notify_repaint() {
    if let Ok(g) = EGUI_CTX.lock() {
        if let Some(ctx) = g.as_ref() {
            ctx.request_repaint();
        }
    }
}

pub fn request_copy_to_clipboard(text: String) {
    if let Ok(mut g) = CLIPBOARD_TEXT.lock() {
        *g = Some(text);
    }
}

pub fn request_show_keyboard() {
    SHOW_KEYBOARD.store(true, Ordering::Relaxed);
    HIDE_KEYBOARD.store(false, Ordering::Relaxed);
}

pub fn request_hide_keyboard() {
    HIDE_KEYBOARD.store(true, Ordering::Relaxed);
    SHOW_KEYBOARD.store(false, Ordering::Relaxed);
}
