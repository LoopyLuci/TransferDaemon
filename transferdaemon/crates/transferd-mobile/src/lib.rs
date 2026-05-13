//! TransferDaemon mobile entry point.
//!
//! Exposes two C-ABI functions:
//!
//!   - `start_daemon(socket_path)` — spawns the daemon on a background thread.
//!   - `start_ui(socket_path, native_window, width, height)` — spawns the UI thread.
//!
//! On Android the native_window is an `ANativeWindow *`.
//! On iOS    the native_window is an opaque `MTKView *`.
//! On desktop (feature = "desktop") the native_window is ignored; the platform
//! module opens its own window using the standard eframe flow.

use std::ffi::{c_char, c_void, CStr};

mod daemon_thread;
mod platform;

// ---------------------------------------------------------------------------
// Public C-ABI entry points
// ---------------------------------------------------------------------------

/// Start the TransferDaemon gRPC server on a background thread.
///
/// `socket_path` must be a null-terminated UTF-8 path to the Unix socket
/// (on Android: inside `filesDir`; on iOS: in the app sandbox tmp dir).
#[no_mangle]
pub extern "C" fn start_daemon(socket_path: *const c_char) {
    let path = unsafe { CStr::from_ptr(socket_path) }.to_str().unwrap_or("").to_owned();
    daemon_thread::spawn(path);
}

/// Start the TransferDaemon UI on a background thread.
///
/// `native_window` is passed to the platform renderer.  On desktop builds
/// (feature = "desktop") it is ignored and an OS window is created instead.
#[no_mangle]
pub extern "C" fn start_ui(
    socket_path: *const c_char,
    native_window: *mut c_void,
    width:  u32,
    height: u32,
) {
    let path = unsafe { CStr::from_ptr(socket_path) }.to_str().unwrap_or("").to_owned();
    let win  = native_window as usize; // send the raw pointer across threads as usize
    std::thread::spawn(move || {
        platform::run_ui(&path, win, width, height);
    });
}
