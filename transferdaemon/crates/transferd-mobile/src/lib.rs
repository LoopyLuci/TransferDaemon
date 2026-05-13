//! TransferDaemon mobile entry point.
//!
//! On Android this library is loaded by `android.app.NativeActivity`.
//! The `android-activity` crate bridges `ANativeActivity_onCreate` → `android_main`.
//!
//! On desktop (feature = "desktop") the JNI shims below are omitted and the
//! crate is used only by integration tests via `daemon_thread`.

mod daemon_thread;
pub mod platform;

// ---------------------------------------------------------------------------
// Android NativeActivity entry point
// ---------------------------------------------------------------------------

/// Called by the `android-activity` C bridge immediately after the .so is loaded
/// by NativeActivity.  This function starts the daemon then runs the eframe loop.
#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: android_activity::AndroidApp) {
    platform::android_main_impl(app);
}

// ---------------------------------------------------------------------------
// Legacy JNI shim — kept so that DaemonService.startDaemon() still compiles
// if the Java file is present. startUi is no longer called (NativeActivity
// drives the UI via android_main above).
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
mod android_jni {
    use super::daemon_thread;
    use jni::objects::{JClass, JObject, JString};
    use jni::sys::jint;
    use jni::JNIEnv;

    /// Called by DaemonService.startDaemon() — starts the gRPC daemon.
    /// With NativeActivity this is no longer the primary startup path
    /// (android_main starts the daemon directly), but kept for compatibility.
    #[no_mangle]
    pub extern "system" fn Java_com_transferdaemon_app_DaemonService_startDaemon(
        mut env: JNIEnv,
        _class: JClass,
        socket_path: JString,
    ) {
        let path: String = env
            .get_string(&socket_path)
            .map(|s| s.into())
            .unwrap_or_default();
        daemon_thread::spawn(path);
    }

    /// Legacy shim — not called when using NativeActivity.
    #[no_mangle]
    pub extern "system" fn Java_com_transferdaemon_app_MainActivity_startUi(
        _env: JNIEnv,
        _class: JClass,
        _surface: JObject,
        _width: jint,
        _height: jint,
    ) {
        // No-op: NativeActivity / android_main owns the rendering loop.
    }
}

// ---------------------------------------------------------------------------
// Desktop / test entry points
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "android"))]
pub mod desktop {
    use super::{daemon_thread, platform};
    use std::ffi::{c_char, c_void, CStr};

    #[no_mangle]
    pub extern "C" fn start_daemon(socket_path: *const c_char) {
        let path = unsafe { CStr::from_ptr(socket_path) }
            .to_str()
            .unwrap_or("")
            .to_owned();
        daemon_thread::spawn(path);
    }

    #[no_mangle]
    pub extern "C" fn start_ui(
        socket_path: *const c_char,
        native_window: *mut c_void,
        width: u32,
        height: u32,
    ) {
        let path = unsafe { CStr::from_ptr(socket_path) }
            .to_str()
            .unwrap_or("")
            .to_owned();
        std::thread::spawn(move || {
            platform::run_ui(&path, native_window as usize, width, height);
        });
    }
}
