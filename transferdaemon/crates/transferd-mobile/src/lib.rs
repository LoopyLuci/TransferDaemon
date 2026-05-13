//! TransferDaemon mobile entry point.
//!
//! Exposes JNI entry points called by MainActivity and DaemonService.
//! The function names follow the JNI convention:
//!   Java_<package>_<Class>_<method>
//!
//! Daemon: DaemonService.startDaemon(String socketPath)
//! UI:     MainActivity.startUi(Object surface, int width, int height)

mod daemon_thread;
mod platform;

// ---------------------------------------------------------------------------
// Android JNI entry points
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
mod android_jni {
    use super::{daemon_thread, platform};
    use jni::objects::{JClass, JObject, JString};
    use jni::sys::jint;
    use jni::JNIEnv;

    /// Called by DaemonService.startDaemon(String socketPath).
    /// Spawns the gRPC daemon on a background thread listening on 127.0.0.1:50051.
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

    /// Called by MainActivity.startUi(Object surface, int width, int height).
    /// Spawns the UI thread. The Java Activity provides the visible layout;
    /// this stub just ensures the call succeeds without crashing.
    #[no_mangle]
    pub extern "system" fn Java_com_transferdaemon_app_MainActivity_startUi(
        _env: JNIEnv,
        _class: JClass,
        _surface: JObject,
        width: jint,
        height: jint,
    ) {
        let w = width as u32;
        let h = height as u32;
        std::thread::spawn(move || {
            platform::run_ui("http://127.0.0.1:50051", 0, w, h);
        });
    }
}

// ---------------------------------------------------------------------------
// Desktop / test entry points (non-Android only)
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
        let win = native_window as usize;
        std::thread::spawn(move || {
            platform::run_ui(&path, win, width, height);
        });
    }
}
