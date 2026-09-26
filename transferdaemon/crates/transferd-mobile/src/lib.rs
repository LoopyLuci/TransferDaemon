//! TransferDaemon mobile entry point.
//!
//! On Android this library is loaded by `android.app.NativeActivity`.
//! The `android-activity` crate bridges `ANativeActivity_onCreate` → `android_main`.
//!
//! On iOS this library is called from Swift via C FFI.
//!
//! On desktop (feature = "desktop") the JNI shims below are omitted and the
//! crate is used only by integration tests via `daemon_thread`.

mod daemon_thread;
pub mod file_picker;
pub mod grpc_bridge;
pub mod notifications;
pub mod share_bridge;
#[cfg(target_os = "android")]
mod keyboard_input;
#[cfg(target_os = "ios")]
pub mod ios_app;
pub mod platform;

// ---------------------------------------------------------------------------
// Android NativeActivity entry point
// ---------------------------------------------------------------------------

/// Called by the JVM immediately after `System.loadLibrary("transferd_mobile")`.
///
/// This runs on the Java thread that called loadLibrary, which has the **app**
/// class loader.  We use this window to call `find_class` for app-defined classes
/// (like `KeyboardHelper`) and register their native methods explicitly via
/// `env.register_native_methods`.  This is necessary because native pthreads
/// (including the android_main thread spawned by NativeActivity) only have the
/// bootstrap class loader and cannot `find_class` for app classes at all.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    eprintln!("[TDJni] JNI_OnLoad entered");
    match unsafe { jni::JavaVM::from_raw(vm) } {
        Err(e) => eprintln!("[TDJni] JNI_OnLoad: from_raw failed: {:?}", e),
        Ok(vm) => {
            // A second handle to the same VM for the notification thread.
            if let Ok(second) = unsafe { jni::JavaVM::from_raw(vm.get_java_vm_pointer()) } {
                notifications::android::store_vm(second);
            }
            match vm.get_env() {
                Err(e) => eprintln!("[TDJni] JNI_OnLoad: get_env failed: {:?}", e),
                Ok(mut env) => {
                    keyboard_input::register_native_methods(&mut env);
                    notifications::android::cache_helper_class(&mut env);
                }
            }
        }
    }
    eprintln!("[TDJni] JNI_OnLoad done");
    jni::sys::JNI_VERSION_1_6
}

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

    /// # Safety
    /// `socket_path` must be a valid, non-null, null-terminated C string that
    /// remains valid for the duration of the call.
    #[no_mangle]
    pub unsafe extern "C" fn start_daemon(socket_path: *const c_char) {
        let path = CStr::from_ptr(socket_path)
            .to_str()
            .unwrap_or("")
            .to_owned();
        daemon_thread::spawn(path);
    }

    /// # Safety
    /// `socket_path` must be a valid, non-null, null-terminated C string.
    /// `native_window` must be a valid pointer to a platform native window handle
    /// (e.g. `ANativeWindow*`) or null for headless mode.
    #[no_mangle]
    pub unsafe extern "C" fn start_ui(
        socket_path: *const c_char,
        native_window: *mut c_void,
        width: u32,
        height: u32,
    ) {
        let path = CStr::from_ptr(socket_path)
            .to_str()
            .unwrap_or("")
            .to_owned();
        let ptr = native_window as usize; // usize is Send
        std::thread::spawn(move || {
            platform::run_ui(&path, ptr, width, height);
        });
    }
}
