//! Cross-platform file-pick bridge.
//!
//! On Android, `request()` launches `FilePickerActivity` (a transparent Java
//! Activity that runs ACTION_GET_CONTENT). The result arrives asynchronously via
//! `Java_com_transferdaemon_app_FilePickerActivity_deliverFilePath`, which stores
//! the resolved path in `PENDING_PATH`. The egui update loop drains it each frame
//! and writes it to `ChatPage::pending_file_path`.
//!
//! On non-Android builds this module compiles but `request()` is a no-op.

use std::sync::Mutex;

/// Path chosen by the user. Set from JNI; drained each egui frame.
pub static PENDING_PATH: Mutex<Option<String>> = Mutex::new(None);

/// Take the pending path (if any) and return it, clearing the slot.
pub fn take() -> Option<String> {
    PENDING_PATH.lock().unwrap_or_else(|e| e.into_inner()).take()
}

// ---------------------------------------------------------------------------
// Android implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
pub mod android {
    use super::PENDING_PATH;
    use jni::objects::{JClass, JString};
    use jni::JNIEnv;

    /// Called by Java `FilePickerActivity.deliverFilePath(String path)`.
    #[no_mangle]
    pub extern "system" fn Java_com_transferdaemon_app_FilePickerActivity_deliverFilePath(
        mut env: JNIEnv,
        _class: JClass,
        path: JString,
    ) {
        let p: String = env
            .get_string(&path)
            .map(Into::into)
            .unwrap_or_default();
        if !p.is_empty() {
            *PENDING_PATH.lock().unwrap() = Some(p);
        }
    }

    /// Launch `FilePickerActivity` via the NativeActivity's JVM.
    /// Called from the `on_attach` closure set in `platform/mod.rs`.
    /// The Activity context was stored by PermissionsActivity.setContext() before
    /// NativeActivity started, so we call the no-arg Java overload.
    pub fn launch(app: &android_activity::AndroidApp) {
        unsafe {
            let vm_ptr = app.vm_as_ptr() as *mut jni::sys::JavaVM;
            let vm = match jni::JavaVM::from_raw(vm_ptr) {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut env = vm.get_env().unwrap_or_else(|_| {
                vm.attach_current_thread_permanently().expect("attach JNI thread")
            });
            let helper = match env.find_class("com/transferdaemon/app/FilePickerActivity") {
                Ok(c) => c,
                Err(_) => return,
            };
            let _ = env.call_static_method(helper, "launch", "()V", &[]);
        }
    }
}
