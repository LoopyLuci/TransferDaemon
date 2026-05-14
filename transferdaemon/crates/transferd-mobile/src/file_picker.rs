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
    PENDING_PATH.lock().unwrap().take()
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
    pub fn launch(app: &android_activity::AndroidApp) {
        // Safety: `native_activity()` returns a valid pointer for the duration
        // of the NativeActivity's lifetime, which encompasses this call.
        unsafe {
            let na = app.native_activity();
            let vm = (*na.as_ptr()).vm as *mut jni::sys::JavaVM;
            let env_ptr = (*na.as_ptr()).env as *mut jni::sys::JNIEnv;

            let vm = jni::JavaVM::from_raw(vm).expect("JavaVM from_raw");
            let mut env = vm.get_env().unwrap_or_else(|_| {
                vm.attach_current_thread_permanently().expect("attach JNI thread")
            });
            let _ = env_ptr; // kept to surface the type for clarity

            let activity_obj = jni::objects::JObject::from_raw(
                (*na.as_ptr()).clazz as jni::sys::jobject,
            );

            // Intent intent = new Intent(this, FilePickerActivity.class);
            // startActivity(intent);
            // We call a static helper method to avoid constructing Intent in JNI.
            let helper = env.find_class("com/transferdaemon/app/FilePickerActivity")
                .expect("FilePickerActivity not found");
            env.call_static_method(
                helper,
                "launch",
                "(Landroid/app/Activity;)V",
                &[jni::objects::JValueGen::Object(&activity_obj)],
            ).expect("FilePickerActivity.launch failed");
        }
    }
}
