//! Cross-platform OS share-intent bridge.
//!
//! When another app "shares" content to TransferDaemon, the Kotlin layer
//! resolves it and calls one of the JNI symbols below, which store the payload
//! in a static. The egui update loop polls `take()` each frame and routes it
//! into `ChatPage` (file → attach, text → draft).
//!
//! On non-Android builds the module compiles but the statics stay empty.

use std::sync::Mutex;

/// Pending share payload `(kind, payload)` where kind ∈ {"file", "text"}.
pub static PENDING_SHARE: Mutex<Option<(String, String)>> = Mutex::new(None);

/// Take the pending share (if any), clearing the slot.
pub fn take() -> Option<(String, String)> {
    PENDING_SHARE.lock().unwrap_or_else(|e| e.into_inner()).take()
}

// ---------------------------------------------------------------------------
// Android implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
pub mod android {
    use super::PENDING_SHARE;
    use jni::objects::{JClass, JString};
    use jni::JNIEnv;

    /// Called by Kotlin `ShareBridge.deliverSharedFile(path, mime)`.
    #[no_mangle]
    pub extern "system" fn Java_com_transferdaemon_app_ShareBridge_deliverSharedFile(
        mut env: JNIEnv,
        _class: JClass,
        path: JString,
        mime: JString,
    ) {
        let p: String = env.get_string(&path).map(Into::into).unwrap_or_default();
        let _m: String = env.get_string(&mime).map(Into::into).unwrap_or_default();
        eprintln!("[share] file captured: {p}");
        if !p.is_empty() {
            *PENDING_SHARE.lock().unwrap_or_else(|e| e.into_inner()) = Some(("file".into(), p));
        }
    }

    /// Called by Kotlin `ShareBridge.deliverSharedText(text)`.
    #[no_mangle]
    pub extern "system" fn Java_com_transferdaemon_app_ShareBridge_deliverSharedText(
        mut env: JNIEnv,
        _class: JClass,
        text: JString,
    ) {
        let t: String = env.get_string(&text).map(Into::into).unwrap_or_default();
        eprintln!("[share] text captured ({} chars)", t.len());
        if !t.is_empty() {
            *PENDING_SHARE.lock().unwrap_or_else(|e| e.into_inner()) = Some(("text".into(), t));
        }
    }
}