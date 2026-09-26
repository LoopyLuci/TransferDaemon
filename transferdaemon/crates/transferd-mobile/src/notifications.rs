//! Cross-platform incoming-message notification bridge.
//!
//! The daemon fires `transferd_lib::state::set_inbound_notify` on every new
//! inbound 1:1 text. On Android this module forwards it to `NotificationHelper`
//! (Kotlin) which posts a system notification. On non-Android targets it's a
//! no-op so the daemon hook stays harmless.

/// Notify the platform about a new inbound message.
/// `(sender_name, text, contact_id)`.
pub fn notify_incoming(sender: &str, text: &str, contact_id: &str) {
    #[cfg(target_os = "android")]
    android::notify_incoming(sender, text, contact_id);
    #[cfg(not(target_os = "android"))]
    {
        let _ = (sender, text, contact_id);
    }
}

#[cfg(target_os = "android")]
pub mod android {
    use jni::JavaVM;
    use jni::objects::{GlobalRef, JValue};
    use jni::sys::jobject;
    use jni::JNIEnv;
    use std::sync::{Mutex, OnceLock};

    /// The app's JavaVM, captured in `JNI_OnLoad`. Used to attach the daemon
    /// thread when it needs to raise a notification.
    static JVM: OnceLock<JavaVM> = OnceLock::new();

    /// Global reference to `NotificationHelper`, cached on the Java thread so
    /// native daemon threads (which only have the bootstrap class loader) can
    /// call its static method.
    static HELPER_CLASS: Mutex<Option<GlobalRef>> = Mutex::new(None);

    /// Store the JavaVM (called from `JNI_OnLoad`).
    pub fn store_vm(vm: JavaVM) {
        let _ = JVM.set(vm);
    }

    /// Cache the app class reference. Must run on the Java thread that loaded
    /// the library (i.e. from `JNI_OnLoad`), which has the app class loader.
    pub fn cache_helper_class(env: &mut JNIEnv) {
        match env.find_class("com/transferdaemon/app/NotificationHelper") {
            Ok(class) => match env.new_global_ref(class) {
                Ok(g) => {
                    *HELPER_CLASS.lock().unwrap_or_else(|e| e.into_inner()) = Some(g);
                    eprintln!("[TDJni] NotificationHelper class cached");
                }
                Err(e) => eprintln!("[TDJni] NotificationHelper global ref failed: {e:?}"),
            },
            Err(e) => eprintln!("[TDJni] find NotificationHelper failed: {e:?}"),
        }
    }

    /// Attach the current thread permanently (daemon threads aren't Java
    /// threads) and return an env. Best-effort: `None` if the VM isn't set.
    fn env() -> Option<JNIEnv<'static>> {
        let vm = JVM.get()?;
        match vm.get_env() {
            Ok(env) => Some(env),
            Err(_) => vm.attach_current_thread_permanently().ok(),
        }
    }

    /// Forward an incoming message to Kotlin's `NotificationHelper`.
    pub fn notify_incoming(sender: &str, text: &str, contact_id: &str) {
        eprintln!("[notify] incoming from {contact_id}: {} chars", text.len());
        let mut env = match env() {
            Some(e) => e,
            None => return,
        };
        let class = match HELPER_CLASS.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            Some(c) => c,
            None => return, // not cached (JNI_OnLoad didn't find the app class)
        };
        let j_sender = match env.new_string(sender) { Ok(s) => s, Err(_) => return };
        let j_text = match env.new_string(text) { Ok(s) => s, Err(_) => return };
        let j_cid = match env.new_string(contact_id) { Ok(s) => s, Err(_) => return };
        let _ = env.call_static_method(
            &class,
            "postIncoming",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            &[
                JValue::Object(&j_sender),
                JValue::Object(&j_text),
                JValue::Object(&j_cid),
            ],
        );
    }

    /// Helper to safely build a `jobject` from a raw jobject (for context passing).
    pub unsafe fn from_jobject(_obj: jobject) -> jobject {
        _obj
    }
}