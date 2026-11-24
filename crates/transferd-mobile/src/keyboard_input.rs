//! JNI callbacks from KeyboardHelper.java → egui event injection.
//!
//! KeyboardHelper's TextWatcher calls these when the user types on the soft
//! keyboard. Events are pushed into INJECTED_EVENTS and drained at the start
//! of each egui frame so the focused TextEdit receives them.

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring};
use jni::JNIEnv;
use transferd_ui_shared::platform_hooks::{CLIPBOARD_TEXT, INJECTED_EVENTS, SHOW_KEYBOARD, HIDE_KEYBOARD, SYSTEM_INSET_TOP, SYSTEM_INSET_BOTTOM};
use std::sync::atomic::Ordering;

/// Polled by KeyboardHelper's Java thread every 32 ms.
/// Returns true and clears the flag if Rust wants the soft keyboard shown.
/// Called from `JNI_OnLoad` in lib.rs to register all KeyboardHelper native
/// methods explicitly.  Must be called from the Java thread that loaded the
/// library (which has the app class loader) because `find_class` for app
/// classes fails from native pthreads (they only have the bootstrap loader).
pub fn register_native_methods(env: &mut jni::JNIEnv) {
    eprintln!("[TDJni] register_native_methods: calling find_class KeyboardHelper");
    match env.find_class("com/transferdaemon/app/KeyboardHelper") {
        Err(e) => {
            eprintln!("[TDJni] register_native_methods: find_class FAILED: {:?}", e);
            let _ = env.exception_clear();
            return;
        }
        Ok(class) => {
            eprintln!("[TDJni] register_native_methods: find_class OK");
            register_methods_for_class(env, class);
        }
    }
}

fn register_methods_for_class(env: &mut jni::JNIEnv, class: jni::objects::JClass) {
    let methods = [
        jni::NativeMethod {
            name: "getClipboardText".into(),
            sig: "()Ljava/lang/String;".into(),
            fn_ptr: Java_com_transferdaemon_app_KeyboardHelper_getClipboardText
                as *mut std::ffi::c_void,
        },
        jni::NativeMethod {
            name: "shouldShowKeyboard".into(),
            sig: "()Z".into(),
            fn_ptr: Java_com_transferdaemon_app_KeyboardHelper_shouldShowKeyboard
                as *mut std::ffi::c_void,
        },
        jni::NativeMethod {
            name: "shouldHideKeyboard".into(),
            sig: "()Z".into(),
            fn_ptr: Java_com_transferdaemon_app_KeyboardHelper_shouldHideKeyboard
                as *mut std::ffi::c_void,
        },
        jni::NativeMethod {
            name: "deliverText".into(),
            sig: "(Ljava/lang/String;)V".into(),
            fn_ptr: Java_com_transferdaemon_app_KeyboardHelper_deliverText
                as *mut std::ffi::c_void,
        },
        jni::NativeMethod {
            name: "deliverBackspace".into(),
            sig: "()V".into(),
            fn_ptr: Java_com_transferdaemon_app_KeyboardHelper_deliverBackspace
                as *mut std::ffi::c_void,
        },
        jni::NativeMethod {
            name: "deliverEnter".into(),
            sig: "()V".into(),
            fn_ptr: Java_com_transferdaemon_app_KeyboardHelper_deliverEnter
                as *mut std::ffi::c_void,
        },
        jni::NativeMethod {
            name: "deliverInsets".into(),
            sig: "(II)V".into(),
            fn_ptr: Java_com_transferdaemon_app_KeyboardHelper_deliverInsets
                as *mut std::ffi::c_void,
        },
        jni::NativeMethod {
            name: "notifyRepaint".into(),
            sig: "()V".into(),
            fn_ptr: Java_com_transferdaemon_app_KeyboardHelper_notifyRepaint
                as *mut std::ffi::c_void,
        },
    ];
    match env.register_native_methods(&class, &methods) {
        Ok(_) => eprintln!("[TDJni] register_native_methods: registration OK"),
        Err(e) => eprintln!("[TDJni] register_native_methods: registration FAILED: {:?}", e),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_transferdaemon_app_KeyboardHelper_shouldShowKeyboard(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    SHOW_KEYBOARD.swap(false, Ordering::Relaxed) as jboolean
}

/// Polled by KeyboardHelper's Java thread every 32 ms.
/// Returns true and clears the flag if Rust wants the soft keyboard hidden.
#[no_mangle]
pub extern "system" fn Java_com_transferdaemon_app_KeyboardHelper_shouldHideKeyboard(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    HIDE_KEYBOARD.swap(false, Ordering::Relaxed) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_transferdaemon_app_KeyboardHelper_deliverText(
    mut env: JNIEnv,
    _class: JClass,
    text: JString,
) {
    let s: String = match env.get_string(&text) {
        Ok(v) => v.into(),
        Err(_) => return,
    };
    if let Ok(mut events) = INJECTED_EVENTS.lock() {
        for ch in s.chars() {
            events.push(egui::Event::Text(ch.to_string()));
        }
    }
    // Wake the render loop immediately — without this, characters sit in
    // INJECTED_EVENTS for up to 500 ms waiting for the next scheduled frame.
    transferd_ui_shared::platform_hooks::notify_repaint();
}

#[no_mangle]
pub extern "system" fn Java_com_transferdaemon_app_KeyboardHelper_deliverBackspace(
    _env: JNIEnv,
    _class: JClass,
) {
    if let Ok(mut events) = INJECTED_EVENTS.lock() {
        events.push(egui::Event::Key {
            key: egui::Key::Backspace,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        events.push(egui::Event::Key {
            key: egui::Key::Backspace,
            physical_key: None,
            pressed: false,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }
    transferd_ui_shared::platform_hooks::notify_repaint();
}

#[no_mangle]
pub extern "system" fn Java_com_transferdaemon_app_KeyboardHelper_deliverEnter(
    _env: JNIEnv,
    _class: JClass,
) {
    if let Ok(mut events) = INJECTED_EVENTS.lock() {
        events.push(egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        events.push(egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: false,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }
    transferd_ui_shared::platform_hooks::notify_repaint();
}

/// Called by KeyboardHelper's polling thread every 32 ms with current system bar heights.
#[no_mangle]
pub extern "system" fn Java_com_transferdaemon_app_KeyboardHelper_deliverInsets(
    _env: JNIEnv,
    _class: JClass,
    top_px: jint,
    bottom_px: jint,
) {
    SYSTEM_INSET_TOP.store(top_px, Ordering::Relaxed);
    SYSTEM_INSET_BOTTOM.store(bottom_px, Ordering::Relaxed);
}

/// Called by KeyboardHelper's polling thread to drain a pending clipboard write.
/// Returns the text to copy, or null if nothing is pending.
#[no_mangle]
pub extern "system" fn Java_com_transferdaemon_app_KeyboardHelper_getClipboardText(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    if let Ok(mut g) = CLIPBOARD_TEXT.lock() {
        if let Some(text) = g.take() {
            return env.new_string(&text)
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut());
        }
    }
    std::ptr::null_mut()
}

/// Called from KeyboardHelper's custom InputConnection after delivering input events,
/// so the egui render loop wakes immediately instead of waiting for the next poll tick.
#[no_mangle]
pub extern "system" fn Java_com_transferdaemon_app_KeyboardHelper_notifyRepaint(
    _env: JNIEnv,
    _class: JClass,
) {
    transferd_ui_shared::platform_hooks::notify_repaint();
}
