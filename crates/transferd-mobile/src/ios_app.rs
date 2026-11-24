//! TransferDaemon iOS App Shell
//!
//! This SwiftUI app provides an iOS frontend for TransferDaemon.
//! It bridges to the Rust `transferd-mobile` library via C FFI.

use std::sync::Arc;

/// iOS app entry point.
///
/// Called from Swift via FFI to initialize the daemon and start the UI.
#[cfg(target_os = "ios")]
pub fn ios_app_start() {
    crate::platform::ios_main();
}

/// iOS app delegate callbacks.
#[cfg(target_os = "ios")]
pub mod app_delegate {
    use std::sync::atomic::{AtomicBool, Ordering};

    static DID_FINISH_LAUNCHING: AtomicBool = AtomicBool::new(false);

    pub fn did_finish_launching() -> bool {
        DID_FINISH_LAUNCHING.load(Ordering::Relaxed)
    }

    pub fn set_did_finish_launching() {
        DID_FINISH_LAUNCHING.store(true, Ordering::Relaxed);
    }

    pub fn will_resign_active() {
        // Pause non-critical tasks
    }

    pub fn did_become_active() {
        // Resume non-critical tasks
    }

    pub fn did_enter_background() {
        // Save state, prepare for suspension
    }

    pub fn will_enter_foreground() {
        // Refresh state on return
    }

    pub fn will_terminate() {
        // Clean shutdown
    }
}

/// iOS permission request handlers.
#[cfg(target_os = "ios")]
pub mod permissions {
    /// Request camera permission.
    pub fn request_camera() -> bool {
        // In production, use AVFoundation's AVCaptureDevice.requestAccess
        true
    }

    /// Request microphone permission.
    pub fn request_microphone() -> bool {
        // In production, use AVAudioSession's requestRecordPermission
        true
    }

    /// Request notification permission.
    pub fn request_notifications() -> bool {
        // In production, use UNUserNotificationCenter
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_app_delegate_states() {
        assert!(!super::app_delegate::did_finish_launching());
        super::app_delegate::set_did_finish_launching();
        assert!(super::app_delegate::did_finish_launching());
    }
}
