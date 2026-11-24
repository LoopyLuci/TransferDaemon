//! Cross-platform desktop notification service.
//!
//! Provides a unified `send_notification` function that dispatches to:
//! - `notify-rust` on Linux (D-Bus) and macOS (Foundation)
//! - `tracing::info!` + in-app toast on Windows (until a WinRT toast backend is added)

pub enum NotificationLevel {
    Info,
    NewMessage,
    TransferComplete,
    Error,
}

/// Send a desktop notification.
///
/// On Linux and macOS this uses the system notification daemon.
/// On Windows it logs to tracing (in-app toasts handle the visual feedback).
#[cfg(not(target_os = "windows"))]
pub fn send_notification(title: &str, body: &str, _level: NotificationLevel) {
    use notify_rust::Notification;

    let mut n = Notification::new();
    n.summary(title)
     .body(body)
     .appname("TransferDaemon");

    // urgency/timeout are Linux (D-Bus) specific in notify-rust; macOS uses
    // the default notification style.
    #[cfg(target_os = "linux")]
    {
        match _level {
            NotificationLevel::Error => n.urgency(notify_rust::Urgency::Critical),
            _ => n.urgency(notify_rust::Urgency::Normal),
        };
        n.timeout(5000);
    }

    let _ = n.show();
}

/// Windows notification stub — logs the notification.
/// In-app toasts (ToastManager) provide the visual feedback on Windows.
#[cfg(target_os = "windows")]
pub fn send_notification(title: &str, body: &str, _level: NotificationLevel) {
    tracing::info!("[Notification] {title}: {body}");
}
