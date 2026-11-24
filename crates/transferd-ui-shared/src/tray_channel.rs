//! Channel types for communication between the egui app and the system tray.
//!
//! These are intentionally free of any GUI/tray library types so they can live
//! in the shared crate without pulling in heavy platform-specific dependencies.

/// Commands sent from the tray thread back to the app.
#[derive(Debug, Clone, PartialEq)]
pub enum TrayCommand {
    ShowWindow,
    Quit,
}

/// Updates sent from the app to the tray thread.
#[derive(Debug, Clone)]
pub enum TrayUpdate {
    SetBadge(Option<u32>),
    SetTooltip(String),
}
