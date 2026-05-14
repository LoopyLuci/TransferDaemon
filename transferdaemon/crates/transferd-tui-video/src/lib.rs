//! TransferDaemon terminal video renderer.
//!
//! Selects the best available terminal graphics protocol at runtime:
//!
//! | Backend     | Quality       | Terminals                          |
//! |-------------|---------------|------------------------------------|
//! | Kitty       | Full 24-bit   | Kitty, WezTerm                     |
//! | Sixel       | 256 colors    | xterm -ti vt340, mlterm, foot, … |
//! | HalfBlock   | True-color    | Any true-color terminal (default)  |
//! | Ascii       | Low           | Any terminal                       |
//!
//! Override with `TRANSFERD_VIDEO_BACKEND=kitty|sixel|halfblock|ascii`.

pub mod backends;
pub mod detection;
pub mod widget;

pub use detection::{detect, TerminalGraphics};
pub use widget::VideoCallOverlay;
