//! Terminal graphics capability detection.
//!
//! Priority: env-var override → Kitty → Sixel → HalfBlock → ASCII.
//! The user can set `TRANSFERD_VIDEO_BACKEND=halfblock|kitty|sixel|ascii`
//! to force a specific backend.

use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalGraphics {
    /// Kitty graphics protocol (best quality, full 24-bit RGB).
    Kitty,
    /// Sixel bitmap protocol (256 colors, good quality).
    Sixel,
    /// Unicode half-block ▀ with true-color ANSI (works in any true-color terminal).
    HalfBlock,
    /// Brightness-mapped ASCII art (maximum compatibility, lowest quality).
    Ascii,
}

impl TerminalGraphics {
    pub fn name(self) -> &'static str {
        match self {
            Self::Kitty     => "kitty",
            Self::Sixel     => "sixel",
            Self::HalfBlock => "halfblock",
            Self::Ascii     => "ascii",
        }
    }
}

/// Detect the best available terminal graphics capability.
///
/// Checks `TRANSFERD_VIDEO_BACKEND` first, then probes environment variables
/// set by known terminal emulators. Falls back to `HalfBlock` if true color
/// is indicated, otherwise `Ascii`.
pub fn detect() -> TerminalGraphics {
    // Manual override.
    if let Ok(v) = env::var("TRANSFERD_VIDEO_BACKEND") {
        match v.to_lowercase().as_str() {
            "kitty"     => return TerminalGraphics::Kitty,
            "sixel"     => return TerminalGraphics::Sixel,
            "halfblock" => return TerminalGraphics::HalfBlock,
            "ascii"     => return TerminalGraphics::Ascii,
            _ => {}
        }
    }

    let term_program = env::var("TERM_PROGRAM").unwrap_or_default();
    let term         = env::var("TERM").unwrap_or_default();
    let colorterm    = env::var("COLORTERM").unwrap_or_default();
    let vte_ver      = env::var("VTE_VERSION").unwrap_or_default();

    // Kitty-native or WezTerm (supports Kitty protocol).
    if term == "xterm-kitty" || term_program.to_lowercase().contains("wezterm") {
        return TerminalGraphics::Kitty;
    }

    // Sixel support: xterm (when compiled with --enable-sixel), mlterm, foot, WezTerm.
    if term.contains("sixel") || term_program == "mlterm"
        || env::var("TERM_PROGRAM_VERSION").is_ok() && term_program == "WezTerm"
        || env::var("XTERM_LOCALE").is_ok()
    {
        return TerminalGraphics::Sixel;
    }

    // True-color capable → HalfBlock (works universally with ANSI escape codes).
    if colorterm == "truecolor" || colorterm == "24bit"
        || term.contains("256color")
        || !vte_ver.is_empty() // VTE-based terminals (GNOME Terminal, Xfce4) support true color
        || term_program == "iTerm.app"
    {
        return TerminalGraphics::HalfBlock;
    }

    TerminalGraphics::Ascii
}
