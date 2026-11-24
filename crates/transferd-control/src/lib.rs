//! TransferDaemon's control plane.
//!
//! * [`catalog`]: every operation (the daemon's whole gRPC API plus the daemon process, its GUI and TUI, and local
//!   relays), described with JSON Schemas built from `transferd.proto` ([`schema`]).
//! * [`hub`]: the local HTTP endpoint the daemon runs (`/v1/call/{op}`, `/mcp`, UI attachment). Feature `hub`.
//! * [`client`]: finds a running hub (`control.json`) and calls it; the GUI and TUI attach through it.
//! * [`mcp`]: the Model Context Protocol server, used by the hub (`/mcp`) and `transferd-cli mcp` (stdio).

pub mod client;
pub mod mcp;
pub mod schema;

#[cfg(feature = "hub")]
pub mod catalog;
#[cfg(feature = "hub")]
pub mod hub;

pub use client::{attach, discover, Client, ClientError, Discovery, UiCommand};

/// Parse a key chord like `ctrl+shift+Tab` into (modifiers, key). Shared by the GUI and TUI automation so both accept
/// the same spelling.
pub fn parse_chord(chord: &str) -> (Vec<String>, String) {
    let parts: Vec<&str> = chord.split('+').map(str::trim).filter(|p| !p.is_empty()).collect();
    let Some((key, mods)) = parts.split_last() else { return (vec![], String::new()) };
    (mods.iter().map(|m| m.to_lowercase()).collect(), key.to_string())
}

/// Split a key sequence (`"ctrl+n Enter"`, `"Down Down Enter"`) into chords.
pub fn chords(keys: &str) -> Vec<(Vec<String>, String)> {
    keys.split_whitespace().map(parse_chord).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn chords_parse() {
        assert_eq!(super::chords("ctrl+shift+Tab Enter"), vec![
            (vec!["ctrl".to_string(), "shift".to_string()], "Tab".to_string()),
            (vec![], "Enter".to_string()),
        ]);
    }
}
