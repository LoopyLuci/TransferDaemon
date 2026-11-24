//! Driving the terminal UI from outside: the `tui.*` operations of the daemon's control hub.
//!
//! The TUI attaches to the hub like the window does. Commands come in on a channel and are handled inside the main
//! loop, between frames, exactly where real key presses are handled: keys go through `events::handle_key`, and the
//! screen is the buffer ratatui just drew. With `--headless` the TUI draws into memory instead of a terminal, so it
//! can run (and be driven) where there is no console at all.

use crate::app::{App, ChatFocus, Modal, Screen, Tab};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use serde_json::{json, Value};
use std::sync::mpsc;
use std::time::Duration;

pub struct Job {
    pub action: String,
    pub args: Value,
    pub reply: mpsc::Sender<Result<Value, String>>,
}

/// Attach to the hub; commands arrive on the returned channel.
pub fn start(headless: bool) -> tokio::sync::mpsc::Receiver<Job> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Job>(16);
    transferd_control::attach("tui", json!({"app": "transferd-tui", "headless": headless, "version": env!("CARGO_PKG_VERSION")}), move |cmd| {
        let (rtx, rrx) = mpsc::channel();
        let timeout = cmd.args.get("timeout_s").and_then(Value::as_f64).unwrap_or(60.0).clamp(1.0, 600.0);
        tx.blocking_send(Job { action: cmd.action, args: cmd.args, reply: rtx }).map_err(|_| "the terminal UI is closing".to_string())?;
        rrx.recv_timeout(Duration::from_secs_f64(timeout)).map_err(|_| format!("the terminal UI did not answer in {timeout}s"))?
    });
    rx
}

pub const TABS: &[(&str, Tab)] = &[
    ("chats", Tab::Chats),
    ("contacts", Tab::Contacts),
    ("transfers", Tab::Transfers),
    ("settings", Tab::Settings),
    ("telemetry", Tab::Telemetry),
];

fn tab_name(t: Tab) -> &'static str {
    TABS.iter().find(|(_, x)| *x == t).map(|(n, _)| *n).unwrap_or("chats")
}

/// The screen as text: one line per row, trailing spaces trimmed.
pub fn buffer_text(buf: &ratatui::buffer::Buffer) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in area.top()..area.bottom() {
        let mut line = String::new();
        for x in area.left()..area.right() {
            line.push_str(buf.get(x, y).symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out.trim_end_matches('\n').to_string()
}

pub fn state(app: &App, size: (u16, u16), headless: bool) -> Value {
    let screen = match &app.screen {
        Screen::Main => json!("main"),
        Screen::Onboarding(step) => json!(format!("onboarding: {}", match step {
            crate::app::OnboardingStep::Welcome => "welcome",
            crate::app::OnboardingStep::EnterName => "enter name",
            crate::app::OnboardingStep::ShowPhrase { .. } => "show phrase",
            crate::app::OnboardingStep::ConfirmPhrase { .. } => "confirm phrase",
            crate::app::OnboardingStep::EnterPhrase => "enter phrase",
        })),
    };
    // Never the recovery phrase: modals that hold it are named, not shown.
    let modal = app.modal.as_ref().map(|m| match m {
        Modal::AddContact { name_input, field, .. } => json!({"kind": "add contact", "field": field, "name": name_input}),
        Modal::SendFile { path_input } => json!({"kind": "send file", "path": path_input}),
        Modal::ConfirmDelete { label, .. } => json!({"kind": "confirm delete", "label": label}),
        Modal::ShowQr { .. } => json!({"kind": "qr code"}),
        Modal::RevealPhrase { .. } => json!({"kind": "recovery phrase (hidden here)"}),
    });
    let focus = match app.chat_focus {
        ChatFocus::ContactList => "contact list",
        ChatFocus::Messages => "messages",
        ChatFocus::Input => "input",
    };
    json!({
        "screen": screen,
        "tab": tab_name(app.tab),
        "focus": focus,
        "open_chat": app.open_contact_id().map(|id| json!({"id": id, "name": app.open_contact_name()})),
        "selected_contact": app.selected_contact,
        "contacts": app.contacts.len(),
        "transfers": app.transfers.len(),
        "input": app.input,
        "modal": modal,
        "in_call": app.call_state.is_some(),
        "status": app.status,
        "identity": app.identity.as_ref().map(|i| json!({"display_name": i.display_name, "public_key": i.public_key})),
        "daemon_live": app.daemon_live,
        "size": [size.0, size.1],
        "headless": headless,
    })
}

fn key_code(name: &str) -> Result<KeyCode, String> {
    let lower = name.to_lowercase();
    Ok(match lower.as_str() {
        "enter" | "return" => KeyCode::Enter,
        "esc" | "escape" => KeyCode::Esc,
        "tab" => KeyCode::Tab,
        "backtab" => KeyCode::BackTab,
        "backspace" => KeyCode::Backspace,
        "delete" | "del" => KeyCode::Delete,
        "up" | "arrowup" => KeyCode::Up,
        "down" | "arrowdown" => KeyCode::Down,
        "left" | "arrowleft" => KeyCode::Left,
        "right" | "arrowright" => KeyCode::Right,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pageup" => KeyCode::PageUp,
        "pagedown" => KeyCode::PageDown,
        "space" => KeyCode::Char(' '),
        f if f.len() >= 2 && f.starts_with('f') && f[1..].parse::<u8>().is_ok() => KeyCode::F(f[1..].parse().unwrap_or(1)),
        _ => {
            let mut chars = name.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => KeyCode::Char(c),
                _ => return Err(format!("unknown key {name:?}")),
            }
        }
    })
}

pub fn key_events(keys: &str) -> Result<Vec<KeyEvent>, String> {
    let mut out = vec![];
    for (mods, key) in transferd_control::chords(keys) {
        let mut m = KeyModifiers::NONE;
        for x in &mods {
            match x.as_str() {
                "ctrl" | "control" => m |= KeyModifiers::CONTROL,
                "alt" | "option" => m |= KeyModifiers::ALT,
                "shift" => m |= KeyModifiers::SHIFT,
                other => return Err(format!("unknown modifier {other:?}")),
            }
        }
        out.push(KeyEvent { code: key_code(&key)?, modifiers: m, kind: KeyEventKind::Press, state: KeyEventState::NONE });
    }
    Ok(out)
}

pub fn text_events(text: &str) -> Vec<KeyEvent> {
    text.chars()
        .map(|c| KeyEvent {
            code: if c == '\n' { KeyCode::Enter } else { KeyCode::Char(c) },
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_parse() {
        let ev = key_events("ctrl+c F2 Enter a").unwrap_or_default();
        assert_eq!(ev.len(), 4);
        assert_eq!(ev[0].code, KeyCode::Char('c'));
        assert!(ev[0].modifiers.contains(KeyModifiers::CONTROL));
        assert_eq!(ev[1].code, KeyCode::F(2));
        assert_eq!(ev[2].code, KeyCode::Enter);
        assert!(key_events("NotAKey").is_err());
        assert_eq!(text_events("hi").len(), 2);
    }

    #[test]
    fn screen_text_is_trimmed_rows() {
        let mut buf = ratatui::buffer::Buffer::empty(ratatui::layout::Rect::new(0, 0, 5, 2));
        buf.set_string(0, 0, "ab", ratatui::style::Style::default());
        assert_eq!(buffer_text(&buf), "ab");
    }
}
