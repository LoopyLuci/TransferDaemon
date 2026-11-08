//! Terminal: type `/help` and drive the daemon with slash commands. The commands are the same ones the CLI and the
//! tests use (see `transferd_control::terminal`); each runs on its own thread, so a slow command never holds up typing.

use crate::design::{self, DesignTokens};
use crate::hub::Calls;
use egui::{RichText, ScrollArea};
use transferd_control::terminal::{self, Command, COMMANDS};

/// How many lines the scrollback keeps.
const KEEP_LINES: usize = 4000;
/// How many earlier inputs the up and down arrows recall.
const KEEP_HISTORY: usize = 200;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Input,
    Output,
    Error,
}

#[derive(Default)]
pub struct TerminalPage {
    lines: Vec<(Kind, String)>,
    input: String,
    history: Vec<String>,
    /// Where the up and down arrows are in `history`, when they are in use.
    history_at: Option<usize>,
    calls: Calls<Vec<String>>,
    next_id: u64,
    welcomed: bool,
    /// Set after a line is sent, so the input keeps the keyboard focus.
    refocus: bool,
}

impl TerminalPage {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        let tokens = DesignTokens::current();
        if !self.welcomed {
            self.welcomed = true;
            self.push(Kind::Output, "TransferDaemon terminal. Type /help for the commands, /status to see the daemon.".to_string());
        }
        self.pump(ui.ctx());

        ui.add_space(tokens.spacing.sm);
        ui.label(RichText::new("Terminal").size(20.0).strong().color(tokens.palette.text_primary));
        ui.add_space(tokens.spacing.xs);

        let input_height = 64.0;
        let scroll_height = (ui.available_height() - input_height).max(80.0);
        design::card_frame(&tokens).show(ui, |ui| {
            ScrollArea::vertical()
                .max_height(scroll_height)
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for (kind, text) in &self.lines {
                        let color = match kind {
                            Kind::Input => tokens.palette.accent,
                            Kind::Output => tokens.palette.text_primary,
                            Kind::Error => tokens.palette.error,
                        };
                        ui.label(RichText::new(text).monospace().size(12.0).color(color));
                    }
                });
        });

        ui.add_space(tokens.spacing.xs);
        let mut submit = false;
        let response = ui.add(
            egui::TextEdit::singleline(&mut self.input)
                .font(egui::TextStyle::Monospace)
                .hint_text("/help")
                .desired_width(f32::INFINITY)
                .lock_focus(true),
        );
        if self.refocus {
            response.request_focus();
            self.refocus = false;
        }
        if response.has_focus() {
            ui.input(|i| {
                if i.key_pressed(egui::Key::ArrowUp) {
                    self.recall(-1);
                }
                if i.key_pressed(egui::Key::ArrowDown) {
                    self.recall(1);
                }
            });
        }
        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            submit = true;
        }
        // Suggestions for the command being typed (the first word after the slash).
        if let Some(prefix) = self.input.strip_prefix('/') {
            let word = prefix.split_whitespace().next().unwrap_or("");
            let names: Vec<String> = COMMANDS
                .iter()
                .filter(|c| c.name.starts_with(&word.to_lowercase()))
                .map(|c| format!("/{}", c.name))
                .collect();
            if !names.is_empty() && !prefix.contains(' ') {
                ui.label(RichText::new(names.join("  ")).size(11.0).color(tokens.palette.text_disabled));
            }
        }
        if submit {
            self.submit();
            self.refocus = true;
        }
    }

    fn push(&mut self, kind: Kind, text: String) {
        self.lines.push((kind, text));
        if self.lines.len() > KEEP_LINES {
            let extra = self.lines.len() - KEEP_LINES;
            self.lines.drain(..extra);
        }
    }

    /// Send what is in the input line.
    fn submit(&mut self) {
        let line = std::mem::take(&mut self.input);
        self.history_at = None;
        if line.trim().is_empty() {
            return;
        }
        self.push(Kind::Input, format!("› {line}"));
        self.history.push(line.clone());
        if self.history.len() > KEEP_HISTORY {
            self.history.remove(0);
        }
        match terminal::parse(&line) {
            Err(error) => self.push(Kind::Error, error),
            Ok(Command::Clear) => self.lines.clear(),
            Ok(Command::Empty) => {}
            Ok(command) => {
                self.next_id += 1;
                let label = format!("cmd{}", self.next_id);
                let started = self.calls.start(&label, move || terminal::run(command));
                if !started {
                    self.push(Kind::Error, "that command is still running".to_string());
                }
            }
        }
    }

    /// Move through the earlier inputs: `step` -1 goes back, 1 forward (to an empty line at the end).
    fn recall(&mut self, step: i32) {
        if self.history.is_empty() {
            return;
        }
        let last = self.history.len() as i32;
        let current = self.history_at.map(|i| i as i32).unwrap_or(last);
        let next = (current + step).clamp(0, last);
        if next == last {
            self.history_at = None;
            self.input.clear();
        } else {
            self.history_at = Some(next as usize);
            self.input = self.history[next as usize].clone();
        }
    }

    fn pump(&mut self, ctx: &egui::Context) {
        for (_label, lines) in self.calls.drain() {
            for line in lines {
                let kind = if line.starts_with("no ") || line.starts_with("could not") || line.starts_with("error:") {
                    Kind::Error
                } else {
                    Kind::Output
                };
                self.push(kind, line);
            }
        }
        if self.calls.pending() {
            // Something is still running: look again soon, so its output appears without a mouse move.
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_walks_back_and_returns_to_an_empty_line() {
        let mut page = TerminalPage::default();
        page.history = vec!["/status".into(), "/logs".into()];
        page.recall(-1);
        assert_eq!(page.input, "/logs");
        page.recall(-1);
        assert_eq!(page.input, "/status");
        page.recall(-1);
        assert_eq!(page.input, "/status", "stops at the oldest");
        page.recall(1);
        page.recall(1);
        assert_eq!(page.input, "", "forward past the newest is an empty line");
        assert_eq!(page.history_at, None);
    }

    #[test]
    fn the_scrollback_is_bounded() {
        let mut page = TerminalPage::default();
        for i in 0..KEEP_LINES + 10 {
            page.push(Kind::Output, format!("line {i}"));
        }
        assert_eq!(page.lines.len(), KEEP_LINES);
        assert_eq!(page.lines[0].1, "line 10");
    }
}
