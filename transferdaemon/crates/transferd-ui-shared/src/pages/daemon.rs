//! The daemon, managed from the window: is it running, start it, stop it, restart it, and edit its settings file
//! (`config.json`, which the daemon reloads when it changes).
//!
//! Starting, stopping and saving run on background threads. A failure is shown here and written to the activity log
//! when the daemon can take it.

use crate::design::{self, DesignTokens};
use crate::hub::{self, Calls};
use egui::RichText;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use transferd_activity::Level;
use transferd_control::daemon_ctl;

const POLL_EVERY: Duration = Duration::from_secs(3);

#[derive(Default)]
pub struct DaemonPanel {
    calls: Calls<Result<Value, String>>,
    /// `daemon.status` while the daemon answers; `None` when it does not.
    status: Option<Value>,
    last_poll: Option<Instant>,
    message: Option<(bool, String)>,
    config_open: bool,
    config_text: String,
    config_message: Option<(bool, String)>,
}

impl DaemonPanel {
    pub fn show(&mut self, ui: &mut egui::Ui, tokens: &DesignTokens) {
        self.pump(ui.ctx());
        let running = self.status.is_some();
        let busy = self.calls.pending();

        design::card_frame(tokens).show(ui, |ui| {
            ui.label(RichText::new("Daemon").size(14.0).strong().color(tokens.palette.text_primary));
            ui.add_space(tokens.spacing.xs);
            let (dot, line, tone) = match &self.status {
                Some(s) => (
                    "●",
                    format!(
                        "Running · version {} · pid {} · up {}",
                        s["version"].as_str().unwrap_or("?"),
                        s["pid"],
                        uptime(s["uptime_s"].as_u64().unwrap_or(0))
                    ),
                    tokens.palette.success,
                ),
                None => ("○", "Not running".to_string(), tokens.palette.text_secondary),
            };
            ui.label(RichText::new(format!("{dot} {line}")).size(13.0).color(tone));
            ui.add_space(tokens.spacing.xs);

            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(!running && !busy, egui::Button::new("Start")).clicked() {
                    self.act("daemon-start", || daemon_ctl::start().map(|pid| json!({"pid": pid})));
                }
                if ui.add_enabled(running && !busy, egui::Button::new("Restart")).clicked() {
                    self.act("daemon-restart", || daemon_ctl::restart().map(|pid| json!({"pid": pid})));
                }
                if ui.add_enabled(running && !busy, egui::Button::new("Stop")).clicked() {
                    self.act("daemon-stop", || daemon_ctl::stop().map(|_| Value::Null).map_err(|e| e.to_string()));
                }
                if busy {
                    ui.spinner();
                }
            });
            if let Some((failed, text)) = &self.message {
                let color = if *failed { tokens.palette.error } else { tokens.palette.success };
                ui.label(RichText::new(text).size(12.0).color(color));
            }

            ui.add_space(tokens.spacing.sm);
            let label = if self.config_open { "Hide settings file" } else { "Edit settings file (config.json)" };
            if ui.button(label).clicked() {
                self.config_open = !self.config_open;
                if self.config_open {
                    self.calls.start("config-load", || daemon_ctl::read_config().map(Value::String));
                }
            }
            if self.config_open {
                ui.label(
                    RichText::new("The daemon reloads this file when it changes, so most settings apply without a restart.")
                        .size(11.0)
                        .color(tokens.palette.text_disabled),
                );
                ui.add(
                    egui::TextEdit::multiline(&mut self.config_text)
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(10)
                        .desired_width(f32::INFINITY),
                );
                ui.horizontal(|ui| {
                    if ui.add_enabled(!self.calls.busy("config-save"), egui::Button::new("Save settings")).clicked() {
                        let text = self.config_text.clone();
                        self.calls.start("config-save", move || {
                            daemon_ctl::write_config(&text).map(|_| Value::Null)
                        });
                    }
                    if ui.button("Reload from disk").clicked() {
                        self.calls.start("config-load", || daemon_ctl::read_config().map(Value::String));
                    }
                });
                if let Some((failed, text)) = &self.config_message {
                    let color = if *failed { tokens.palette.error } else { tokens.palette.success };
                    ui.label(RichText::new(text).size(12.0).color(color));
                }
            }
        });
    }

    /// Start a daemon action on a thread. Its outcome is written by `pump`.
    fn act(&mut self, label: &'static str, work: impl FnOnce() -> Result<Value, String> + Send + 'static) {
        self.message = None;
        self.calls.start(label, work);
    }

    fn pump(&mut self, ctx: &egui::Context) {
        for (label, result) in self.calls.drain() {
            match label.as_str() {
                "status" => match result {
                    Ok(status) => self.status = Some(status),
                    Err(_) => self.status = None,
                },
                "daemon-start" | "daemon-restart" | "daemon-stop" => {
                    let (done, failed) = match label.as_str() {
                        "daemon-start" => ("Started the daemon.", "Could not start the daemon"),
                        "daemon-restart" => ("Restarted the daemon.", "Could not restart the daemon"),
                        _ => ("Stopped the daemon.", "Could not stop the daemon"),
                    };
                    match result {
                        Ok(_) => self.message = Some((false, done.to_string())),
                        Err(error) => {
                            hub::report(Level::Error, "gui", format!("{failed}: {error}"));
                            self.message = Some((true, format!("{failed}: {error}")));
                        }
                    }
                    // Look at the daemon straight away, not at the next poll.
                    self.last_poll = None;
                }
                "config-load" => match result {
                    Ok(Value::String(text)) => self.config_text = text,
                    Ok(_) => {}
                    Err(error) => self.config_message = Some((true, error)),
                },
                "config-save" => match result {
                    Ok(_) => {
                        self.config_message = Some((false, "Saved. The daemon reloads it now.".to_string()));
                        // Show what was written (it is pretty-printed on the way to disk).
                        self.calls.start("config-load", || daemon_ctl::read_config().map(Value::String));
                    }
                    Err(error) => self.config_message = Some((true, error)),
                },
                _ => {}
            }
        }
        let due = self.last_poll.map(|t| t.elapsed() >= POLL_EVERY).unwrap_or(true);
        if due && !self.calls.busy("status") {
            self.last_poll = Some(Instant::now());
            self.calls.start("status", || daemon_ctl::status().map_err(|e| e.to_string()));
        }
        ctx.request_repaint_after(POLL_EVERY);
    }
}

fn uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m {}s", secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_reads_in_the_largest_useful_units() {
        assert_eq!(uptime(59), "0m 59s");
        assert_eq!(uptime(3_720), "1h 2m");
        assert_eq!(uptime(90_000), "1d 1h");
    }
}
