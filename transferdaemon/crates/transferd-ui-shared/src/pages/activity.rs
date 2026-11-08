//! Activity: what the daemon has logged, newest last. Errors, warnings, connections, API calls, lane and relay events,
//! and this window's own reports.
//!
//! It reads the daemon's activity log through the control hub and asks only for what is new, so it keeps up while the
//! window is open. With the daemon stopped it says so and keeps what it had.

use crate::design::{self, DesignTokens};
use crate::hub::{self, Calls};
use egui::{RichText, ScrollArea};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use transferd_control::terminal::{format_utc, CATEGORIES};

/// Events this window keeps. The daemon keeps its own copy, and a file.
const KEEP: usize = 5000;
const POLL_EVERY: Duration = Duration::from_millis(1500);
/// The first load takes the newest this many; later polls take only what is new.
const FIRST_LOAD: u64 = 1000;

/// The least serious level shown.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Min {
    /// Everything, including debug.
    All,
    Info,
    Warn,
    Error,
}

impl Min {
    fn rank(self) -> u8 {
        match self {
            Min::All => 0,
            Min::Info => 1,
            Min::Warn => 2,
            Min::Error => 3,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Min::All => "Everything",
            Min::Info => "Info and up",
            Min::Warn => "Warnings",
            Min::Error => "Errors",
        }
    }
}

fn level_rank(level: &str) -> u8 {
    match level {
        "error" => 3,
        "warn" => 2,
        "info" => 1,
        _ => 0,
    }
}

pub struct ActivityPage {
    events: VecDeque<Value>,
    last_seq: u64,
    counts: Value,
    calls: Calls<Result<Value, String>>,
    last_poll: Option<Instant>,
    /// Why the last poll failed (the daemon is not running, usually). `None` when the last poll worked.
    error: Option<String>,
    min: Min,
    category: Option<&'static str>,
    search: String,
    paused: bool,
    note: Option<String>,
}

impl Default for ActivityPage {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            last_seq: 0,
            counts: Value::Null,
            calls: Calls::new(),
            last_poll: None,
            error: None,
            min: Min::Info,
            category: None,
            search: String::new(),
            paused: false,
            note: None,
        }
    }
}

impl ActivityPage {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        let tokens = DesignTokens::current();
        self.pump(ui.ctx());

        ui.add_space(tokens.spacing.sm);
        ui.label(RichText::new("Activity").size(20.0).strong().color(tokens.palette.text_primary));
        ui.add_space(tokens.spacing.xs);

        design::card_frame(&tokens).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                for min in [Min::Info, Min::Warn, Min::Error, Min::All] {
                    if ui.selectable_label(self.min == min, min.label()).clicked() {
                        self.min = min;
                    }
                }
                ui.separator();
                egui::ComboBox::from_id_source("activity_category")
                    .selected_text(self.category.unwrap_or("All areas"))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.category, None, "All areas");
                        for category in CATEGORIES {
                            ui.selectable_value(&mut self.category, Some(*category), *category);
                        }
                    });
                ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Search").desired_width(160.0));
            });
            ui.add_space(tokens.spacing.xs);
            ui.horizontal_wrapped(|ui| {
                let pause_label = if self.paused { "Paused" } else { "Pause" };
                ui.toggle_value(&mut self.paused, pause_label);
                if ui.button("Clear view").clicked() {
                    self.calls.start("clear", || hub::call("activity.clear", json!({})));
                }
                let errors = self.count("error");
                let warnings = self.count("warn");
                ui.label(
                    RichText::new(format!("{errors} errors · {warnings} warnings · {} kept", self.events.len()))
                        .size(11.0)
                        .color(tokens.palette.text_secondary),
                );
            });
            if let Some(error) = &self.error {
                ui.label(RichText::new(format!("Not connected: {error}")).size(11.0).color(tokens.palette.warning));
            }
            if let Some(note) = &self.note {
                ui.label(RichText::new(note).size(11.0).color(tokens.palette.text_disabled));
            }
        });

        ui.add_space(tokens.spacing.xs);
        let shown: Vec<&Value> = self.events.iter().filter(|e| self.matches(e)).collect();
        if shown.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() / 4.0);
                let text = if self.events.is_empty() { "No activity yet" } else { "Nothing matches these filters" };
                ui.label(RichText::new(text).size(14.0).color(tokens.palette.text_secondary));
            });
            return;
        }
        ScrollArea::vertical().auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
            for event in shown {
                row(ui, &tokens, event);
            }
            ui.label(
                RichText::new("Times are UTC.").size(10.0).color(tokens.palette.text_disabled),
            );
        });
    }

    fn count(&self, level: &str) -> u64 {
        self.counts[level].as_u64().unwrap_or(0)
    }

    fn matches(&self, event: &Value) -> bool {
        if level_rank(event["level"].as_str().unwrap_or("")) < self.min.rank() {
            return false;
        }
        if let Some(category) = self.category {
            if event["category"].as_str() != Some(category) {
                return false;
            }
        }
        let needle = self.search.trim().to_lowercase();
        needle.is_empty()
            || ["message", "category", "source"]
                .iter()
                .any(|k| event[*k].as_str().unwrap_or("").to_lowercase().contains(&needle))
    }

    /// Take in finished calls, and ask the daemon for what is new.
    fn pump(&mut self, ctx: &egui::Context) {
        for (label, result) in self.calls.drain() {
            match (label.as_str(), result) {
                ("poll", Ok(reply)) => self.absorb(&reply),
                ("poll", Err(error)) => self.error = Some(error),
                ("clear", Ok(_)) => {
                    self.events.clear();
                    self.note = Some("Cleared the view. The daemon's log file keeps its history.".to_string());
                }
                ("clear", Err(error)) => self.note = Some(format!("Could not clear: {error}")),
                _ => {}
            }
        }
        let due = self.last_poll.map(|t| t.elapsed() >= POLL_EVERY).unwrap_or(true);
        if due && !self.paused && !self.calls.busy("poll") {
            self.last_poll = Some(Instant::now());
            let since = self.last_seq;
            let limit = if since == 0 { FIRST_LOAD } else { 1000 };
            self.calls.start("poll", move || hub::call("activity.list", json!({"since_seq": since, "limit": limit})));
        }
        ctx.request_repaint_after(POLL_EVERY);
    }

    fn absorb(&mut self, reply: &Value) {
        self.error = None;
        // A daemon whose log file was removed numbers from one again: start over rather than wait for old numbers.
        if reply["last_seq"].as_u64().unwrap_or(0) < self.last_seq {
            self.events.clear();
            self.last_seq = 0;
        }
        if let Some(list) = reply["events"].as_array() {
            for event in list {
                self.last_seq = self.last_seq.max(event["seq"].as_u64().unwrap_or(0));
                self.events.push_back(event.clone());
            }
        }
        while self.events.len() > KEEP {
            self.events.pop_front();
        }
        self.counts = reply["counts"].clone();
    }
}

/// One event: time, level, area and source on a line, the message, then any details.
fn row(ui: &mut egui::Ui, tokens: &DesignTokens, event: &Value) {
    let level = event["level"].as_str().unwrap_or("info");
    let tone = match level {
        "error" => tokens.palette.error,
        "warn" => tokens.palette.warning,
        "debug" => tokens.palette.text_disabled,
        _ => tokens.palette.info,
    };
    let time = format_utc(event["ts_ms"].as_u64().unwrap_or(0));
    let clock = time.split(' ').nth(1).unwrap_or("").to_string();
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(clock).monospace().size(11.0).color(tokens.palette.text_disabled));
        ui.label(RichText::new(level.to_uppercase()).monospace().size(11.0).strong().color(tone));
        ui.label(RichText::new(event["category"].as_str().unwrap_or("")).size(11.0).color(tokens.palette.text_secondary));
        ui.label(RichText::new(event["source"].as_str().unwrap_or("")).size(11.0).color(tokens.palette.text_disabled));
    });
    ui.label(RichText::new(event["message"].as_str().unwrap_or("")).size(13.0).color(tokens.palette.text_primary));
    if let Some(fields) = event["fields"].as_object().filter(|f| !f.is_empty()) {
        let details: Vec<String> = fields
            .iter()
            .map(|(k, v)| format!("{k}={}", v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
            .collect();
        ui.label(RichText::new(details.join("   ")).monospace().size(11.0).color(tokens.palette.text_disabled));
    }
    ui.add_space(tokens.spacing.xs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_level_filter_keeps_that_level_and_worse() {
        assert!(level_rank("error") > level_rank("warn"));
        assert!(level_rank("warn") > level_rank("info"));
        assert!(level_rank("info") > level_rank("debug"));
        assert!(level_rank("warn") >= Min::Warn.rank());
        assert!(level_rank("info") < Min::Warn.rank());
    }

    #[test]
    fn a_search_matches_message_category_or_source() {
        let mut page = ActivityPage::default();
        let event = json!({"level": "warn", "category": "lanes", "source": "transferd::transport",
                           "message": "Lane stalled"});
        page.search = "STALLED".into();
        assert!(page.matches(&event));
        page.search = "transport".into();
        assert!(page.matches(&event));
        page.search = "relay".into();
        assert!(!page.matches(&event));
        page.search = String::new();
        page.category = Some("relay");
        assert!(!page.matches(&event));
    }

    #[test]
    fn a_daemon_that_started_its_numbering_again_is_read_from_the_start() {
        let mut page = ActivityPage::default();
        page.absorb(&json!({"events": [{"seq": 40, "level": "info", "message": "a"}], "last_seq": 40, "counts": {}}));
        assert_eq!(page.last_seq, 40);
        page.absorb(&json!({"events": [{"seq": 1, "level": "info", "message": "b"}], "last_seq": 1, "counts": {}}));
        assert_eq!(page.events.len(), 1, "the old events are dropped");
        assert_eq!(page.last_seq, 1);
    }
}
