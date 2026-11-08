//! Updates and the Android app, from Settings: the installed version and the latest release side by side, the update
//! policy, and the actions that go with them. Plus [`UpdateWatch`], which turns a new release, a finished download or
//! a finished install into a prompt, whichever page is open.
//!
//! Nothing here installs anything without the user's say, unless the user chose the `install` policy. The daemon does
//! the work and the activity log records it; this panel shows the state.

use crate::design::{self, DesignTokens};
use crate::hub::{self, Calls};
use egui::RichText;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};
use transferd_control::daemon_ctl;

/// The watch looks at the daemon's state (no network) this often.
const WATCH_EVERY: Duration = Duration::from_secs(60);
const POLL_EVERY: Duration = Duration::from_secs(20);

/// The policies the user can pick, with what each one does.
const POLICIES: [(&str, &str, &str); 3] = [
    ("manual", "Manual", "Only when you ask. TransferDaemon never contacts GitHub by itself."),
    (
        "download",
        "Download automatically",
        "Checks every few hours and downloads new releases in the background. Each one is checked against GitHub's SHA-256 before it is kept. You install it when you choose.",
    ),
    (
        "install",
        "Download and install automatically",
        "Also installs them in the background. The new version runs after the daemon restarts, and you are told when that is needed.",
    ),
];

#[derive(Default)]
pub struct UpdatesPanel {
    calls: Calls<Result<Value, String>>,
    /// `updates.get_update_state` (no network): the versions, the policy, anything waiting.
    state: Option<Value>,
    state_error: Option<String>,
    last_poll: Option<Instant>,
    message: Option<(bool, String)>,
    apk: Option<Value>,
    apk_message: Option<(bool, String)>,
}

impl UpdatesPanel {
    pub fn show(&mut self, ui: &mut egui::Ui, tokens: &DesignTokens) {
        self.pump(ui.ctx());
        let busy = self.calls.pending();
        let state = self.state.clone().unwrap_or(Value::Null);
        // The daemon reports the installed version. Without it there is nothing honest to show.
        let installed = match text(&state, "current_version") {
            v if v.is_empty() => "—".to_string(),
            v => v,
        };
        let latest = text(&state, "latest_version");
        let policy = text(&state, "policy");

        design::card_frame(tokens).show(ui, |ui| {
            ui.label(RichText::new("Updates").size(14.0).strong().color(tokens.palette.text_primary));
            ui.add_space(tokens.spacing.xs);

            // The two versions, next to each other.
            ui.columns(2, |cols| {
                cols[0].label(RichText::new("Installed").size(11.0).color(tokens.palette.text_secondary));
                cols[0].label(RichText::new(&installed).size(20.0).strong().color(tokens.palette.text_primary));
                cols[1].label(RichText::new("Latest release").size(11.0).color(tokens.palette.text_secondary));
                let latest_text = if latest.is_empty() { "not checked yet".to_string() } else { latest.clone() };
                cols[1].label(RichText::new(latest_text).size(20.0).strong().color(tokens.palette.text_primary));
                let published = text(&state, "published_at");
                if !published.is_empty() {
                    cols[1].label(
                        RichText::new(format!("published {}", published.split('T').next().unwrap_or(&published)))
                            .size(11.0)
                            .color(tokens.palette.text_disabled),
                    );
                }
            });
            ui.add_space(tokens.spacing.xs);

            let (status, tone) = status_line(&state, tokens);
            ui.label(RichText::new(status).size(13.0).color(tone));
            if let Some(error) = &self.state_error {
                ui.label(RichText::new(format!("TransferDaemon is not reachable: {error}")).size(11.0).color(tokens.palette.warning));
            }
            ui.add_space(tokens.spacing.sm);

            // Actions.
            let update_waiting = text(&state, "staged_version");
            let has_update = state["has_update"].as_bool().unwrap_or(false);
            let restart_needed = state["restart_required"].as_bool().unwrap_or(false);
            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(!busy, egui::Button::new("Check now")).clicked() {
                    self.calls.start("check", || hub::call("updates.check_for_updates", json!({})));
                }
                if has_update && update_waiting.is_empty() && ui.add_enabled(!busy, egui::Button::new("Download")).clicked() {
                    self.calls.start("download", || hub::call("updates.download_update", json!({})));
                }
                if (has_update || !update_waiting.is_empty()) && !restart_needed
                    && ui.add_enabled(!busy, egui::Button::new("Install update")).clicked()
                {
                    self.calls.start("install", || hub::call("updates.apply_update", json!({})));
                }
                if restart_needed && ui.add_enabled(!busy, egui::Button::new("Restart daemon")).clicked() {
                    self.calls.start("restart", || daemon_ctl::restart().map(|pid| json!({"pid": pid})));
                }
                if busy {
                    ui.spinner();
                }
            });
            if let Some((failed, text)) = &self.message {
                let color = if *failed { tokens.palette.error } else { tokens.palette.success };
                ui.label(RichText::new(text).size(12.0).color(color));
            }

            // Policy.
            ui.add_space(tokens.spacing.md);
            ui.label(RichText::new("When TransferDaemon looks for updates").size(12.0).strong().color(tokens.palette.text_primary));
            ui.horizontal_wrapped(|ui| {
                for (key, label, _) in POLICIES {
                    if ui.selectable_label(policy == key, label).clicked() && policy != key {
                        self.calls.start("policy", move || {
                            hub::call("updates.set_update_policy", json!({"policy": key}))
                        });
                    }
                }
            });
            if let Some((_, _, description)) = POLICIES.iter().find(|(key, _, _)| *key == policy) {
                ui.label(RichText::new(*description).size(11.0).color(tokens.palette.text_disabled));
            }
        });

        ui.add_space(tokens.spacing.sm);
        self.show_apk(ui, tokens, busy);
    }

    fn show_apk(&mut self, ui: &mut egui::Ui, tokens: &DesignTokens, busy: bool) {
        design::card_frame(tokens).show(ui, |ui| {
            ui.label(RichText::new("Android app").size(14.0).strong().color(tokens.palette.text_primary));
            ui.add_space(tokens.spacing.xs);
            let apk = self.apk.clone();
            match &apk {
                Some(info) => {
                    let size_mb = info["size"].as_u64().unwrap_or(0) as f64 / 1_048_576.0;
                    ui.label(
                        RichText::new(format!(
                            "Version {} · {} · {:.1} MB",
                            text(info, "version"),
                            text(info, "asset_name"),
                            size_mb
                        ))
                        .size(12.0)
                        .color(tokens.palette.text_secondary),
                    );
                }
                None => {
                    ui.label(
                        RichText::new("Save the Android app to this device, checked against GitHub's SHA-256.")
                            .size(12.0)
                            .color(tokens.palette.text_disabled),
                    );
                }
            }
            ui.add_space(tokens.spacing.xs);
            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(!busy, egui::Button::new("Save to Downloads")).clicked() {
                    self.calls.start("apk-save", || hub::call("updates.save_apk", json!({})));
                }
                if let Some(info) = &apk {
                    let link = text(info, "url");
                    if !link.is_empty() && ui.button("Copy download link").clicked() {
                        let copied = link.clone();
                        ui.ctx().output_mut(|o| o.copied_text = copied);
                        self.apk_message = Some((false, "Copied the download link.".to_string()));
                    }
                    let saved = text(info, "saved_path");
                    if !saved.is_empty() && ui.button("Show in folder").clicked() {
                        if let Err(e) = crate::reveal::show_in_folder(Path::new(&saved)) {
                            self.apk_message = Some((true, format!("Could not open the folder: {e}")));
                        }
                    }
                }
            });
            if let Some((failed, text)) = &self.apk_message {
                let color = if *failed { tokens.palette.error } else { tokens.palette.success };
                ui.label(RichText::new(text).size(12.0).color(color));
            }
        });
    }

    fn pump(&mut self, ctx: &egui::Context) {
        for (label, result) in self.calls.drain() {
            match (label.as_str(), result) {
                ("poll", Ok(reply)) => {
                    self.state = Some(reply);
                    self.state_error = None;
                }
                ("poll", Err(error)) => self.state_error = Some(error),
                ("check", Ok(reply)) | ("download", Ok(reply)) | ("policy", Ok(reply)) => {
                    self.state = Some(reply.clone());
                    self.message = Some(outcome_of(&label, &reply));
                }
                ("install", Ok(_)) => {
                    self.last_poll = None;
                    self.message = Some((false, "Installed. Restart the daemon to run the new version.".to_string()));
                }
                ("restart", Ok(_)) => {
                    self.last_poll = None;
                    self.message = Some((false, "Restarted the daemon.".to_string()));
                }
                ("apk-save", Ok(info)) => {
                    self.apk_message = Some((false, format!("Saved to {}", text(&info, "saved_path"))));
                    self.apk = Some(info);
                }
                ("check", Err(error)) | ("download", Err(error)) | ("policy", Err(error)) | ("install", Err(error)) | ("restart", Err(error)) => {
                    hub::report(transferd_activity::Level::Error, "updates", format!("{label} failed: {error}"));
                    self.message = Some((true, error));
                }
                ("apk-save", Err(error)) => {
                    hub::report(transferd_activity::Level::Error, "updates", format!("saving the Android app failed: {error}"));
                    self.apk_message = Some((true, error));
                }
                _ => {}
            }
        }
        let due = self.last_poll.map(|t| t.elapsed() >= POLL_EVERY).unwrap_or(true);
        if due && !self.calls.busy("poll") {
            self.last_poll = Some(Instant::now());
            self.calls.start("poll", || hub::call("updates.get_update_state", json!({})));
        }
        ctx.request_repaint_after(POLL_EVERY);
    }
}

/// The one line that says where things stand.
fn status_line(state: &Value, tokens: &DesignTokens) -> (String, egui::Color32) {
    let latest = text(state, "latest_version");
    let error = text(state, "error");
    if !error.is_empty() {
        return (format!("The last check did not work: {error}"), tokens.palette.error);
    }
    if state["restart_required"].as_bool().unwrap_or(false) {
        return (format!("{} is installed. Restart the daemon to run it.", latest), tokens.palette.warning);
    }
    let staged = text(state, "staged_version");
    if !staged.is_empty() {
        return (format!("{staged} is downloaded and checked. Install it when you are ready."), tokens.palette.accent);
    }
    if state["has_update"].as_bool().unwrap_or(false) {
        return (format!("Version {latest} is available."), tokens.palette.accent);
    }
    if state["checked_at"].as_u64().unwrap_or(0) == 0 {
        return ("Not checked yet. Press Check now to look for a newer release.".to_string(), tokens.palette.text_secondary);
    }
    ("You have the latest release.".to_string(), tokens.palette.success)
}

fn outcome_of(label: &str, reply: &Value) -> (bool, String) {
    let error = text(reply, "error");
    if !error.is_empty() {
        return (true, error);
    }
    let message = match label {
        "download" => format!("Downloaded and checked {}. Install it when you are ready.", text(reply, "staged_version")),
        "policy" => "Saved the update policy.".to_string(),
        _ => {
            if reply["has_update"].as_bool().unwrap_or(false) {
                format!("Version {} is available.", text(reply, "latest_version"))
            } else {
                "You have the latest release.".to_string()
            }
        }
    };
    (false, message)
}

/// Watches the daemon's update state for changes, and says what is new. Keep one for the whole window; call
/// [`UpdateWatch::poll`] each frame and show what it returns.
#[derive(Default)]
pub struct UpdateWatch {
    calls: Calls<Result<Value, String>>,
    seen: Option<(String, String, bool)>,
    last_poll: Option<Instant>,
}

impl UpdateWatch {
    /// Prompts to show now, as `(title, detail)`. Each change is reported once.
    pub fn poll(&mut self, ctx: &egui::Context) -> Vec<(String, String)> {
        let mut prompts = Vec::new();
        for (label, result) in self.calls.drain() {
            if label == "watch" {
                if let Ok(reply) = result {
                    prompts = self.changes(&reply);
                }
            }
        }
        let due = self.last_poll.map(|t| t.elapsed() >= WATCH_EVERY).unwrap_or(true);
        if due && !self.calls.busy("watch") {
            self.last_poll = Some(Instant::now());
            self.calls.start("watch", || hub::call("updates.get_update_state", json!({})));
        }
        ctx.request_repaint_after(WATCH_EVERY);
        prompts
    }

    fn changes(&mut self, reply: &Value) -> Vec<(String, String)> {
        let available = if reply["has_update"].as_bool().unwrap_or(false) { text(reply, "new_version") } else { String::new() };
        let staged = text(reply, "staged_version");
        let restart = reply["restart_required"].as_bool().unwrap_or(false);
        let previous = self.seen.replace((available.clone(), staged.clone(), restart));
        let (was_available, was_staged, was_restart) = previous.unwrap_or_default();
        let mut prompts = Vec::new();
        if !available.is_empty() && available != was_available {
            prompts.push((
                format!("TransferDaemon {available} is available"),
                "Open Settings to download it. Nothing is installed without you.".to_string(),
            ));
        }
        if !staged.is_empty() && staged != was_staged {
            prompts.push((
                format!("Update {staged} is ready to install"),
                "It was downloaded and checked against GitHub's SHA-256. Install it from Settings.".to_string(),
            ));
        }
        if restart && !was_restart {
            prompts.push((
                "Restart the daemon to finish the update".to_string(),
                "The new version is installed. Restart the daemon to run it.".to_string(),
            ));
        }
        prompts
    }
}

fn text(v: &Value, key: &str) -> String {
    v[key].as_str().map(str::to_string).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_release_is_announced_once() {
        let mut watch = UpdateWatch::default();
        let available = json!({"has_update": true, "new_version": "2.5.0", "staged_version": "", "restart_required": false});
        assert_eq!(watch.changes(&available).len(), 1);
        assert!(watch.changes(&available).is_empty(), "the same release is not announced again");
        let staged = json!({"has_update": true, "new_version": "2.5.0", "staged_version": "2.5.0", "restart_required": false});
        assert_eq!(watch.changes(&staged).len(), 1, "a finished download is announced");
        let installed = json!({"has_update": false, "latest_version": "2.5.0", "staged_version": "2.5.0", "restart_required": true});
        assert_eq!(watch.changes(&installed).len(), 1, "an install that needs a restart is announced");
    }

    #[test]
    fn the_policy_list_is_the_three_the_daemon_accepts() {
        let keys: Vec<&str> = POLICIES.iter().map(|(k, _, _)| *k).collect();
        assert_eq!(keys, vec!["manual", "download", "install"]);
    }
}
