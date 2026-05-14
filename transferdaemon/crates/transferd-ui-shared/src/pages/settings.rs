//! Settings page — identity info, QR code, theme, about.

use crate::app::AppState;
use crate::widgets::qr_widget::QrWidget;
use egui::{Color32, Context, RichText, Ui};

#[derive(Default)]
pub struct SettingsPage {
    qr: QrWidget,
    show_qr: bool,
    show_full_key: bool,
    show_phrase: bool,
    phrase_confirmed: bool,
    relay_enabled: bool,
    relay_status: String,
    relay_bandwidth_input: String,
    relay_settings_loaded: bool,
}

impl SettingsPage {
    pub fn show(&mut self, ui: &mut Ui, ctx: &Context, state: &AppState) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(16.0);
            section_header(ui, "Identity");

            if let Some(id) = &state.identity {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Display name:").color(Color32::from_gray(160)));
                    ui.label(RichText::new(&id.display_name).strong().color(Color32::WHITE));
                });
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    ui.label(RichText::new("Public key:").color(Color32::from_gray(160)));
                    let display = if self.show_full_key { id.public_key.clone() } else { truncate_key(&id.public_key) };
                    ui.label(RichText::new(&display).monospace().color(Color32::from_gray(200)));
                    if ui.small_button(if self.show_full_key { "Collapse" } else { "Expand" }).clicked() {
                        self.show_full_key = !self.show_full_key;
                    }
                    if ui.small_button("Copy").clicked() {
                        ui.output_mut(|o| o.copied_text = id.public_key.clone());
                    }
                });

                if self.show_full_key {
                    ui.add_space(4.0);
                    ui.add(egui::TextEdit::singleline(&mut id.public_key.clone())
                        .font(egui::FontId::monospace(11.0))
                        .desired_width(ui.available_width())
                        .interactive(false));
                    ui.label(RichText::new(format!("{} hex chars (Ed25519 public key)", id.public_key.len()))
                        .size(11.0).color(Color32::from_gray(100)));
                }

                ui.add_space(8.0);
                if ui.button(if self.show_qr { "Hide QR code" } else { "Show QR code" }).clicked() {
                    self.show_qr = !self.show_qr;
                }
                if self.show_qr {
                    ui.add_space(8.0);
                    ui.centered_and_justified(|ui| {
                        self.qr.show(ui, ctx, &id.public_key, 200.0);
                    });
                    ui.add_space(4.0);
                    ui.label(RichText::new("Share this QR code so others can add you as a contact.")
                        .size(12.0).color(Color32::from_gray(150)));
                }

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);
                section_header(ui, "Recovery Phrase");

                if state.recovery_phrase.is_some() {
                    if !self.show_phrase {
                        ui.label(RichText::new("Your 12-word recovery phrase is available this session.")
                            .color(Color32::from_gray(160)).size(13.0));
                        ui.add_space(6.0);
                        if ui.add(egui::Button::new(
                            RichText::new("⚠ Reveal Recovery Phrase").color(Color32::from_rgb(255, 214, 10))
                        ).fill(Color32::from_rgb(44, 44, 46))).clicked() {
                            self.phrase_confirmed = false;
                            self.show_phrase = true;
                        }
                    } else {
                        ui.label(RichText::new("Write these words down. Anyone with this phrase can access your identity.")
                            .color(Color32::from_rgb(255, 69, 58)).size(13.0));
                        ui.add_space(8.0);
                        if let Some(phrase) = &state.recovery_phrase {
                            let words: Vec<&str> = phrase.split_whitespace().collect();
                            egui::Grid::new("settings_phrase_grid").num_columns(3).spacing([16.0, 6.0]).show(ui, |ui| {
                                for (i, word) in words.iter().enumerate() {
                                    ui.label(RichText::new(format!("{}. {}", i + 1, word))
                                        .size(14.0).monospace().color(Color32::WHITE));
                                    if (i + 1) % 3 == 0 { ui.end_row(); }
                                }
                            });
                            ui.add_space(8.0);
                            if ui.small_button("Copy phrase").clicked() {
                                ui.output_mut(|o| o.copied_text = phrase.clone());
                            }
                        }
                        ui.add_space(8.0);
                        if ui.small_button("Hide phrase").clicked() { self.show_phrase = false; }
                    }
                } else {
                    ui.label(RichText::new(
                        "Recovery phrase is only available in the session when it was created.\n\
                         Restart the app and create a new identity to generate a new phrase.",
                    ).size(13.0).color(Color32::from_gray(120)));
                }
            } else {
                ui.label(RichText::new("No identity set up.").color(Color32::from_gray(140)));
            }

            ui.add_space(24.0);
            ui.separator();
            section_header(ui, "Network");
            ui.horizontal(|ui| {
                ui.label(RichText::new("Relay lanes:").color(Color32::from_gray(160)));
                ui.label(RichText::new("1 active").color(Color32::from_rgb(48, 209, 88)));
            });
            ui.horizontal(|ui| {
                ui.label(RichText::new("Daemon:").color(Color32::from_gray(160)));
                if state.daemon_is_live {
                    ui.label(RichText::new("gRPC (live)").color(Color32::from_rgb(48, 209, 88)).size(12.0));
                } else {
                    ui.label(RichText::new("Mock (offline)").color(Color32::from_rgb(255, 214, 10)).size(12.0));
                }
            });

            // Load relay settings once on first render.
            if !self.relay_settings_loaded {
                self.relay_settings_loaded = true;
                let rt = tokio::runtime::Handle::current();
                self.relay_enabled = rt.block_on(state.daemon.get_setting("relay.enabled"))
                    .map(|v| v == "true" || v == "1")
                    .unwrap_or(true);
                self.relay_bandwidth_input = rt.block_on(state.daemon.get_setting("relay.bandwidth_kbps"))
                    .unwrap_or_else(|| "10000".into());
                self.relay_status = rt.block_on(state.daemon.get_setting("relay.status"))
                    .unwrap_or_else(|| "stopped".into());
            }

            ui.add_space(24.0);
            ui.separator();
            section_header(ui, "Relay Mesh");
            ui.label(RichText::new(
                "Embedded anonymous relay — lets other TransferDaemon peers route through this node."
            ).size(12.0).color(Color32::from_gray(130)));
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Enable relay:").color(Color32::from_gray(160)));
                let mut toggled = self.relay_enabled;
                if ui.checkbox(&mut toggled, "").changed() {
                    self.relay_enabled = toggled;
                    let rt = tokio::runtime::Handle::current();
                    let val = if toggled { "true" } else { "false" };
                    let _ = rt.block_on(state.daemon.set_setting("relay.enabled", val));
                    // Refresh status after a brief delay would require polling; for now
                    // force a re-load on next repaint.
                    self.relay_settings_loaded = false;
                    ctx.request_repaint();
                }
            });

            ui.horizontal(|ui| {
                ui.label(RichText::new("Bandwidth cap (kbps):").color(Color32::from_gray(160)));
                let response = ui.add(egui::TextEdit::singleline(&mut self.relay_bandwidth_input).desired_width(80.0));
                if response.lost_focus() {
                    let rt = tokio::runtime::Handle::current();
                    let _ = rt.block_on(state.daemon.set_setting("relay.bandwidth_kbps", &self.relay_bandwidth_input));
                }
            });

            ui.horizontal(|ui| {
                ui.label(RichText::new("Status:").color(Color32::from_gray(160)));
                let (color, label) = if self.relay_status.starts_with("running") {
                    (Color32::from_rgb(48, 209, 88), self.relay_status.as_str())
                } else {
                    (Color32::from_rgb(255, 69, 58), "stopped")
                };
                ui.label(RichText::new(label).color(color).size(12.0));
                if ui.small_button("Refresh").clicked() {
                    let rt = tokio::runtime::Handle::current();
                    self.relay_status = rt.block_on(state.daemon.get_setting("relay.status"))
                        .unwrap_or_else(|| "stopped".into());
                }
            });

            ui.add_space(24.0);
            ui.separator();
            section_header(ui, "About");
            ui.label(RichText::new("TransferDaemon").strong().color(Color32::WHITE));
            ui.label(RichText::new("Version 1.0.0").color(Color32::from_gray(160)));
            ui.add_space(4.0);
            ui.label(RichText::new(
                "Sovereign, zero-knowledge, universal data transfer.\n\
                 No third-party services. No telemetry. No compromise.",
            ).size(13.0).color(Color32::from_gray(150)));
        });
    }
}

fn section_header(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title.to_uppercase()).size(12.0).color(Color32::from_gray(120)));
    ui.add_space(6.0);
}

fn truncate_key(key: &str) -> String {
    if key.len() <= 16 { return key.to_owned(); }
    format!("{}…{}", &key[..8], &key[key.len()-8..])
}
