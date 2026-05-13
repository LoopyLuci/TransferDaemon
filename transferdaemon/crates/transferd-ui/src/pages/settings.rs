//! Settings page — identity info, QR code, theme, about.

use crate::app::AppState;
use crate::widgets::qr_widget::QrWidget;
use egui::{Color32, Context, RichText, Ui};

#[derive(Default)]
pub struct SettingsPage {
    qr: QrWidget,
    show_qr: bool,
}

impl SettingsPage {
    pub fn show(&mut self, ui: &mut Ui, ctx: &Context, state: &AppState) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            // Identity section
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
                    ui.label(
                        RichText::new(truncate_key(&id.public_key))
                            .monospace()
                            .color(Color32::from_gray(200)),
                    );
                    if ui.small_button("Copy").clicked() {
                        ui.output_mut(|o| o.copied_text = id.public_key.clone());
                    }
                });

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
                    ui.label(
                        RichText::new("Share this QR code so others can add you as a contact.")
                            .size(12.0)
                            .color(Color32::from_gray(150)),
                    );
                }
            } else {
                ui.label(RichText::new("No identity set up.").color(Color32::from_gray(140)));
            }

            ui.add_space(24.0);
            ui.separator();

            // Network section
            section_header(ui, "Network");
            ui.horizontal(|ui| {
                ui.label(RichText::new("Relay lanes:").color(Color32::from_gray(160)));
                ui.label(RichText::new("1 active").color(Color32::from_rgb(48, 209, 88)));
            });
            ui.horizontal(|ui| {
                ui.label(RichText::new("TCP lanes:").color(Color32::from_gray(160)));
                ui.label(RichText::new("0 active").color(Color32::from_gray(140)));
            });
            ui.horizontal(|ui| {
                ui.label(RichText::new("Daemon:").color(Color32::from_gray(160)));
                ui.label(
                    RichText::new("Mock (Phase 7: gRPC)")
                        .color(Color32::from_rgb(255, 214, 10))
                        .size(12.0),
                );
            });

            ui.add_space(24.0);
            ui.separator();

            // About section
            section_header(ui, "About");
            ui.label(RichText::new("TransferDaemon").strong().color(Color32::WHITE));
            ui.label(RichText::new("Version 0.5.0-alpha").color(Color32::from_gray(160)));
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Sovereign, zero-knowledge, universal data transfer.\n\
                     No third-party services. No telemetry. No compromise.",
                )
                .size(13.0)
                .color(Color32::from_gray(150)),
            );
        });
    }
}

fn section_header(ui: &mut Ui, title: &str) {
    ui.label(
        RichText::new(title.to_uppercase())
            .size(12.0)
            .color(Color32::from_gray(120)),
    );
    ui.add_space(6.0);
}

fn truncate_key(key: &str) -> String {
    if key.len() <= 16 { return key.to_owned(); }
    format!("{}…{}", &key[..8], &key[key.len()-8..])
}
