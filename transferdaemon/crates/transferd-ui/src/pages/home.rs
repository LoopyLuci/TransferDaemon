//! Home page — tab bar (Chats, Transfers, Contacts) with per-tab panels.

use crate::app::{AppState, Page};
use crate::types::Contact;
use crate::widgets::transfer_bar::transfer_bar;
use egui::{Color32, RichText, ScrollArea, Ui};

#[derive(Default, PartialEq, Clone, Copy)]
pub enum Tab {
    #[default]
    Chats,
    Transfers,
    Contacts,
}

#[derive(Default)]
pub struct HomePage {
    pub tab: Tab,
    pub add_contact_key: String,
    pub add_contact_name: String,
    pub add_error: Option<String>,
}

impl HomePage {
    pub fn show(&mut self, ui: &mut Ui, state: &mut AppState) {
        // Top navigation bar.
        egui::TopBottomPanel::top("tab_bar").show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.set_min_height(44.0);
                for (label, t) in [("💬 Chats", Tab::Chats), ("⬆⬇ Transfers", Tab::Transfers), ("👥 Contacts", Tab::Contacts)] {
                    let active = self.tab == t;
                    let btn = egui::Button::new(
                        RichText::new(label)
                            .color(if active { Color32::from_rgb(0, 122, 255) } else { Color32::from_gray(160) })
                    )
                    .frame(false);
                    if ui.add(btn).clicked() { self.tab = t; }
                    ui.separator();
                }
            });
        });

        // Content area.
        egui::CentralPanel::default().show_inside(ui, |ui| {
            match self.tab {
                Tab::Chats     => self.show_chats(ui, state),
                Tab::Transfers => self.show_transfers(ui, state),
                Tab::Contacts  => self.show_contacts(ui, state),
            }
        });
    }

    fn show_chats(&self, ui: &mut Ui, state: &mut AppState) {
        if state.contacts.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("No conversations yet.\nGo to Contacts to add someone.")
                    .color(Color32::from_gray(140)).size(15.0));
            });
            return;
        }

        ScrollArea::vertical().show(ui, |ui| {
            for contact in &state.contacts.clone() {
                if contact_row(ui, contact) {
                    state.open_chat = Some(contact.id.clone());
                    state.page = Page::Chat;
                }
                ui.separator();
            }
        });
    }

    fn show_transfers(&self, ui: &mut Ui, state: &AppState) {
        if state.transfers.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("No active transfers.").color(Color32::from_gray(140)));
            });
            return;
        }

        ScrollArea::vertical().show(ui, |ui| {
            for t in &state.transfers {
                transfer_bar(ui, t);
                ui.add_space(8.0);
            }
        });
    }

    fn show_contacts(&mut self, ui: &mut Ui, state: &mut AppState) {
        egui::CollapsingHeader::new("Add contact")
            .default_open(state.contacts.is_empty())
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Key:");
                    ui.add(egui::TextEdit::singleline(&mut self.add_contact_key)
                        .hint_text("64-char hex public key")
                        .desired_width(320.0));
                });
                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.add(egui::TextEdit::singleline(&mut self.add_contact_name)
                        .hint_text("Display name")
                        .desired_width(200.0));
                });

                if let Some(e) = &self.add_error {
                    ui.label(RichText::new(e).color(Color32::RED));
                }

                let can_add = self.add_contact_key.len() == 64 && !self.add_contact_name.is_empty();
                ui.add_enabled_ui(can_add, |ui| {
                    if ui.button("Add").clicked() {
                        let rt = tokio::runtime::Handle::current();
                        match rt.block_on(state.daemon.add_contact(
                            self.add_contact_key.clone(),
                            self.add_contact_name.clone(),
                        )) {
                            Ok(c) => {
                                state.contacts.push(c);
                                self.add_contact_key.clear();
                                self.add_contact_name.clear();
                                self.add_error = None;
                            }
                            Err(e) => self.add_error = Some(e.to_string()),
                        }
                    }
                });
            });

        ui.separator();

        ScrollArea::vertical().show(ui, |ui| {
            for contact in &state.contacts.clone() {
                if contact_row(ui, contact) {
                    state.open_chat = Some(contact.id.clone());
                    state.page = Page::Chat;
                }
                ui.separator();
            }
        });
    }
}

/// Renders a contact list row. Returns `true` if the row was clicked (open chat).
fn contact_row(ui: &mut Ui, c: &Contact) -> bool {
    let mut clicked = false;
    let resp = ui.horizontal(|ui| {
        ui.set_min_height(56.0);

        // Avatar circle with initials.
        let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(40.0), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 20.0, Color32::from_rgb(60, 60, 80));
        let initial = c.name.chars().next().unwrap_or('?').to_uppercase().next().unwrap_or('?');
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            initial,
            egui::FontId::proportional(18.0),
            Color32::WHITE,
        );

        ui.vertical(|ui| {
            ui.label(RichText::new(&c.name).strong().color(Color32::WHITE));
            let status = if c.online {
                RichText::new("● Online").color(Color32::from_rgb(48, 209, 88)).size(12.0)
            } else {
                RichText::new("○ Offline").color(Color32::from_gray(140)).size(12.0)
            };
            ui.label(status);
        });
    });

    if resp.response.interact(egui::Sense::click()).clicked() {
        clicked = true;
    }
    clicked
}
