//! Home page — bottom tab bar (Chats / Contacts / Transfers / Settings).

use crate::app::{AppState, Page};
use crate::pages::{chat::ChatPage, settings::SettingsPage};
use crate::types::{Contact, Conversation};
use crate::widgets::transfer_bar::transfer_bar;
use egui::{Color32, Context, RichText, ScrollArea, Ui};

// ---------------------------------------------------------------------------
// Tab
// ---------------------------------------------------------------------------

#[derive(Default, PartialEq, Clone, Copy)]
pub enum Tab {
    #[default]
    Chats,
    Contacts,
    Transfers,
    Settings,
}

// ---------------------------------------------------------------------------
// HomePage
// ---------------------------------------------------------------------------

pub struct HomePage {
    pub tab: Tab,
    // Contacts sub-state
    add_contact_key:  String,
    add_contact_name: String,
    add_error:        Option<String>,
    // Settings sub-state (reused shared widget)
    settings: SettingsPage,
}

impl Default for HomePage {
    fn default() -> Self {
        Self {
            tab:              Tab::Chats,
            add_contact_key:  String::new(),
            add_contact_name: String::new(),
            add_error:        None,
            settings:         SettingsPage::default(),
        }
    }
}

impl HomePage {
    /// Top-level show — called from `TransferDaemonApp::update()` with Context
    /// so we can use TopBottomPanel at the root level (not nested inside another panel).
    pub fn show(&mut self, ctx: &Context, state: &mut AppState, chat: &mut ChatPage) {
        // ── Bottom tab bar ────────────────────────────────────────────────────
        egui::TopBottomPanel::bottom("bottom_tabs")
            .min_height(56.0)
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(18, 18, 18))
                    .inner_margin(egui::Margin::symmetric(0.0, 4.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let tab_width = ui.available_width() / 4.0;
                    for (t, icon, label) in [
                        (Tab::Chats,     "💬", "Chats"),
                        (Tab::Contacts,  "👥", "Contacts"),
                        (Tab::Transfers, "⬆⬇", "Transfers"),
                        (Tab::Settings,  "⚙",  "Settings"),
                    ] {
                        let active = self.tab == t;
                        let text_color = if active {
                            Color32::from_rgb(0, 122, 255)
                        } else {
                            Color32::from_gray(140)
                        };
                        let btn = egui::Button::new(
                            RichText::new(format!("{icon}\n{label}"))
                                .size(11.0)
                                .color(text_color),
                        )
                        .frame(false)
                        .min_size(egui::vec2(tab_width, 48.0));

                        if ui.add_sized(egui::vec2(tab_width, 48.0), btn).clicked() {
                            self.tab = t;
                        }
                    }
                });
            });

        // ── Top bar (title) — not shown on Settings tab (it has its own header) ─
        if self.tab != Tab::Settings {
            egui::TopBottomPanel::top("home_top_bar")
                .frame(egui::Frame::none().fill(Color32::from_rgb(0, 0, 0)))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.set_min_height(44.0);
                        let title = match self.tab {
                            Tab::Chats     => "Chats",
                            Tab::Contacts  => "Contacts",
                            Tab::Transfers => "Transfers",
                            Tab::Settings  => "Settings",
                        };
                        ui.label(RichText::new(title).size(17.0).strong().color(Color32::WHITE));
                    });
                });
        }

        // ── Content ───────────────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(Color32::from_rgb(0, 0, 0)))
            .show(ctx, |ui| {
                match self.tab {
                    Tab::Chats     => show_chat_list(ui, state, chat),
                    Tab::Contacts  => self.show_contacts(ui, state),
                    Tab::Transfers => show_transfers(ui, state),
                    Tab::Settings  => self.settings.show(ui, ctx, state),
                }
            });
    }
}

// ---------------------------------------------------------------------------
// Chat list
// ---------------------------------------------------------------------------

fn show_chat_list(ui: &mut Ui, state: &mut AppState, _chat: &mut ChatPage) {
    if state.conversations.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(
                RichText::new("No conversations yet.\nGo to Contacts to add someone.")
                    .color(Color32::from_gray(140))
                    .size(15.0),
            );
        });
        return;
    }

    ScrollArea::vertical().show(ui, |ui| {
        let convs: Vec<Conversation> = state.conversations.clone();
        for conv in &convs {
            let clicked = conversation_row(ui, conv);
            ui.add(egui::Separator::default().spacing(0.0));
            if clicked {
                state.open_chat = Some(conv.contact_id.clone());
                state.page = Page::Chat;
            }
        }
    });
}

/// Renders one conversation row. Returns `true` if clicked.
fn conversation_row(ui: &mut Ui, conv: &Conversation) -> bool {
    const ROW_H: f32 = 68.0;
    const AVATAR_R: f32 = 22.0;

    let (rect, resp) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), ROW_H),
        egui::Sense::click(),
    );

    if ui.is_rect_visible(rect) {
        // Hover / press highlight
        if resp.hovered() {
            ui.painter().rect_filled(rect, 0.0, Color32::from_rgb(28, 28, 30));
        }

        // Avatar circle
        let avatar_center = rect.left_center() + egui::vec2(20.0 + AVATAR_R, 0.0);
        ui.painter().circle_filled(avatar_center, AVATAR_R, Color32::from_rgb(55, 55, 75));
        let initial = conv.display_name.chars().next().unwrap_or('?')
            .to_uppercase().next().unwrap_or('?');
        ui.painter().text(
            avatar_center,
            egui::Align2::CENTER_CENTER,
            initial,
            egui::FontId::proportional(18.0),
            Color32::WHITE,
        );

        // Online dot
        if conv.online {
            let dot = avatar_center + egui::vec2(AVATAR_R * 0.65, AVATAR_R * 0.65);
            ui.painter().circle_filled(dot, 6.0, Color32::from_rgb(48, 209, 88));
            ui.painter().circle_stroke(dot, 6.0, egui::Stroke::new(2.0, Color32::BLACK));
        }

        let text_x = avatar_center.x + AVATAR_R + 12.0;
        let right_x = rect.right() - 12.0;

        // Timestamp (top right)
        let ts = format_ts(conv.last_time_sec);
        let ts_galley = ui.painter().layout_no_wrap(
            ts,
            egui::FontId::proportional(11.0),
            Color32::from_gray(120),
        );
        let ts_pos = egui::pos2(right_x - ts_galley.size().x, rect.top() + 14.0);
        ui.painter().galley(ts_pos, ts_galley, Color32::from_gray(120));

        // Name
        let name_galley = ui.painter().layout_no_wrap(
            conv.display_name.clone(),
            egui::FontId::proportional(15.0),
            Color32::WHITE,
        );
        ui.painter().galley(egui::pos2(text_x, rect.top() + 12.0), name_galley, Color32::WHITE);

        // Last-message preview
        let preview = if conv.last_message.is_empty() {
            "No messages yet".to_owned()
        } else {
            conv.last_message.clone()
        };
        let preview_color = if conv.last_message.is_empty() {
            Color32::from_gray(80)
        } else {
            Color32::from_gray(150)
        };
        let max_preview_w = right_x - text_x - if conv.unread > 0 { 36.0 } else { 0.0 };
        let preview_galley = ui.painter().layout(
            preview,
            egui::FontId::proportional(13.0),
            preview_color,
            max_preview_w,
        );
        ui.painter().galley(
            egui::pos2(text_x, rect.top() + 34.0),
            preview_galley,
            preview_color,
        );

        // Unread badge
        if conv.unread > 0 {
            let badge_center = egui::pos2(right_x - 10.0, rect.top() + 38.0);
            ui.painter().circle_filled(badge_center, 10.0, Color32::from_rgb(0, 122, 255));
            let n = format!("{}", conv.unread.min(99));
            let ng = ui.painter().layout_no_wrap(n, egui::FontId::proportional(10.0), Color32::WHITE);
            ui.painter().galley(
                badge_center - ng.size() / 2.0,
                ng,
                Color32::WHITE,
            );
        }
    }

    resp.clicked()
}

// ---------------------------------------------------------------------------
// Contacts tab
// ---------------------------------------------------------------------------

impl HomePage {
    fn show_contacts(&mut self, ui: &mut Ui, state: &mut AppState) {
        // Add contact form
        egui::CollapsingHeader::new("➕  Add contact")
            .default_open(state.contacts.is_empty())
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Key:").color(Color32::from_gray(160)));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_contact_key)
                            .hint_text("64-char hex public key")
                            .desired_width(ui.available_width() - 8.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Name:").color(Color32::from_gray(160)));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_contact_name)
                            .hint_text("Display name")
                            .desired_width(ui.available_width() - 8.0),
                    );
                });
                if let Some(e) = &self.add_error {
                    ui.label(RichText::new(e).color(Color32::RED).size(12.0));
                }

                let can_add = self.add_contact_key.len() == 64 && !self.add_contact_name.is_empty();
                ui.add_enabled_ui(can_add, |ui| {
                    if ui.add_sized([ui.available_width(), 44.0],
                        egui::Button::new("Add contact").fill(Color32::from_rgb(0, 122, 255)),
                    ).clicked() {
                        let rt = tokio::runtime::Handle::current();
                        match rt.block_on(state.daemon.add_contact(
                            self.add_contact_key.trim().to_owned(),
                            self.add_contact_name.trim().to_owned(),
                        )) {
                            Ok(c) => {
                                state.contacts.push(c);
                                state.rebuild_conversations();
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
            let contacts: Vec<Contact> = state.contacts.clone();
            for c in &contacts {
                let clicked = contact_row(ui, c);
                ui.separator();
                if clicked {
                    state.open_chat = Some(c.id.clone());
                    state.page = Page::Chat;
                }
            }
        });
    }
}

fn contact_row(ui: &mut Ui, c: &Contact) -> bool {
    const ROW_H: f32 = 56.0;
    let (rect, resp) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), ROW_H),
        egui::Sense::click(),
    );

    if ui.is_rect_visible(rect) {
        if resp.hovered() {
            ui.painter().rect_filled(rect, 0.0, Color32::from_rgb(28, 28, 30));
        }
        // Avatar
        let av = rect.left_center() + egui::vec2(32.0, 0.0);
        ui.painter().circle_filled(av, 20.0, Color32::from_rgb(55, 55, 75));
        let init = c.name.chars().next().unwrap_or('?').to_uppercase().next().unwrap_or('?');
        ui.painter().text(av, egui::Align2::CENTER_CENTER, init,
            egui::FontId::proportional(16.0), Color32::WHITE);

        // Name + status
        let tx = av.x + 28.0;
        let name_g = ui.painter().layout_no_wrap(
            c.name.clone(), egui::FontId::proportional(15.0), Color32::WHITE,
        );
        ui.painter().galley(egui::pos2(tx, rect.top() + 10.0), name_g, Color32::WHITE);

        let (status_txt, status_col) = if c.online {
            ("● Online", Color32::from_rgb(48, 209, 88))
        } else {
            ("○ Offline", Color32::from_gray(120))
        };
        let sg = ui.painter().layout_no_wrap(
            status_txt.to_owned(), egui::FontId::proportional(12.0), status_col,
        );
        ui.painter().galley(egui::pos2(tx, rect.top() + 30.0), sg, status_col);

        // Key truncated
        let short_key = if c.id.len() >= 16 {
            format!("{}…{}", &c.id[..6], &c.id[c.id.len()-6..])
        } else {
            c.id.clone()
        };
        let kg = ui.painter().layout_no_wrap(
            short_key, egui::FontId::monospace(10.0), Color32::from_gray(80),
        );
        ui.painter().galley(
            egui::pos2(rect.right() - kg.size().x - 8.0, rect.center().y - kg.size().y / 2.0),
            kg, Color32::from_gray(80),
        );
    }

    resp.clicked()
}

// ---------------------------------------------------------------------------
// Transfers tab
// ---------------------------------------------------------------------------

fn show_transfers(ui: &mut Ui, state: &AppState) {
    if state.transfers.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(
                RichText::new("No active transfers.")
                    .color(Color32::from_gray(140))
                    .size(15.0),
            );
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_ts(ts: u64) -> String {
    if ts == 0 { return String::new(); }
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let delta = now.saturating_sub(ts);
    if delta < 60 {
        "now".to_owned()
    } else if delta < 3600 {
        format!("{}m", delta / 60)
    } else if delta < 86400 {
        format!("{}h", delta / 3600)
    } else {
        format!("{}d", delta / 86400)
    }
}
