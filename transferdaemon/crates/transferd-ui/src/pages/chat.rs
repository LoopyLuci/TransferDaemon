//! Chat page — message thread with text input, call controls, and call overlay.

use crate::app::{AppState, Page};
use crate::types::{Message, MessageContent};
use crate::widgets::message_bubble::message_bubble;
use egui::{Color32, Key, Modifiers, RichText, ScrollArea, Ui};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use transferd_webrtc::{CallManager, CallState, MockMediaCapture};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub struct ChatPage {
    pub input: String,
    messages: Vec<Message>,
    last_contact_id: String,
    // File attach state
    file_path: String,
    show_file_input: bool,
    file_error: Option<String>,
    // Call state
    call_manager: CallManager,
    call_start_ts: Option<u64>,
    muted: bool,
}

impl Default for ChatPage {
    fn default() -> Self {
        Self {
            input: String::new(),
            messages: Vec::new(),
            last_contact_id: String::new(),
            file_path: String::new(),
            show_file_input: false,
            file_error: None,
            call_manager: CallManager::new(),
            call_start_ts: None,
            muted: false,
        }
    }
}

impl ChatPage {
    pub fn enter(&mut self, state: &mut AppState) {
        if let Some(cid) = &state.open_chat {
            if *cid != self.last_contact_id {
                let rt = tokio::runtime::Handle::current();
                self.messages = rt.block_on(state.daemon.get_messages(cid));
                self.last_contact_id = cid.clone();
            }
        }
    }

    pub fn show(&mut self, ui: &mut Ui, state: &mut AppState) {
        let contact = state.open_chat.as_ref().and_then(|id| {
            state.contacts.iter().find(|c| c.id == *id).cloned()
        });

        // Snapshot call state synchronously (non-blocking mutex).
        let rt = tokio::runtime::Handle::current();
        let call_state = rt.block_on(self.call_manager.state());

        // ── Header ──
        egui::TopBottomPanel::top("chat_header").show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.set_min_height(44.0);
                if ui.button("←").clicked() {
                    // Hang up before leaving.
                    if !call_state.is_idle() && !call_state.is_ended() {
                        rt.block_on(self.call_manager.end_call());
                        self.call_start_ts = None;
                    }
                    state.page = Page::Home;
                }

                if let Some(c) = &contact {
                    ui.label(RichText::new(&c.name).strong().color(Color32::WHITE).size(17.0));
                    let (dot, col) = if c.online {
                        ("● ", Color32::from_rgb(48, 209, 88))
                    } else {
                        ("○ ", Color32::from_gray(140))
                    };
                    ui.label(RichText::new(dot).color(col).size(12.0));
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    match &call_state {
                        CallState::Active { .. } => {
                            // Hang-up button (red).
                            if ui.add_sized(
                                [36.0, 36.0],
                                egui::Button::new("📵").fill(Color32::from_rgb(255, 59, 48)),
                            ).clicked() {
                                rt.block_on(self.call_manager.end_call());
                                self.call_start_ts = None;
                            }
                        }
                        CallState::Outgoing { .. } => {
                            ui.label(RichText::new("Calling…").color(Color32::from_gray(160)).size(13.0));
                            if ui.small_button("Cancel").clicked() {
                                rt.block_on(self.call_manager.end_call());
                                self.call_start_ts = None;
                            }
                        }
                        _ => {
                            // Voice call button.
                            if ui.add_sized(
                                [36.0, 36.0],
                                egui::Button::new("📞").fill(Color32::from_rgb(30, 30, 30)),
                            ).clicked() {
                                if let Some(_cid) = &state.open_chat {
                                    let media = Arc::new(MockMediaCapture::default());
                                    rt.block_on(self.call_manager.start_call(
                                        _cid.clone(), false, media,
                                    ));
                                    self.call_start_ts = None;
                                }
                            }
                            // Video call button.
                            if ui.add_sized(
                                [36.0, 36.0],
                                egui::Button::new("📹").fill(Color32::from_rgb(30, 30, 30)),
                            ).clicked() {
                                if let Some(_cid) = &state.open_chat {
                                    let media = Arc::new(MockMediaCapture::new_with_video());
                                    rt.block_on(self.call_manager.start_call(
                                        _cid.clone(), true, media,
                                    ));
                                    self.call_start_ts = None;
                                }
                            }
                        }
                    }
                });
            });
        });

        // ── Input bar ──
        egui::TopBottomPanel::bottom("chat_input").show_inside(ui, |ui| {
            // File attach panel (shown when 📎 is toggled).
            if self.show_file_input {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("File:").color(Color32::from_gray(160)));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.file_path)
                            .hint_text("Paste full file path…")
                            .desired_width(ui.available_width() - 80.0),
                    );
                    let can_send = !self.file_path.trim().is_empty();
                    ui.add_enabled_ui(can_send, |ui| {
                        if ui.button(RichText::new("Send").color(Color32::from_rgb(0, 122, 255))).clicked() {
                            self.send_file(state);
                        }
                    });
                });
                if let Some(e) = &self.file_error.clone() {
                    ui.label(RichText::new(e).color(Color32::RED).size(12.0));
                }
                ui.separator();
            }

            // Text message row.
            ui.horizontal(|ui| {
                ui.set_min_height(48.0);

                // 📎 toggle.
                let attach_color = if self.show_file_input {
                    Color32::from_rgb(0, 122, 255)
                } else {
                    Color32::from_gray(160)
                };
                if ui.add_sized([32.0, 32.0],
                    egui::Button::new(RichText::new("📎").color(attach_color)).frame(false)
                ).clicked() {
                    self.show_file_input = !self.show_file_input;
                    self.file_error = None;
                }

                let input_field = egui::TextEdit::singleline(&mut self.input)
                    .hint_text("Message…")
                    .font(egui::FontId::proportional(15.0))
                    .desired_width(ui.available_width() - 64.0);
                let resp = ui.add(input_field);

                let send_shortcut = ui.input(|i| {
                    i.key_pressed(Key::Enter)
                        && !i.modifiers.matches_logically(Modifiers::SHIFT)
                });

                if (ui
                    .button(RichText::new("Send").color(Color32::from_rgb(0, 122, 255)))
                    .clicked()
                    || (send_shortcut && resp.has_focus()))
                    && !self.input.trim().is_empty()
                {
                    self.send_message(state);
                }
            });
        });

        // ── Main area: active call overlay + messages ──
        egui::CentralPanel::default().show_inside(ui, |ui| {
            // Active call banner at the top of the message area.
            if let CallState::Active { .. } = &call_state {
                if self.call_start_ts.is_none() {
                    self.call_start_ts = Some(now_secs());
                }
                self.show_call_banner(ui, &rt);
            }

            ScrollArea::vertical()
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.add_space(8.0);
                    for msg in &self.messages {
                        message_bubble(ui, msg);
                        ui.add_space(4.0);
                    }
                    ui.add_space(8.0);
                });
        });
    }

    fn show_call_banner(&mut self, ui: &mut Ui, rt: &tokio::runtime::Handle) {
        let elapsed = self
            .call_start_ts
            .map(|t| now_secs().saturating_sub(t))
            .unwrap_or(0);
        let duration = format!("{:02}:{:02}", elapsed / 60, elapsed % 60);

        egui::Frame::none()
            .fill(Color32::from_rgb(28, 28, 30))
            .rounding(egui::Rounding::same(10.0))
            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Green pulsing dot.
                    ui.label(
                        RichText::new("●")
                            .color(Color32::from_rgb(48, 209, 88))
                            .size(12.0),
                    );
                    ui.label(
                        RichText::new(format!("Call in progress  {duration}"))
                            .color(Color32::WHITE)
                            .size(13.0),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Hang up.
                        if ui
                            .add_sized(
                                [28.0, 28.0],
                                egui::Button::new("📵")
                                    .fill(Color32::from_rgb(255, 59, 48)),
                            )
                            .clicked()
                        {
                            rt.block_on(self.call_manager.end_call());
                            self.call_start_ts = None;
                        }

                        // Mute toggle.
                        let mute_label = if self.muted { "🔇" } else { "🔊" };
                        let mute_color = if self.muted {
                            Color32::from_rgb(255, 59, 48)
                        } else {
                            Color32::from_rgb(58, 58, 60)
                        };
                        if ui
                            .add_sized(
                                [28.0, 28.0],
                                egui::Button::new(mute_label).fill(mute_color),
                            )
                            .clicked()
                        {
                            self.muted = !self.muted;
                        }
                    });
                });
            });
        ui.add_space(6.0);
    }

    fn send_file(&mut self, state: &mut AppState) {
        let Some(cid) = state.open_chat.clone() else { return };
        let path = self.file_path.trim().to_owned();
        if path.is_empty() { return; }
        let rt = tokio::runtime::Handle::current();
        match rt.block_on(state.daemon.send_file(&cid, path)) {
            Ok(msg) => {
                self.messages.push(msg);
                self.file_path.clear();
                self.file_error = None;
                self.show_file_input = false;
                // Refresh transfers list.
                state.transfers = rt.block_on(state.daemon.get_transfers());
            }
            Err(e) => {
                self.file_error = Some(e.to_string());
            }
        }
    }

    fn send_message(&mut self, state: &mut AppState) {
        let Some(cid) = state.open_chat.clone() else { return };
        let text = self.input.trim().to_owned();
        if text.is_empty() { return; }

        let rt = tokio::runtime::Handle::current();
        match rt.block_on(state.daemon.send_text(&cid, text)) {
            Ok(msg) => {
                self.messages.push(msg);
                self.input.clear();
            }
            Err(e) => {
                self.messages.push(Message {
                    id: "err".into(),
                    contact_id: cid,
                    outbound: true,
                    content: MessageContent::Text(format!("⚠ {e}")),
                    timestamp_ts: 0,
                    status: crate::types::MessageStatus::Failed,
                });
            }
        }
    }
}
