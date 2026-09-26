//! Chat page — message thread with text input, file attachment, and call overlay.
//!
//! Redesigned with the new design system for a modern, accessible experience.

use crate::app::{AppState, Page};
use crate::design::{self, DesignTokens};
use crate::types::{Message, MessageContent, MessageStatus};
use crate::widgets::message_bubble::{message_bubble, DEFAULT_INBOUND_COLOR, DEFAULT_OUTBOUND_COLOR};
use egui::{Color32, ColorImage, Key, Modifiers, RichText, ScrollArea, TextureHandle, TextureOptions, Ui, Vec2};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use transferd_webrtc::{media::MediaCapture, CallManager, CallState, MockMediaCapture};

const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Preset palette for inbound bubble colors.
const COLOR_PALETTE: &[(Color32, &str)] = &[
    (Color32::from_rgb(44,  44,  46),  "Default"),
    (Color32::from_rgb(52,  199, 89),  "Green"),
    (Color32::from_rgb(90,  200, 250), "Sky"),
    (Color32::from_rgb(255, 149, 0),   "Orange"),
    (Color32::from_rgb(175, 82,  222), "Purple"),
    (Color32::from_rgb(255, 55,  95),  "Pink"),
    (Color32::from_rgb(255, 204, 0),   "Yellow"),
    (Color32::from_rgb(88,  86,  214), "Indigo"),
    (Color32::from_rgb(0,   122, 255), "Blue"),
    (Color32::from_rgb(162, 132, 94),  "Tan"),
];

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct ChatPage {
    pub input: String,
    pub file_path: String,
    show_file_input: bool,
    file_error: Option<String>,
    pub pending_file_path: Option<String>,
    pub on_attach: Option<Box<dyn Fn() + Send + Sync>>,

    messages: Vec<Message>,
    seen_ids: HashSet<String>,
    last_contact_id: String,
    last_poll: Instant,
    scroll_to_bottom: bool,

    call_manager: CallManager,
    call_start_ts: Option<u64>,
    muted: bool,
    remote_video_texture: Option<TextureHandle>,
    #[allow(clippy::type_complexity)]
    pub media_factory: Option<Box<dyn Fn(bool) -> Arc<dyn MediaCapture> + Send + Sync>>,

    /// Whether the in-chat settings panel is expanded.
    show_settings: bool,
    /// Whether the safety-number panel is expanded.
    show_safety: bool,
    /// Cached safety number (refreshed when the panel opens).
    safety_number: String,
    safety_verified: bool,
    /// Pending color save: set by the settings panel, drained by TransferDaemonApp::update().
    pending_color_save: Option<(String, Color32)>,
    /// Message search query (empty = no filtering).
    search_query: String,
    /// Whether the search field is open.
    search_active: bool,
    /// Cached results from `DaemonApi::search_messages`, refreshed on query change.
    search_results: Vec<Message>,
    /// The query the cached `search_results` were produced for.
    last_search_query: String,
    /// Id of the message currently being replied to (quote preview above input).
    replying_to: Option<String>,
    /// Last time a typing indicator was sent (throttled).
    last_typing_sent: Instant,
}

impl Default for ChatPage {
    fn default() -> Self {
        Self {
            input: String::new(),
            file_path: String::new(),
            show_file_input: false,
            file_error: None,
            pending_file_path: None,
            on_attach: None,
            messages: Vec::new(),
            seen_ids: HashSet::new(),
            last_contact_id: String::new(),
            last_poll: Instant::now()
                .checked_sub(POLL_INTERVAL * 2)
                .unwrap_or_else(Instant::now),
            scroll_to_bottom: true,
            call_manager: CallManager::new(),
            call_start_ts: None,
            muted: false,
            remote_video_texture: None,
            media_factory: None,
            show_settings: false,
            show_safety: false,
            safety_number: String::new(),
            safety_verified: false,
            pending_color_save: None,
            search_query: String::new(),
            search_active: false,
            search_results: Vec::new(),
            last_search_query: String::new(),
            replying_to: None,
            last_typing_sent: Instant::now(),
        }
    }
}

impl ChatPage {
    /// Drain any pending color save produced by the settings panel.
    pub fn take_pending_color_save(&mut self) -> Option<(String, Color32)> {
        self.pending_color_save.take()
    }

    // -------------------------------------------------------------------------
    // Entry hook
    // -------------------------------------------------------------------------

    pub fn enter(&mut self, state: &mut AppState) {
        // Consume a pending OS share payload (file → attach, text → draft).
        if let Some((kind, payload)) = state.pending_share.take() {
            match kind.as_str() {
                "file" => self.pending_file_path = Some(payload),
                _ => {
                    self.input = payload;
                }
            }
        }
        if let Some(cid) = state.open_chat.clone() {
            if cid != self.last_contact_id {
                // Save the previous conversation's draft.
                if !self.last_contact_id.is_empty() && !self.input.is_empty() {
                    state.drafts.insert(self.last_contact_id.clone(), std::mem::take(&mut self.input));
                }
                self.messages.clear();
                self.seen_ids.clear();
                self.last_contact_id = cid.clone();
                self.last_poll = Instant::now()
                    .checked_sub(POLL_INTERVAL * 2)
                    .unwrap_or_else(Instant::now);
                self.scroll_to_bottom = true;
                self.input = state.drafts.get(&cid).cloned().unwrap_or_default();
                self.show_file_input = false;
                self.file_error = None;
                self.show_settings = false;
                self.replying_to = None;
            }

            if self.last_poll.elapsed() >= POLL_INTERVAL {
                self.last_poll = Instant::now();
                let rt = tokio::runtime::Handle::current();
                let all = rt.block_on(state.daemon.get_messages(&cid));
                let mut added = false;
                for msg in all {
                    if self.seen_ids.insert(msg.id.clone()) {
                        self.messages.push(msg);
                        added = true;
                    }
                }
                if added {
                    self.scroll_to_bottom = true;
                    if let Some(last) = self.messages.last() {
                        let preview = message_preview(last);
                        state
                            .message_previews
                            .insert(cid.clone(), (preview, last.timestamp_ts));
                        state.rebuild_conversations();
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Main render
    // -------------------------------------------------------------------------

    pub fn show(&mut self, ui: &mut Ui, state: &mut AppState) {
        let tokens = DesignTokens::current();

        if let Some(path) = self.pending_file_path.take() {
            self.file_path = path;
            self.show_file_input = true;
            self.file_error = None;
        }

        let contact = state
            .open_chat
            .as_ref()
            .and_then(|id| state.contacts.iter().find(|c| c.id == *id).cloned());

        let rt = tokio::runtime::Handle::current();
        let call_state = rt.block_on(self.call_manager.state());
        let bubble_max_w = ui.available_width() * 0.78;

        // Get the inbound color for this contact (used for bubbles and the settings panel).
        let contact_id = state.open_chat.clone().unwrap_or_default();
        let inbound_color = state.contact_colors.get(&contact_id).copied();

        // ── Header ────────────────────────────────────────────────────────────
        egui::TopBottomPanel::top("chat_header")
            .frame(
                egui::Frame::none()
                    .fill(tokens.palette.chat_header)
                    .stroke(egui::Stroke::new(0.5_f32, tokens.palette.border_subtle))
                    .inner_margin(egui::Margin::symmetric(8.0, 4.0)),
            )
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.set_min_height(48.0);

                    // Back button
                    if ui
                        .add_sized(
                            [44.0, 44.0],
                            egui::Button::new(
                                RichText::new("←")
                                    .size(18.0)
                                    .color(tokens.palette.text_primary),
                            )
                            .frame(false),
                        )
                        .clicked()
                    {
                        if !call_state.is_idle() && !call_state.is_ended() {
                            rt.block_on(self.call_manager.end_call());
                            self.call_start_ts = None;
                        }
                        state.open_chat = None;
                        state.page = Page::Home;
                    }

                    // Contact info
                    if let Some(c) = &contact {
                        let (dot, dot_col) = if c.online {
                            ("●", tokens.palette.success)
                        } else {
                            ("○", tokens.palette.text_disabled)
                        };
                        ui.label(
                            RichText::new(dot)
                                .color(dot_col)
                                .size(10.0),
                        );
                        ui.label(
                            RichText::new(c.display_name())
                                .strong()
                                .color(tokens.palette.text_primary)
                                .size(17.0),
                        );
                        // Live typing indicator.
                        if c.typing {
                            ui.label(
                                RichText::new("is typing…")
                                    
                                    .size(12.0)
                                    .color(tokens.palette.accent),
                            );
                        }
                    }

                    // Search toggle
                    if !self.search_active {
                        if ui.add_sized(
                            [40.0, 40.0],
                            egui::Button::new(RichText::new("🔍").size(16.0).color(tokens.palette.text_secondary))
                                .frame(false),
                        ).clicked() {
                            self.search_active = true;
                            self.search_query = String::new();
                        }
                    } else {
                        ui.add_sized(
                            [120.0, 32.0],
                            egui::TextEdit::singleline(&mut self.search_query)
                                .hint_text("Search…"),
                        );
                        if ui.add_sized(
                            [28.0, 28.0],
                            egui::Button::new(RichText::new("✕").size(12.0).color(tokens.palette.text_disabled))
                                .frame(false),
                        ).clicked() {
                            self.search_query.clear();
                            self.search_active = false;
                            self.search_results.clear();
                            self.last_search_query.clear();
                        }
                    }

                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            // Safety number
                            let shield_col = if self.show_safety {
                                tokens.palette.accent
                            } else {
                                tokens.palette.text_secondary
                            };
                            if ui
                                .add_sized(
                                    [40.0, 40.0],
                                    egui::Button::new(
                                        RichText::new("🔒")
                                            .size(16.0)
                                            .color(shield_col),
                                    )
                                    .frame(false),
                                )
                                .clicked()
                            {
                                self.show_safety = !self.show_safety;
                                if self.show_safety {
                                    if let Some(cid) = &state.open_chat.clone() {
                                        let (num, verified) =
                                            rt.block_on(state.daemon.get_safety_number(cid));
                                        self.safety_number = num;
                                        self.safety_verified = verified;
                                    }
                                }
                            }

                            // Settings gear
                            let gear_col = if self.show_settings {
                                tokens.palette.accent
                            } else {
                                tokens.palette.text_secondary
                            };
                            if ui
                                .add_sized(
                                    [40.0, 40.0],
                                    egui::Button::new(
                                        RichText::new("⚙")
                                            .size(18.0)
                                            .color(gear_col),
                                    )
                                    .frame(false),
                                )
                                .clicked()
                            {
                                self.show_settings = !self.show_settings;
                            }

                            // Call controls
                            match &call_state {
                                CallState::Active { .. } => {
                                    if ui
                                        .add_sized(
                                            [40.0, 40.0],
                                            egui::Button::new("📵")
                                                .fill(tokens.palette.error)
                                                .rounding(20.0),
                                        )
                                        .clicked()
                                    {
                                        rt.block_on(self.call_manager.end_call());
                                        self.call_start_ts = None;
                                    }
                                }
                                CallState::Outgoing { .. } => {
                                    ui.label(
                                        RichText::new("Calling…")
                                            .color(tokens.palette.text_secondary)
                                            .size(13.0),
                                    );
                                    if ui
                                        .add_sized(
                                            [60.0, 36.0],
                                            egui::Button::new(
                                                RichText::new("Cancel")
                                                    .color(tokens.palette.text_primary),
                                            )
                                            .fill(tokens.palette.surface)
                                            .rounding(tokens.spacing.button_rounding),
                                        )
                                        .clicked()
                                    {
                                        rt.block_on(self.call_manager.end_call());
                                        self.call_start_ts = None;
                                    }
                                }
                                _ => {
                                    if ui
                                        .add_sized(
                                            [40.0, 40.0],
                                            egui::Button::new("📹")
                                                .fill(tokens.palette.surface)
                                                .rounding(20.0),
                                        )
                                        .clicked()
                                    {
                                        if let Some(cid) = &state.open_chat.clone() {
                                            let media = self.make_capture(true);
                                            let _ = rt.block_on(
                                                self.call_manager
                                                    .start_call(cid.clone(), true, media),
                                            );
                                            self.call_start_ts = None;
                                        }
                                    }
                                    if ui
                                        .add_sized(
                                            [40.0, 40.0],
                                            egui::Button::new("📞")
                                                .fill(tokens.palette.surface)
                                                .rounding(20.0),
                                        )
                                        .clicked()
                                    {
                                        if let Some(cid) = &state.open_chat.clone() {
                                            let media = self.make_capture(false);
                                            let _ = rt.block_on(
                                                self.call_manager
                                                    .start_call(cid.clone(), false, media),
                                            );
                                            self.call_start_ts = None;
                                        }
                                    }
                                }
                            }
                        },
                    );
                });
            });

        // ── Settings panel ────────────────────────────────────────────────────
        if self.show_settings {
            egui::TopBottomPanel::top("chat_settings")
                .frame(
                    egui::Frame::none()
                        .fill(tokens.palette.bg_secondary)
                        .inner_margin(egui::Margin::symmetric(12.0, 10.0)),
                )
                .show_inside(ui, |ui| {
                    ui.label(
                        RichText::new("Conversation settings")
                            .size(13.0)
                            .color(tokens.palette.text_secondary),
                    );
                    ui.add_space(tokens.spacing.xs);
                    ui.label(
                        RichText::new("Their bubble color")
                            .size(14.0)
                            .color(tokens.palette.text_primary),
                    );
                    ui.add_space(tokens.spacing.xs);
                    ui.horizontal_wrapped(|ui| {
                        for (color, label) in COLOR_PALETTE {
                            let selected = inbound_color
                                .map(|c| c == *color)
                                .unwrap_or(*color == DEFAULT_INBOUND_COLOR);
                            let stroke = if selected {
                                egui::Stroke::new(2.5_f32, tokens.palette.text_primary)
                            } else {
                                egui::Stroke::new(1.0_f32, tokens.palette.border)
                            };
                            let (rect, resp) =
                                ui.allocate_exact_size(Vec2::splat(32.0), egui::Sense::click());
                            ui.painter()
                                .rect_filled(rect, 8.0, *color);
                            ui.painter().rect_stroke(rect, 8.0, stroke);
                            if resp.hovered() {
                                ui.painter().rect_stroke(
                                    rect,
                                    8.0,
                                    egui::Stroke::new(2.0_f32, tokens.palette.text_primary),
                                );
                            }
                            if resp.clicked() {
                                self.pending_color_save =
                                    Some((contact_id.clone(), *color));
                            }
                            resp.on_hover_text(*label);
                        }
                    });
                    ui.add_space(tokens.spacing.xxs);

                    // Preview row
                    ui.add_space(tokens.spacing.xxs);
                    ui.label(
                        RichText::new("Preview")
                            .size(12.0)
                            .color(tokens.palette.text_disabled),
                    );
                    ui.add_space(tokens.spacing.xxs);
                    ui.horizontal(|ui| {
                        let preview_color =
                            inbound_color.unwrap_or(DEFAULT_INBOUND_COLOR);
                        let avail = ui.available_width();
                        // Inbound preview
                        let (r, _) = ui.allocate_exact_size(
                            Vec2::new(avail * 0.4, 28.0),
                            egui::Sense::hover(),
                        );
                        ui.painter().rect_filled(r, 10.0, preview_color);
                        ui.painter().text(
                            r.center(),
                            egui::Align2::CENTER_CENTER,
                            "Hello!",
                            egui::FontId::proportional(12.0),
                            Color32::WHITE,
                        );
                        ui.add_space(8.0);
                        // Outbound preview
                        let (r2, _) = ui.allocate_exact_size(
                            Vec2::new(avail * 0.4, 28.0),
                            egui::Sense::hover(),
                        );
                        ui.painter()
                            .rect_filled(r2, 10.0, DEFAULT_OUTBOUND_COLOR);
                        ui.painter().text(
                            r2.center(),
                            egui::Align2::CENTER_CENTER,
                            "Hi!",
                            egui::FontId::proportional(12.0),
                            Color32::WHITE,
                        );
                    });
                });
        }

        // ── Safety number panel ───────────────────────────────────────────────
        if self.show_safety {
            egui::TopBottomPanel::top("chat_safety")
                .frame(
                    egui::Frame::none()
                        .fill(tokens.palette.bg_secondary)
                        .inner_margin(egui::Margin::symmetric(12.0, 10.0)),
                )
                .show_inside(ui, |ui| {
                    ui.label(
                        RichText::new("Safety number")
                            .size(13.0)
                            .color(tokens.palette.text_secondary),
                    );
                    ui.add_space(tokens.spacing.xs);
                    if self.safety_number.is_empty() {
                        ui.label(
                            RichText::new(
                                "No verified identity yet — establish a session first.",
                            )
                            .size(13.0)
                            .color(tokens.palette.text_disabled),
                        );
                    } else {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&self.safety_number)
                                    .monospace()
                                    .size(18.0)
                                    .color(tokens.palette.text_primary),
                            ),
                        );
                        ui.add_space(tokens.spacing.xxs);
                        ui.horizontal(|ui| {
                            if self.safety_verified {
                                ui.label(
                                    RichText::new("✓ verified")
                                        .color(tokens.palette.success)
                                        .size(11.0),
                                );
                            } else {
                                ui.label(
                                    RichText::new("not verified")
                                        .color(tokens.palette.text_disabled)
                                        .size(11.0),
                                );
                            }
                        });
                        ui.add_space(tokens.spacing.xxs);
                        ui.label(
                            RichText::new(
                                "Compare this number with the one shown to your contact \
                                 on their device. If they match, you are talking to the \
                                 right person.",
                            )
                            .size(11.0)
                            .color(tokens.palette.text_disabled),
                        );
                    }
                });
        }

        // ── Input bar ─────────────────────────────────────────────────────────
        egui::TopBottomPanel::bottom("chat_input")
            .frame(
                egui::Frame::none()
                    .fill(tokens.palette.chat_header)
                    .stroke(egui::Stroke::new(0.5_f32, tokens.palette.border_subtle))
                    .inner_margin(egui::Margin::symmetric(8.0, 8.0)),
            )
            .show_inside(ui, |ui| {
                if self.show_file_input {
                design::card_frame(&tokens).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("📁").size(16.0));
                            let input_frame = design::input_frame(&tokens);
                            input_frame.show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.file_path)
                                        .hint_text("File path…")
                                        .desired_width(ui.available_width() - 72.0)
                                        .margin(Vec2::new(8.0, 6.0)),
                                );
                            });
                            if ui
                                .add_sized(
                                    [56.0, 32.0],
                                    egui::Button::new(
                                        RichText::new("Send")
                                            .size(14.0)
                                            .color(tokens.palette.text_inverse),
                                    )
                                    .fill(tokens.palette.accent)
                                    .rounding(tokens.spacing.button_rounding),
                                )
                                .clicked()
                                && !self.file_path.trim().is_empty()
                            {
                                self.send_file(state);
                            }
                        });
                        if let Some(e) = &self.file_error.clone() {
                            ui.label(
                                RichText::new(format!("⚠ {e}"))
                                    .color(tokens.palette.error)
                                    .size(12.0),
                            );
                        }
                    });
                    ui.add_space(tokens.spacing.xs);
                }

                ui.horizontal(|ui| {
                    ui.set_min_height(48.0);

                    // Attachment button
                    let attach_active = self.show_file_input;
                    let attach_col = if attach_active {
                        tokens.palette.accent
                    } else {
                        tokens.palette.text_secondary
                    };
                    if ui
                        .add_sized(
                            [40.0, 40.0],
                            egui::Button::new(
                                RichText::new("📎")
                                    .size(18.0)
                                    .color(attach_col),
                            )
                            .frame(false),
                        )
                        .clicked()
                    {
                        if let Some(cb) = &self.on_attach {
                            cb();
                        } else {
                            self.show_file_input = !self.show_file_input;
                            self.file_error = None;
                            if !self.show_file_input {
                                self.file_path.clear();
                            }
                        }
                    }

                    // Text input
                    let avail = ui.available_width() - 56.0;
                    let input_frame = design::input_frame(&tokens);
                    let input_resp = input_frame
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut self.input)
                                    .hint_text("Message…")
                                    .font(egui::FontId::proportional(15.0))
                                    .desired_rows(1)
                                    .desired_width(avail - 16.0)
                                    .margin(Vec2::new(8.0, 8.0)),
                            )
                        })
                        .inner;

                    // Typing indicator: throttled "is typing" while the user has
                    // non-empty text, cleared once they send.
                    if input_resp.changed() {
                        state.drafts.insert(contact_id.clone(), self.input.clone());
                        if !self.input.trim().is_empty()
                            && self.last_typing_sent.elapsed() >= std::time::Duration::from_secs(2)
                        {
                            self.last_typing_sent = Instant::now();
                            let rt = tokio::runtime::Handle::current();
                            rt.block_on(state.daemon.send_typing(&contact_id, true));
                        }
                    }

                    // Reply-quote bar above the input.
                    if let Some(rid) = self.replying_to.clone() {
                        let quoted = self.messages.iter().find(|m| m.id == rid);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("↩").color(tokens.palette.accent));
                            if let Some(q) = quoted {
                                ui.label(
                                    RichText::new(q.content.preview())
                                        .size(12.0)
                                        .color(tokens.palette.text_secondary),
                                );
                            } else {
                                ui.label(
                                    RichText::new("Replying…")
                                        .size(12.0)
                                        .color(tokens.palette.text_secondary),
                                );
                            }
                            if ui.small_button("✕").clicked() {
                                self.replying_to = None;
                            }
                        });
                    }

                    let send_shortcut = ui.input(|i| {
                        i.key_pressed(Key::Enter)
                            && !i.modifiers.matches_logically(Modifiers::SHIFT)
                    });

                    let can_send = !self.input.trim().is_empty();
                    ui.add_enabled_ui(can_send, |ui| {
                        if ui
                            .add_sized(
                                [48.0, 40.0],
                                egui::Button::new(
                                    RichText::new("➤")
                                        .size(18.0)
                                        .color(tokens.palette.text_inverse),
                                )
                                .fill(tokens.palette.accent)
                                .rounding(20.0),
                            )
                            .clicked()
                            || (send_shortcut && input_resp.has_focus() && can_send)
                        {
                            self.send_message(state);
                        }
                    });
                });
            });

        // ── Message list ──────────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(tokens.palette.bg_primary))
            .show_inside(ui, |ui| {
                if let CallState::Active { .. } = &call_state {
                    if self.call_start_ts.is_none() {
                        self.call_start_ts = Some(now_secs());
                    }
                    if let Some(frame) = rt.block_on(self.call_manager.poll_remote_video()) {
                        let color_image = ColorImage::from_rgba_unmultiplied(
                            [frame.width as usize, frame.height as usize],
                            &frame.rgba,
                        );
                        match &mut self.remote_video_texture {
                            Some(tex) => tex.set(color_image, TextureOptions::LINEAR),
                            None => {
                                self.remote_video_texture = Some(
                                    ui.ctx().load_texture(
                                        "remote_video",
                                        color_image,
                                        TextureOptions::LINEAR,
                                    ),
                                );
                            }
                        }
                    }
                    self.show_call_banner(ui, &rt, &tokens);
                } else {
                    self.remote_video_texture = None;
                }

                if self.messages.is_empty() {
                    ui.centered_and_justified(|ui| {
                        let name = contact
                            .as_ref()
                            .map(|c| c.display_name().to_owned())
                            .unwrap_or_else(|| "this contact".to_owned());
                        ui.vertical_centered(|ui| {
                            ui.add_space(ui.available_height() / 3.0);
                            ui.label(
                                RichText::new("💬")
                                    .size(48.0)
                                    .color(tokens.palette.text_disabled),
                            );
                            ui.add_space(tokens.spacing.sm);
                            ui.label(
                                RichText::new(format!("No messages with {name} yet."))
                                    .color(tokens.palette.text_secondary)
                                    .size(15.0),
                            );
                            ui.add_space(tokens.spacing.xs);
                            ui.label(
                                RichText::new("Say hello!")
                                    .color(tokens.palette.text_tertiary)
                                    .size(13.0),
                            );
                        });
                    });
                    return;
                }

                let mut scroll = ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true);

                if self.scroll_to_bottom {
                    scroll = scroll.vertical_scroll_offset(f32::MAX);
                    self.scroll_to_bottom = false;
                }

                scroll.show(ui, |ui| {
                    ui.add_space(tokens.spacing.sm);
                    let iter: Box<dyn Iterator<Item = &Message>> = if self.search_query.is_empty() {
                        Box::new(self.messages.iter())
                    } else {
                        // Refresh server-side search results whenever the query changes.
                        if self.last_search_query != self.search_query {
                            self.last_search_query = self.search_query.clone();
                            let rt = tokio::runtime::Handle::current();
                            self.search_results =
                                rt.block_on(state.daemon.search_messages(&contact_id, &self.search_query));
                        }
                        Box::new(self.search_results.iter())
                    };
                    let mut pending_actions = Vec::new();
                    for msg in iter {
                        let msgs = self.messages.clone();
                        if let Some(action) = message_bubble(ui, msg, bubble_max_w, inbound_color, &msgs) {
                            pending_actions.push(action);
                        }
                        ui.add_space(tokens.spacing.xxs);
                    }
                    ui.add_space(tokens.spacing.sm);

                    // Apply hover actions after the borrow of self.messages ends.
                    for action in pending_actions {
                        match action {
                            crate::widgets::message_bubble::BubbleAction::Reply(id) => {
                                self.replying_to = Some(id);
                            }
                            crate::widgets::message_bubble::BubbleAction::React { msg_id, emoji } => {
                                let rt = tokio::runtime::Handle::current();
                                rt.block_on(state.daemon.toggle_reaction(&contact_id, &msg_id, &emoji));
                                let all = rt.block_on(state.daemon.get_messages(&contact_id));
                                self.messages = all;
                                self.seen_ids.clear();
                                for m in &self.messages {
                                    self.seen_ids.insert(m.id.clone());
                                }
                            }
                        }
                    }
                });
            });
    }

    // -------------------------------------------------------------------------
    // Active call banner
    // -------------------------------------------------------------------------

    fn show_call_banner(
        &mut self,
        ui: &mut Ui,
        rt: &tokio::runtime::Handle,
        tokens: &DesignTokens,
    ) {
        let elapsed = self
            .call_start_ts
            .map(|t| now_secs().saturating_sub(t))
            .unwrap_or(0);
        let duration = format!("{:02}:{:02}", elapsed / 60, elapsed % 60);

        if let Some(tex) = &self.remote_video_texture {
            let avail_w = ui.available_width();
            let vid_h = avail_w * 3.0 / 4.0;
            let size = Vec2::new(avail_w, vid_h.min(240.0));
            ui.add(egui::Image::new(tex).fit_to_exact_size(size));
            ui.add_space(tokens.spacing.xs);
        }

        design::card_frame(tokens).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("●")
                        .color(tokens.palette.success)
                        .size(12.0),
                );
                ui.label(
                    RichText::new(format!("Call in progress  {duration}"))
                        .color(tokens.palette.text_primary)
                        .size(13.0),
                );

                ui.with_layout(
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        if ui
                            .add_sized(
                                [32.0, 32.0],
                                egui::Button::new("📵")
                                    .fill(tokens.palette.error)
                                    .rounding(16.0),
                            )
                            .clicked()
                        {
                            rt.block_on(self.call_manager.end_call());
                            self.call_start_ts = None;
                        }

                        let mute_lbl = if self.muted { "🔇" } else { "🔊" };
                        let mute_col = if self.muted {
                            tokens.palette.error
                        } else {
                            tokens.palette.surface
                        };
                        if ui
                            .add_sized(
                                [32.0, 32.0],
                                egui::Button::new(mute_lbl)
                                    .fill(mute_col)
                                    .rounding(16.0),
                            )
                            .clicked()
                        {
                            self.muted = !self.muted;
                        }
                    },
                );
            });
        });
        ui.add_space(tokens.spacing.sm);
    }

    fn make_capture(&self, video: bool) -> Arc<dyn MediaCapture> {
        if let Some(factory) = &self.media_factory {
            factory(video)
        } else if video {
            Arc::new(MockMediaCapture::new_with_video())
        } else {
            Arc::new(MockMediaCapture::default())
        }
    }

    // -------------------------------------------------------------------------
    // Send helpers
    // -------------------------------------------------------------------------

    fn send_file(&mut self, state: &mut AppState) {
        let Some(cid) = state.open_chat.clone() else {
            return;
        };
        let path = self.file_path.trim().to_owned();
        if path.is_empty() {
            return;
        }
        let rt = tokio::runtime::Handle::current();
        match rt.block_on(state.daemon.send_file(&cid, path)) {
            Ok(msg) => {
                if self.seen_ids.insert(msg.id.clone()) {
                    self.messages.push(msg);
                    self.scroll_to_bottom = true;
                }
                self.file_path.clear();
                self.file_error = None;
                self.show_file_input = false;
                state.transfers = rt.block_on(state.daemon.get_transfers());
            }
            Err(e) => self.file_error = Some(e.to_string()),
        }
    }

    fn send_message(&mut self, state: &mut AppState) {
        let Some(cid) = state.open_chat.clone() else {
            return;
        };
        let text = self.input.trim().to_owned();
        if text.is_empty() {
            return;
        }
        let reply_to = self.replying_to.clone();
        self.input.clear();
        self.replying_to = None;
        state.drafts.remove(&cid);

        let rt = tokio::runtime::Handle::current();
        rt.block_on(state.daemon.send_typing(&cid, false));
        let result = if let Some(r) = reply_to {
            rt.block_on(state.daemon.send_reply(&cid, text.clone(), r))
        } else {
            rt.block_on(state.daemon.send_text(&cid, text.clone()))
        };
        match result {
            Ok(msg) => {
                state
                    .message_previews
                    .insert(cid.clone(), (text, msg.timestamp_ts));
                state.rebuild_conversations();
                if self.seen_ids.insert(msg.id.clone()) {
                    self.messages.push(msg);
                }
                self.scroll_to_bottom = true;
            }
            Err(e) => {
                let err_msg = Message {
                    id: format!("err-{}", now_secs()),
                    contact_id: cid,
                    outbound: true,
                    content: MessageContent::Text(format!("⚠ {e}")),
                    timestamp_ts: now_secs(),
                    status: MessageStatus::Failed,
                    group_id: None,
                    sender_pk: None,
                    reply_to: None,
                    reactions: Vec::new(),
                };
                self.seen_ids.insert(err_msg.id.clone());
                self.messages.push(err_msg);
                self.scroll_to_bottom = true;
            }
        }
    }
}

fn message_preview(msg: &Message) -> String {
    match &msg.content {
        MessageContent::Text(t) => t.clone(),
        MessageContent::File { name, .. } => format!("📁 {name}"),
    }
}
