//! Chat page — message thread with text input, file attachment, and call overlay.

use crate::app::{AppState, Page};
use crate::types::{Message, MessageContent, MessageStatus};
use crate::widgets::message_bubble::message_bubble;
use egui::{Color32, ColorImage, Key, Modifiers, RichText, ScrollArea, TextureHandle, TextureOptions, Ui};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use transferd_webrtc::{media::MediaCapture, CallManager, CallState, MockMediaCapture};

const POLL_INTERVAL: Duration = Duration::from_millis(500);

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub struct ChatPage {
    // Input state
    pub input: String,
    // File attach — either a text path (desktop) or filled by platform picker callback.
    pub file_path: String,
    show_file_input: bool,
    file_error: Option<String>,
    /// Set by the platform layer (e.g. Android JNI) when a file is chosen.
    /// `show()` drains this each frame.
    pub pending_file_path: Option<String>,
    /// Optional platform-provided callback invoked when the 📎 button is tapped.
    /// If `None`, the text-field fallback is shown instead (desktop default).
    pub on_attach: Option<Box<dyn Fn() + Send + Sync>>,

    // Message state
    messages: Vec<Message>,
    seen_ids: HashSet<String>,
    last_contact_id: String,
    last_poll: Instant,
    scroll_to_bottom: bool,

    // Call state
    call_manager: CallManager,
    call_start_ts: Option<u64>,
    muted: bool,
    /// Remote video frame rendered as an egui texture during active video calls.
    remote_video_texture: Option<TextureHandle>,
    /// Platform-injected factory for creating the right `MediaCapture` backend.
    /// If `None`, falls back to `MockMediaCapture` (desktop/CI behaviour).
    pub media_factory: Option<Box<dyn Fn(bool) -> Arc<dyn MediaCapture> + Send + Sync>>,
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
                // Force an immediate fetch on first entry.
                .checked_sub(POLL_INTERVAL * 2)
                .unwrap_or_else(Instant::now),
            scroll_to_bottom: true,
            call_manager: CallManager::new(),
            call_start_ts: None,
            muted: false,
            remote_video_texture: None,
            media_factory: None,
        }
    }
}

impl ChatPage {
    // -------------------------------------------------------------------------
    // Entry hook — called once per frame before `show` when the page is active.
    // -------------------------------------------------------------------------

    pub fn enter(&mut self, state: &mut AppState) {
        if let Some(cid) = state.open_chat.clone() {
            if cid != self.last_contact_id {
                // Switched to a different contact — clear history and force fetch.
                self.messages.clear();
                self.seen_ids.clear();
                self.last_contact_id = cid.clone();
                self.last_poll = Instant::now()
                    .checked_sub(POLL_INTERVAL * 2)
                    .unwrap_or_else(Instant::now);
                self.scroll_to_bottom = true;
                self.input.clear();
                self.show_file_input = false;
                self.file_error = None;
            }

            // Poll for new messages on a 500ms cadence.
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
                    // Update conversation preview.
                    if let Some(last) = self.messages.last() {
                        let preview = message_preview(last);
                        state.message_previews.insert(cid.clone(), (preview, last.timestamp_ts));
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
        // Drain any file path delivered by the platform picker.
        if let Some(path) = self.pending_file_path.take() {
            self.file_path = path;
            self.show_file_input = true;
            self.file_error = None;
        }

        let contact = state.open_chat.as_ref().and_then(|id| {
            state.contacts.iter().find(|c| c.id == *id).cloned()
        });

        let rt = tokio::runtime::Handle::current();
        let call_state = rt.block_on(self.call_manager.state());
        let bubble_max_w = ui.available_width() * 0.75;

        // ── Header ────────────────────────────────────────────────────────────
        egui::TopBottomPanel::top("chat_header")
            .frame(egui::Frame::none().fill(Color32::from_rgb(18, 18, 18)))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.set_min_height(48.0);

                    // Back button — returns to chat list and clears active chat.
                    if ui.add_sized(
                        [44.0, 44.0],
                        egui::Button::new(RichText::new("←").size(18.0)).frame(false),
                    ).clicked() {
                        if !call_state.is_idle() && !call_state.is_ended() {
                            rt.block_on(self.call_manager.end_call());
                            self.call_start_ts = None;
                        }
                        state.open_chat = None;
                        state.page = Page::Home;
                    }

                    // Contact name + online indicator
                    if let Some(c) = &contact {
                        let (dot, dot_col) = if c.online {
                            ("●", Color32::from_rgb(48, 209, 88))
                        } else {
                            ("○", Color32::from_gray(120))
                        };
                        ui.label(RichText::new(dot).color(dot_col).size(10.0));
                        ui.label(RichText::new(&c.name).strong().color(Color32::WHITE).size(17.0));
                    }

                    // Call buttons (right-aligned)
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        match &call_state {
                            CallState::Active { .. } => {
                                if ui.add_sized([40.0, 40.0],
                                    egui::Button::new("📵").fill(Color32::from_rgb(255, 59, 48)),
                                ).clicked() {
                                    rt.block_on(self.call_manager.end_call());
                                    self.call_start_ts = None;
                                }
                            }
                            CallState::Outgoing { .. } => {
                                ui.label(RichText::new("Calling…").color(Color32::from_gray(160)).size(13.0));
                                if ui.add_sized([60.0, 36.0],
                                    egui::Button::new("Cancel").fill(Color32::from_rgb(60, 60, 60)),
                                ).clicked() {
                                    rt.block_on(self.call_manager.end_call());
                                    self.call_start_ts = None;
                                }
                            }
                            _ => {
                                // Video call
                                if ui.add_sized([40.0, 40.0],
                                    egui::Button::new("📹").fill(Color32::from_rgb(30, 30, 30)),
                                ).clicked() {
                                    if let Some(cid) = &state.open_chat.clone() {
                                        let media = self.make_capture(true);
                                        rt.block_on(self.call_manager.start_call(cid.clone(), true, media));
                                        self.call_start_ts = None;
                                    }
                                }
                                // Voice call
                                if ui.add_sized([40.0, 40.0],
                                    egui::Button::new("📞").fill(Color32::from_rgb(30, 30, 30)),
                                ).clicked() {
                                    if let Some(cid) = &state.open_chat.clone() {
                                        let media = self.make_capture(false);
                                        rt.block_on(self.call_manager.start_call(cid.clone(), false, media));
                                        self.call_start_ts = None;
                                    }
                                }
                            }
                        }
                    });
                });
            });

        // ── Input bar ─────────────────────────────────────────────────────────
        egui::TopBottomPanel::bottom("chat_input")
            .frame(egui::Frame::none()
                .fill(Color32::from_rgb(18, 18, 18))
                .inner_margin(egui::Margin::symmetric(8.0, 6.0)))
            .show_inside(ui, |ui| {
                // File attach panel — shown when file_path is pending.
                if self.show_file_input {
                    egui::Frame::none()
                        .fill(Color32::from_rgb(28, 28, 30))
                        .rounding(8.0)
                        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("📁").size(16.0));
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.file_path)
                                        .hint_text("File path…")
                                        .desired_width(ui.available_width() - 72.0),
                                );
                                if ui.add_sized([56.0, 32.0],
                                    egui::Button::new(RichText::new("Send").size(14.0))
                                        .fill(Color32::from_rgb(0, 122, 255)),
                                ).clicked() && !self.file_path.trim().is_empty() {
                                    self.send_file(state);
                                }
                            });
                            if let Some(e) = &self.file_error.clone() {
                                ui.label(RichText::new(e).color(Color32::RED).size(12.0));
                            }
                        });
                    ui.add_space(4.0);
                }

                // Text row: 📎 — input — ➤
                ui.horizontal(|ui| {
                    ui.set_min_height(48.0);

                    // Attach button
                    let attach_active = self.show_file_input;
                    let attach_col = if attach_active {
                        Color32::from_rgb(0, 122, 255)
                    } else {
                        Color32::from_gray(160)
                    };
                    if ui.add_sized(
                        [40.0, 40.0],
                        egui::Button::new(RichText::new("📎").size(18.0).color(attach_col)).frame(false),
                    ).clicked() {
                        if let Some(cb) = &self.on_attach {
                            // Platform-native picker (Android).
                            cb();
                        } else {
                            // Desktop fallback: toggle text-field.
                            self.show_file_input = !self.show_file_input;
                            self.file_error = None;
                            if !self.show_file_input { self.file_path.clear(); }
                        }
                    }

                    // Grow-as-you-type text input (multiline, starts as single line).
                    let avail = ui.available_width() - 56.0;
                    let input_resp = ui.add(
                        egui::TextEdit::multiline(&mut self.input)
                            .hint_text("Message…")
                            .font(egui::FontId::proportional(15.0))
                            .desired_rows(1)
                            .desired_width(avail),
                    );

                    // Send on Enter (not Shift+Enter).
                    let send_shortcut = ui.input(|i| {
                        i.key_pressed(Key::Enter)
                            && !i.modifiers.matches_logically(Modifiers::SHIFT)
                    });

                    // Send button ➤
                    let can_send = !self.input.trim().is_empty();
                    ui.add_enabled_ui(can_send, |ui| {
                        if ui.add_sized(
                            [48.0, 40.0],
                            egui::Button::new(RichText::new("➤").size(18.0))
                                .fill(Color32::from_rgb(0, 122, 255)),
                        ).clicked()
                            || (send_shortcut && input_resp.has_focus() && can_send)
                        {
                            self.send_message(state);
                        }
                    });
                });
            });

        // ── Message list ──────────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(Color32::from_rgb(0, 0, 0)))
            .show_inside(ui, |ui| {
                // Active call: poll remote video and update egui texture.
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
                                    )
                                );
                            }
                        }
                    }
                    self.show_call_banner(ui, &rt);
                } else {
                    // Clear texture when call ends.
                    self.remote_video_texture = None;
                }

                // Empty state
                if self.messages.is_empty() {
                    ui.centered_and_justified(|ui| {
                        let name = contact.as_ref().map(|c| c.name.as_str()).unwrap_or("this contact");
                        ui.label(
                            RichText::new(format!("No messages with {name} yet.\nSay hello!"))
                                .color(Color32::from_gray(100))
                                .size(14.0),
                        );
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
                    ui.add_space(8.0);
                    for msg in &self.messages {
                        message_bubble(ui, msg, bubble_max_w);
                        ui.add_space(4.0);
                    }
                    ui.add_space(8.0);
                });
            });
    }

    // -------------------------------------------------------------------------
    // Active call banner
    // -------------------------------------------------------------------------

    fn show_call_banner(&mut self, ui: &mut Ui, rt: &tokio::runtime::Handle) {
        let elapsed = self.call_start_ts.map(|t| now_secs().saturating_sub(t)).unwrap_or(0);
        let duration = format!("{:02}:{:02}", elapsed / 60, elapsed % 60);

        // Remote video feed — shown when the session is delivering frames.
        if let Some(tex) = &self.remote_video_texture {
            let avail_w = ui.available_width();
            // Maintain 4:3 aspect ratio.
            let vid_h = avail_w * 3.0 / 4.0;
            let size = egui::Vec2::new(avail_w, vid_h.min(240.0));
            ui.add(egui::Image::new(tex).fit_to_exact_size(size));
            ui.add_space(4.0);
        }

        egui::Frame::none()
            .fill(Color32::from_rgb(28, 28, 30))
            .rounding(egui::Rounding::same(10.0))
            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("●").color(Color32::from_rgb(48, 209, 88)).size(12.0));
                    ui.label(RichText::new(format!("Call in progress  {duration}"))
                        .color(Color32::WHITE).size(13.0));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add_sized([32.0, 32.0],
                            egui::Button::new("📵").fill(Color32::from_rgb(255, 59, 48)),
                        ).clicked() {
                            rt.block_on(self.call_manager.end_call());
                            self.call_start_ts = None;
                        }

                        let mute_lbl = if self.muted { "🔇" } else { "🔊" };
                        let mute_col = if self.muted {
                            Color32::from_rgb(255, 59, 48)
                        } else {
                            Color32::from_rgb(58, 58, 60)
                        };
                        if ui.add_sized([32.0, 32.0],
                            egui::Button::new(mute_lbl).fill(mute_col),
                        ).clicked() {
                            self.muted = !self.muted;
                        }
                    });
                });
            });
        ui.add_space(6.0);
    }

    /// Create the right `MediaCapture` for this platform.
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
        let Some(cid) = state.open_chat.clone() else { return };
        let path = self.file_path.trim().to_owned();
        if path.is_empty() { return; }
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
        let Some(cid) = state.open_chat.clone() else { return };
        // Trim but preserve the original for the preview.
        let text = self.input.trim().to_owned();
        if text.is_empty() { return; }
        self.input.clear(); // Clear optimistically — feels snappier.

        let rt = tokio::runtime::Handle::current();
        match rt.block_on(state.daemon.send_text(&cid, text.clone())) {
            Ok(msg) => {
                state.message_previews.insert(cid.clone(), (text, msg.timestamp_ts));
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
                };
                self.seen_ids.insert(err_msg.id.clone());
                self.messages.push(err_msg);
                self.scroll_to_bottom = true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn message_preview(msg: &Message) -> String {
    match &msg.content {
        MessageContent::Text(t) => t.clone(),
        MessageContent::File { name, .. } => format!("📁 {name}"),
    }
}
