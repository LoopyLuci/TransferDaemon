//! Home page — bottom tab bar (Chats / Contacts / Transfers / Settings).
//!
//! Redesigned with the new design system for a modern, responsive experience.

use crate::app::{AppState, Page};
use crate::design::{self, DesignTokens, LayoutMode};
use crate::pages::{chat::ChatPage, settings::SettingsPage, telemetry::TelemetryPage};
use crate::widgets::transfer_bar::{transfer_bar, TransferActionKind};
use egui::{Color32, Context, RichText, ScrollArea, Vec2};

#[derive(Default, PartialEq, Clone, Copy)]
pub enum Tab {
    #[default]
    Chats,
    Groups,
    Contacts,
    Transfers,
    Settings,
    Telemetry,
    Connections,
}

/// Actions available from a contact's overflow menu.
enum ContactAction {
    Block,
    Unblock,
    Remove,
    CopyKey,
}

pub struct HomePage {
    pub tab: Tab,
    // Add-contact form
    show_add_contact_form: bool,
    add_contact_key: String,
    add_contact_name: String,
    add_contact_address: String,
    add_error: Option<String>,
    // QR scanner
    qr_scanner: crate::widgets::qr_scanner::QrScanner,
    // Nickname editing state
    editing_nickname_for: Option<String>,
    nickname_input: String,
    /// Pending nickname persistence — drained by TransferDaemonApp::update() via take_pending_nickname_save().
    pending_nickname_save: Option<(String, Option<String>)>,
    /// Contact whose action menu (block/remove/copy) is open.
    contact_menu_for: Option<String>,
    /// Two-step confirmation for contact removal.
    confirm_remove: bool,
    /// Tab to auto-reveal (center) in the scrollable nav bar next frame.
    /// Set when the active tab changes so the strip scrolls it into view.
    pending_nav_scroll: Option<Tab>,
    // Sub-pages
    settings: SettingsPage,
    telemetry: TelemetryPage,
    groups: crate::pages::groups::GroupsPage,
    connections: crate::pages::connections::ConnectionsPage,
}

impl Default for HomePage {
    fn default() -> Self {
        Self {
            tab: Tab::Chats,
            show_add_contact_form: true,
            add_contact_key: String::new(),
            add_contact_name: String::new(),
            add_contact_address: String::new(),
            add_error: None,
            qr_scanner: crate::widgets::qr_scanner::QrScanner::new(),
            editing_nickname_for: None,
            nickname_input: String::new(),
            pending_nickname_save: None,
            contact_menu_for: None,
            confirm_remove: false,
            pending_nav_scroll: None,
            settings: SettingsPage::default(),
            telemetry: TelemetryPage::default(),
            groups: crate::pages::groups::GroupsPage::default(),
            connections: crate::pages::connections::ConnectionsPage::default(),
        }
    }
}

impl HomePage {
    pub fn show(
        &mut self,
        ctx: &Context,
        state: &mut AppState,
        chat: &mut ChatPage,
        layout_mode: LayoutMode,
    ) {
        let tokens = DesignTokens::current();
        let tabs = [
            (Tab::Chats, "💬", "Chats"),
            (Tab::Groups, "👥", "Groups"),
            (Tab::Contacts, "📇", "Contacts"),
            (Tab::Transfers, "⬆⬇", "Transfers"),
            (Tab::Settings, "⚙", "Settings"),
            (Tab::Connections, "🌐", "Network"),
            (Tab::Telemetry, "📊", "Metrics"),
        ];

        if layout_mode == LayoutMode::Compact {
            // ── Phone: bottom tab bar (horizontally scrollable strip) ──────
            // Each tab is a fixed, comfortable width; tabs that don't fit are
            // reached by side-scrolling (touch drag, mouse drag, or shift+wheel).
            // The active tab auto-reveals (centers itself) when it changes.
            egui::TopBottomPanel::bottom("bottom_tabs")
                .min_height(64.0)
                .frame(
                    egui::Frame::none()
                        .fill(tokens.palette.tab_bar_bg)
                        .stroke(egui::Stroke::new(0.5_f32, tokens.palette.border_subtle))
                        .inner_margin(egui::Margin::symmetric(8.0, 6.0)),
                )
                .show(ctx, |ui| {
                    egui::ScrollArea::horizontal()
                        .id_source("home_nav_scroll")
                        .auto_shrink([false, false])
                        .scroll_bar_visibility(
                            egui::scroll_area::ScrollBarVisibility::AlwaysHidden,
                        )
                        .drag_to_scroll(true)
                        .max_height(54.0)
                        .show(ui, |ui| {
                            ui.set_min_height(50.0);
                            ui.horizontal(|ui| {
                                for (t, icon, label) in tabs {
                                    let active = self.tab == t;
                                    let (clicked, response) =
                                        Self::nav_button(ui, &tokens, icon, label, active, 88.0, 46.0);
                                    if clicked {
                                        self.select_tab(t);
                                    }
                                    if active && self.pending_nav_scroll == Some(t) {
                                        response
                                            .scroll_to_me(Some(egui::Align::Center));
                                    }
                                }
                            });
                        });
                    // One-shot reveal has been consumed for this frame.
                    self.pending_nav_scroll = None;
                });
        } else {
            // ── Tablet/Desktop: left navigation rail ────────────────────────
            egui::SidePanel::left("nav_rail")
                .exact_width(96.0)
                .frame(
                    egui::Frame::none()
                        .fill(tokens.palette.tab_bar_bg)
                        .stroke(egui::Stroke::new(0.5_f32, tokens.palette.border_subtle))
                        .inner_margin(egui::Margin::symmetric(6.0, 10.0)),
                )
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .id_source("nav_rail_scroll")
                        .auto_shrink([false, false])
                        .scroll_bar_visibility(
                            egui::scroll_area::ScrollBarVisibility::AlwaysHidden,
                        )
                        .show(ui, |ui| {
                            ui.set_min_height(ui.available_height());
                            for (t, icon, label) in tabs {
                                let active = self.tab == t;
                                let (clicked, _) =
                                    Self::nav_button(ui, &tokens, icon, label, active, 84.0, 54.0);
                                if clicked {
                                    self.select_tab(t);
                                }
                            }
                        });
                });
        }
        self.pending_nav_scroll = None;

        // ── Top bar (title) ───────────────────────────────────────────────────
        if self.tab != Tab::Settings && self.tab != Tab::Telemetry {
            egui::TopBottomPanel::top("home_top_bar")
                .frame(
                    egui::Frame::none()
                        .fill(tokens.palette.chat_header)
                        .inner_margin(egui::Margin::symmetric(16.0, 10.0)),
                )
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.set_min_height(44.0);

                        let title = match self.tab {
                            Tab::Chats => "Chats",
                            Tab::Groups => "Groups",
                            Tab::Contacts => "Contacts",
                            Tab::Transfers => "Transfers",
                            _ => "",
                        };
                        ui.label(
                            RichText::new(title)
                                .size(20.0)
                                .strong()
                                .color(tokens.palette.text_primary),
                        );

                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                // Add button (context-dependent)
                                match self.tab {
                                    Tab::Contacts => {
                                        if ui
                                            .add_sized(
                                                [36.0, 36.0],
                                                egui::Button::new(
                                                    RichText::new("+").size(18.0).color(tokens.palette.text_primary),
                                                )
                                                .fill(tokens.palette.accent)
                                                .rounding(18.0),
                                            )
                                            .clicked()
                                        {
                                            self.show_add_contact_form = !self.show_add_contact_form;
                                        }
                                    }
                                    Tab::Chats => {
                                        // New chat button (future: contact picker)
                                    }
                                    _ => {}
                                }
                            },
                        );
                    });
                });
        }

        // ── Tab content ───────────────────────────────────────────────────────
        match self.tab {
            Tab::Chats => self.show_chats(ctx, state, chat),
            Tab::Groups => {
                egui::CentralPanel::default()
                    .frame(egui::Frame::none().fill(tokens.palette.bg_primary))
                    .show(ctx, |ui| {
                        self.groups.show(ui, state);
                    });
            }
            Tab::Contacts => self.show_contacts(ctx, state),
            Tab::Connections => {
                egui::CentralPanel::default()
                    .frame(egui::Frame::none().fill(tokens.palette.bg_primary))
                    .show(ctx, |ui| {
                        self.connections.show(ui, state);
                    });
            }
            Tab::Transfers => self.show_transfers(ctx, state),
            Tab::Settings => {
                egui::CentralPanel::default()
                    .frame(egui::Frame::none().fill(tokens.palette.bg_primary))
                    .show(ctx, |ui| {
                        self.settings.show(ui, ctx, state);
                    });
                // Apply a pending app-lock change (set / clear PIN).
                if let Some(action) = self.settings.take_pending_pin() {
                    let rt = tokio::runtime::Handle::current();
                    match action {
                        Some(hash) => {
                            let _ = rt.block_on(state.daemon.set_setting("app.lock.pin", &hash));
                            state.pin_hash = Some(hash);
                        }
                        None => {
                            let _ = rt.block_on(state.daemon.set_setting("app.lock.pin", ""));
                            state.pin_hash = None;
                        }
                    }
                }
            }
            Tab::Telemetry => {
                egui::CentralPanel::default()
                    .frame(egui::Frame::none().fill(tokens.palette.bg_primary))
                    .show(ctx, |ui| {
                        self.telemetry
                            .show(ui, state.daemon_addr.as_deref(), ctx);
                    });
            }
        }
    }

    /// Switch the active nav tab, cancelling any inline edit and scheduling a
    /// reveal of the newly-active tab in the scrollable strip.
    fn select_tab(&mut self, t: Tab) {
        if self.tab != t {
            self.tab = t;
            self.editing_nickname_for = None;
            self.pending_nav_scroll = Some(t);
        }
    }

    /// Render a single nav tab (icon + label). Returns `(clicked, response)`.
    fn nav_button(
        ui: &mut egui::Ui,
        tokens: &DesignTokens,
        icon: &str,
        label: &str,
        active: bool,
        w: f32,
        h: f32,
    ) -> (bool, egui::Response) {
        let text_color = if active {
            tokens.palette.text_inverse
        } else {
            tokens.palette.tab_inactive
        };
        let bg = if active {
            tokens.palette.accent
        } else {
            Color32::TRANSPARENT
        };
        let btn = egui::Button::new(
            RichText::new(format!("{icon}\n{label}"))
                .size(11.0)
                .strong()
                .color(text_color),
        )
        .fill(bg)
        .stroke(egui::Stroke::new(0.5_f32, tokens.palette.border_subtle))
        .rounding(egui::Rounding::same(12.0))
        .min_size(egui::vec2(w, h));
        let response = ui.add_sized(egui::vec2(w, h), btn);
        (response.clicked(), response)
    }

    fn show_chats(&mut self, ctx: &Context, state: &mut AppState, _chat: &mut ChatPage) {
        let tokens = DesignTokens::current();

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(tokens.palette.bg_primary))
            .show(ctx, |ui| {
                if state.conversations.is_empty() {
                    // Empty state
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() / 3.0);
                        ui.label(
                            RichText::new("💬")
                                .size(48.0)
                                .color(tokens.palette.text_disabled),
                        );
                        ui.add_space(tokens.spacing.sm);
                        ui.label(
                            RichText::new("No conversations yet")
                                .size(16.0)
                                .color(tokens.palette.text_secondary),
                        );
                        ui.add_space(tokens.spacing.xs);
                        ui.label(
                            RichText::new("Add a contact to start chatting")
                                .size(13.0)
                                .color(tokens.palette.text_tertiary),
                        );
                    });
                    return;
                }

                ScrollArea::vertical().show(ui, |ui| {
                    for conv in &state.conversations {
                        let is_selected = state
                            .open_chat
                            .as_ref()
                            .map(|id| id == &conv.contact_id)
                            .unwrap_or(false);

                        let bg = if is_selected {
                            tokens.palette.surface_hover
                        } else {
                            Color32::TRANSPARENT
                        };

                        let response = ui
                            .add_sized(
                                [ui.available_width(), 64.0],
                                egui::Button::new(
                                    RichText::new("").size(1.0),
                                )
                                .fill(bg)
                                .rounding(0.0)
                                .frame(true),
                            );

                        // Draw chat row content over the button
                        let rect = response.rect;
                        let painter = ui.painter();

                        // Online indicator
                        let dot_color = if conv.online {
                            tokens.palette.success
                        } else {
                            tokens.palette.text_disabled
                        };
                        painter.circle_filled(
                            rect.left_center() + Vec2::new(20.0, 0.0),
                            4.0,
                            dot_color,
                        );

                        // Name
                        painter.text(
                            rect.left_center() + Vec2::new(32.0, -8.0),
                            egui::Align2::LEFT_CENTER,
                            &conv.display_name,
                            egui::FontId::proportional(15.0),
                            tokens.palette.text_primary,
                        );

                        // Last message preview
                        if !conv.last_message.is_empty() {
                            let preview = if conv.last_message.len() > 40 {
                                format!("{}…", &conv.last_message[..40])
                            } else {
                                conv.last_message.clone()
                            };
                            painter.text(
                                rect.left_center() + Vec2::new(32.0, 10.0),
                                egui::Align2::LEFT_CENTER,
                                &preview,
                                egui::FontId::proportional(12.0),
                                tokens.palette.text_tertiary,
                            );
                        }

                        // Timestamp
                        if conv.last_time_sec > 0 {
                            let ts = format_time(conv.last_time_sec);
                            painter.text(
                                rect.right_center() + Vec2::new(-12.0, -8.0),
                                egui::Align2::RIGHT_CENTER,
                                &ts,
                                egui::FontId::proportional(11.0),
                                tokens.palette.text_disabled,
                            );
                        }

                        // Unread badge
                        if conv.unread > 0 {
                            let badge_rect = egui::Rect::from_center_size(
                                rect.right_center() + Vec2::new(-12.0, 10.0),
                                Vec2::new(20.0, 20.0),
                            );
                            painter.circle_filled(badge_rect.center(), 10.0, tokens.palette.accent);
                            painter.text(
                                badge_rect.center(),
                                egui::Align2::CENTER_CENTER,
                                conv.unread.to_string(),
                                egui::FontId::proportional(11.0),
                                tokens.palette.text_inverse,
                            );
                        }

                        // Separator line
                        painter.line_segment(
                            [
                                rect.left_bottom() + Vec2::new(32.0, 0.0),
                                rect.right_bottom(),
                            ],
                            egui::Stroke::new(0.5_f32, tokens.palette.border_subtle),
                        );

                        if response.clicked() {
                            state.open_chat = Some(conv.contact_id.clone());
                            state.page = Page::Chat;
                        }
                    }
                });
            });
    }

    fn show_contacts(&mut self, ctx: &Context, state: &mut AppState) {
        let tokens = DesignTokens::current();

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(tokens.palette.bg_primary))
            .show(ctx, |ui| {
                // Add contact form (toggleable)
                if self.show_add_contact_form {
                    design::card_frame(&tokens).show(ui, |ui| {
                        ui.label(
                            RichText::new("Add Contact")
                                .size(14.0)
                                .strong()
                                .color(tokens.palette.text_primary),
                    );
                    ui.add_space(tokens.spacing.xs);

                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Public Key:")
                                .size(12.0)
                                .color(tokens.palette.text_secondary),
                        );
                        let input_frame = design::input_frame(&tokens);
                        input_frame.show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.add_contact_key)
                                    .hint_text("Paste 64-char hex key…")
                                    .font(egui::FontId::monospace(12.0))
                                    .desired_width(ui.available_width() - 16.0)
                                    .margin(Vec2::new(8.0, 6.0)),
                            );
                        });
                    });

                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Name:")
                                .size(12.0)
                                .color(tokens.palette.text_secondary),
                        );
                        let input_frame = design::input_frame(&tokens);
                        input_frame.show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.add_contact_name)
                                    .hint_text("Display name…")
                                    .desired_width(ui.available_width() - 16.0)
                                    .margin(Vec2::new(8.0, 6.0)),
                            );
                        });
                    });

                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Address:")
                                .size(12.0)
                                .color(tokens.palette.text_secondary),
                        );
                        let input_frame = design::input_frame(&tokens);
                        input_frame.show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.add_contact_address)
                                    .hint_text("127.0.0.1:50051 (optional)")
                                    .desired_width(ui.available_width() - 16.0)
                                    .margin(Vec2::new(8.0, 6.0)),
                            );
                        });
                    });

                    // QR Scanner
                    ui.add_space(tokens.spacing.xs);
                    self.qr_scanner.show(ui, ctx);

                    // Auto-fill from QR scan
                    if let Some(key) = self.qr_scanner.decoded_key() {
                        if self.add_contact_key.is_empty() {
                            self.add_contact_key = key.to_owned();
                        }
                    }

                    if let Some(e) = &self.add_error {
                        ui.label(
                            RichText::new(format!("⚠ {e}"))
                                .color(tokens.palette.error)
                                .size(12.0),
                        );
                    }

                    let can_add =
                        self.add_contact_key.len() == 64
                        && self.add_contact_key.chars().all(|c| c.is_ascii_hexdigit())
                        && !self.add_contact_name.trim().is_empty();

                    let btn_color = if can_add {
                        tokens.palette.accent
                    } else {
                        tokens.palette.surface
                    };

                    let btn_text_color = if can_add {
                        tokens.palette.text_inverse
                    } else {
                        tokens.palette.text_disabled
                    };

                    if ui
                        .add_sized(
                            [120.0, 36.0],
                            egui::Button::new(
                                RichText::new("Add Contact")
                                    .size(13.0)
                                    .color(btn_text_color),
                            )
                            .fill(btn_color)
                            .rounding(tokens.spacing.button_rounding),
                        )
                        .clicked()
                        && can_add
                    {
                        let rt = tokio::runtime::Handle::current();
                            let address = if self.add_contact_address.trim().is_empty() {
                                None
                            } else {
                                Some(self.add_contact_address.trim().to_owned())
                            };
                            match rt.block_on(state.daemon.add_contact(
                                self.add_contact_key.trim().to_owned(),
                                self.add_contact_name.trim().to_owned(),
                                address,
                            )) {
                                Ok(_) => {
                                    self.add_contact_key.clear();
                                    self.add_contact_name.clear();
                                    self.add_contact_address.clear();
                                    self.add_error = None;
                                    // Refresh contacts and merge local nicknames
                                    let local_nicknames: std::collections::HashMap<String, Option<String>> = state.contacts
                                        .iter()
                                        .map(|c| (c.id.clone(), c.nickname.clone()))
                                        .collect();
                                    let mut new_contacts = rt.block_on(state.daemon.get_contacts());
                                    for c in &mut new_contacts {
                                        if let Some(nick) = local_nicknames.get(&c.id) {
                                            c.nickname = nick.clone();
                                        }
                                    }
                                    state.contacts = new_contacts;
                                    state.rebuild_conversations();
                                }
                                Err(e) => self.add_error = Some(e.to_string()),
                            }
                    }
                });
                } // end if show_add_contact_form

                ui.add_space(tokens.spacing.sm);

                // Contact list
                ScrollArea::vertical().show(ui, |ui| {
                    let mut action: Option<(ContactAction, String)> = None;
                    if state.contacts.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.add_space(ui.available_height() / 4.0);
                            ui.label(
                                RichText::new("👥")
                                    .size(48.0)
                                    .color(tokens.palette.text_disabled),
                            );
                            ui.add_space(tokens.spacing.sm);
                            ui.label(
                                RichText::new("No contacts yet")
                                    .size(16.0)
                                    .color(tokens.palette.text_secondary),
                            );
                        });
                        return;
                    }

                    for contact in &state.contacts {
                        let is_online = contact.online;
                        let display_name = contact.display_name().to_owned();
                        let contact_id = contact.id.clone();

                        let response = ui
                            .add_sized(
                                [ui.available_width(), 56.0],
                                egui::Button::new(RichText::new("").size(1.0))
                                    .fill(Color32::TRANSPARENT)
                                    .frame(false),
                            );

                        let rect = response.rect;
                        let painter = ui.painter();

                        // Online indicator
                        let dot_color = if is_online {
                            tokens.palette.success
                        } else {
                            tokens.palette.text_disabled
                        };
                        painter.circle_filled(
                            rect.left_center() + Vec2::new(16.0, 0.0),
                            5.0,
                            dot_color,
                        );

                        // Name
                        painter.text(
                            rect.left_center() + Vec2::new(30.0, 0.0),
                            egui::Align2::LEFT_CENTER,
                            &display_name,
                            egui::FontId::proportional(15.0),
                            tokens.palette.text_primary,
                        );

                        // Nickname indicator
                        if contact.nickname.is_some() {
                            let name_width = display_name.len() as f32 * 8.0;
                            painter.text(
                                rect.left_center() + Vec2::new(30.0 + name_width + 8.0, 0.0),
                                egui::Align2::LEFT_CENTER,
                                format!("({})", contact.name),
                                egui::FontId::proportional(11.0),
                                tokens.palette.text_disabled,
                            );
                        }

                        // Separator
                        painter.line_segment(
                            [
                                rect.left_bottom() + Vec2::new(16.0, 0.0),
                                rect.right_bottom(),
                            ],
                            egui::Stroke::new(0.5_f32, tokens.palette.border_subtle),
                        );

                        // Rename affordance on the right edge of the row.
                        let edit_btn = ui.put(
                            egui::Rect::from_min_size(
                                rect.right_top() - Vec2::new(36.0, 0.0),
                                Vec2::new(28.0, 28.0),
                            ),
                            egui::Button::new(RichText::new("✏️").size(13.0))
                                .frame(false),
                        );
                        if edit_btn.clicked() {
                            self.editing_nickname_for = Some(contact_id.clone());
                            self.nickname_input =
                                contact.nickname.clone().unwrap_or_default();
                        }

                        if response.clicked() {
                            state.open_chat = Some(contact_id.clone());
                            state.page = Page::Chat;
                        }

                        // Inline nickname editor when active for this contact.
                        if self.editing_nickname_for.as_deref() == Some(contact_id.as_str()) {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Nickname:").size(13.0));
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.nickname_input)
                                        .desired_width(140.0),
                                );
                                if ui.button("Save").clicked() {
                                    let nick = self.nickname_input.trim().to_owned();
                                    self.pending_nickname_save = Some((
                                        contact_id.clone(),
                                        if nick.is_empty() { None } else { Some(nick) },
                                    ));
                                    self.editing_nickname_for = None;
                                }
                                if ui.button("Clear").clicked() {
                                    self.pending_nickname_save = Some((contact_id.clone(), None));
                                    self.editing_nickname_for = None;
                                }
                                if ui.button("Cancel").clicked() {
                                    self.editing_nickname_for = None;
                                }
                            });
                        }

                        // Overflow menu ("⋯") toggle — to the left of the rename button.
                        let menu_btn = ui.put(
                            egui::Rect::from_min_size(
                                rect.right_top() - Vec2::new(70.0, 0.0),
                                Vec2::new(28.0, 28.0),
                            ),
                            egui::Button::new(RichText::new("⋯").size(15.0))
                                .frame(false),
                        );
                        if menu_btn.clicked() {
                            if self.contact_menu_for.as_deref() == Some(contact_id.as_str()) {
                                self.contact_menu_for = None;
                            } else {
                                self.contact_menu_for = Some(contact_id.clone());
                                self.confirm_remove = false;
                            }
                        }

                        // Contact action menu (block / unblock / remove / copy key).
                        if self.contact_menu_for.as_deref() == Some(contact_id.as_str()) {
                            let blocked = contact.blocked;
                            ui.horizontal(|ui| {
                                if ui
                                    .button(if blocked { "✅ Unblock" } else { "⛔ Block" })
                                    .clicked()
                                {
                                    action = Some((
                                        if blocked { ContactAction::Unblock } else { ContactAction::Block },
                                        contact_id.clone(),
                                    ));
                                }
                                if ui.button("⧉ Copy key").clicked() {
                                    action = Some((ContactAction::CopyKey, contact_id.clone()));
                                }
                                if !self.confirm_remove {
                                    if ui.button("🗑 Remove").clicked() {
                                        self.confirm_remove = true;
                                    }
                                } else if ui.button("Confirm remove?").clicked() {
                                    action = Some((ContactAction::Remove, contact_id.clone()));
                                }
                                if ui.button("Done").clicked() {
                                    self.contact_menu_for = None;
                                    self.confirm_remove = false;
                                }
                            });
                        }
                    }

                    // Apply any contact action after the immutable loop borrow ends.
                    if let Some((act, id)) = action {
                        match act {
                            ContactAction::Block | ContactAction::Unblock => {
                                let rt = tokio::runtime::Handle::current();
                                let result = if matches!(act, ContactAction::Block) {
                                    rt.block_on(state.daemon.block_contact(&id))
                                } else {
                                    rt.block_on(state.daemon.unblock_contact(&id))
                                };
                                if let Ok(updated) = result {
                                    if let Some(c) = state.contacts.iter_mut().find(|c| c.id == id) {
                                        c.blocked = updated.blocked;
                                    }
                                }
                            }
                            ContactAction::Remove => {
                                let rt = tokio::runtime::Handle::current();
                                let _ = rt.block_on(state.daemon.remove_contact(&id));
                                state.contacts.retain(|c| c.id != id);
                                state.message_previews.remove(&id);
                                state.rebuild_conversations();
                                if state.open_chat.as_deref() == Some(id.as_str()) {
                                    state.open_chat = None;
                                }
                            }
                            ContactAction::CopyKey => {
                                ui.output_mut(|o| o.copied_text = id.clone());
                            }
                        }
                        self.contact_menu_for = None;
                        self.confirm_remove = false;
                    }
                });
            });
    }

    fn show_transfers(&mut self, ctx: &Context, state: &mut AppState) {
        let tokens = DesignTokens::current();

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(tokens.palette.bg_primary))
            .show(ctx, |ui| {
                if state.transfers.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() / 3.0);
                        ui.label(
                            RichText::new("⬆⬇")
                                .size(48.0)
                                .color(tokens.palette.text_disabled),
                        );
                        ui.add_space(tokens.spacing.sm);
                        ui.label(
                            RichText::new("No active transfers")
                                .size(16.0)
                                .color(tokens.palette.text_secondary),
                        );
                        ui.add_space(tokens.spacing.xs);
                        ui.label(
                            RichText::new("Send a file to start a transfer")
                                .size(13.0)
                                .color(tokens.palette.text_tertiary),
                        );
                    });
                    return;
                }

                let mut pending_action: Option<crate::widgets::transfer_bar::TransferAction> = None;
                ScrollArea::vertical().show(ui, |ui| {
                    for t in &state.transfers {
                        if let Some(act) = transfer_bar(ui, t) {
                            pending_action = Some(act);
                        }
                        ui.add_space(tokens.spacing.xs);
                    }
                });
                if let Some(act) = pending_action {
                    let d = state.daemon.clone();
                    let rt = tokio::runtime::Handle::current();
                    match act.action {
                        TransferActionKind::Cancel => {
                            if rt.block_on(d.cancel_transfer(&act.transfer_id)).is_ok() {
                                state.transfers.retain(|t| t.id != act.transfer_id);
                            }
                        }
                        TransferActionKind::Pause => {
                            let _ = rt.block_on(d.pause_transfer(&act.transfer_id));
                            if let Some(t) = state.transfers.iter_mut().find(|t| t.id == act.transfer_id) {
                                t.paused = true;
                            }
                        }
                        TransferActionKind::Resume => {
                            let _ = rt.block_on(d.resume_transfer(&act.transfer_id));
                            if let Some(t) = state.transfers.iter_mut().find(|t| t.id == act.transfer_id) {
                                t.paused = false;
                            }
                        }
                    }
                }
            });
    }

    /// Drain any pending nickname save produced by the inline editor.
    pub fn take_pending_nickname_save(&mut self) -> Option<(String, Option<String>)> {
        self.pending_nickname_save.take()
    }
}

fn format_time(ts: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let diff = now.saturating_sub(ts);

    if diff < 60 {
        "now".to_string()
    } else if diff < 3600 {
        format!("{}m", diff / 60)
    } else if diff < 86400 {
        format!("{}h", diff / 3600)
    } else {
        format!("{}d", diff / 86400)
    }
}
