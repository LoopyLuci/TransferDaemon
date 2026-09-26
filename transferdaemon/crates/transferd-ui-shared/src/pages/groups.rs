//! Groups — the Groups tab (list + create) and the group chat page.

use crate::app::{AppState, Page};
use crate::design::{self, DesignTokens};
use crate::types::Message;
use crate::widgets::message_bubble::message_bubble;
use egui::{RichText, ScrollArea};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Groups tab (embedded in the Home page)
// ---------------------------------------------------------------------------

pub struct GroupsPage {
    /// Create-group form state.
    pub show_create: bool,
    pub new_name: String,
    pub new_member_ids: Vec<String>,
    pub error: Option<String>,
    last_refresh: Instant,
}

impl Default for GroupsPage {
    fn default() -> Self {
        Self {
            show_create: false,
            new_name: String::new(),
            new_member_ids: Vec::new(),
            error: None,
            last_refresh: Instant::now()
                .checked_sub(std::time::Duration::from_secs(5))
                .unwrap_or_else(Instant::now),
        }
    }
}

impl GroupsPage {
    /// Render the groups list + create form inside the Home tab area.
    pub fn show(&mut self, ui: &mut egui::Ui, state: &mut AppState) {
        let tokens = DesignTokens::current();
        ui.add_space(tokens.spacing.sm);

        // Header row: title + "New group" toggle.
        ui.horizontal(|ui| {
            ui.label(RichText::new("👥 Groups").size(16.0).color(tokens.palette.text_primary));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("+ New group").clicked() {
                    self.show_create = !self.show_create;
                    self.error = None;
                }
            });
        });
        ui.add_space(tokens.spacing.sm);

        // Create form.
        if self.show_create {
            design::card_frame(&tokens).show(ui, |ui| {
                ui.label(RichText::new("Group name").size(13.0));
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_name)
                        .hint_text("e.g. Project Alpha")
                        .desired_width(ui.available_width() * 0.7),
                );
                ui.add_space(tokens.spacing.sm);
                ui.label(RichText::new("Members (add from contacts)").size(13.0));
                ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
                    for c in &state.contacts {
                        let selected = self.new_member_ids.contains(&c.id);
                        if ui.selectable_label(selected, c.display_name()).clicked() {
                            if selected {
                                self.new_member_ids.retain(|x| x != &c.id);
                            } else {
                                self.new_member_ids.push(c.id.clone());
                            }
                        }
                    }
                });
                ui.add_space(tokens.spacing.sm);
                if let Some(err) = &self.error {
                    ui.colored_label(tokens.palette.error, err);
                }
                ui.horizontal(|ui| {
                    if ui.button("Create").clicked() {
                        let name = self.new_name.trim().to_owned();
                        if name.is_empty() {
                            self.error = Some("Group name required".into());
                        } else {
                            let rt = tokio::runtime::Handle::current();
                            let members = self.new_member_ids.clone();
                            match rt.block_on(state.daemon.create_group(name, members)) {
                                Ok(g) => {
                                    self.new_name.clear();
                                    self.new_member_ids.clear();
                                    self.show_create = false;
                                    state.groups.push(g.clone());
                                    state.open_group = Some(g.id);
                                    state.page = Page::GroupChat;
                                }
                                Err(e) => self.error = Some(e.to_string()),
                            }
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.show_create = false;
                        self.error = None;
                    }
                });
            });
            ui.add_space(tokens.spacing.sm);
        }

        // Refresh groups periodically so member changes appear.
        if self.last_refresh.elapsed() >= std::time::Duration::from_secs(3) {
            self.last_refresh = Instant::now();
            let rt = tokio::runtime::Handle::current();
            let groups = rt.block_on(state.daemon.get_groups());
            state.groups = groups;
        }

        // Group list.
        if state.groups.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() / 4.0);
                ui.label(RichText::new("👥").size(48.0).color(tokens.palette.text_disabled));
                ui.add_space(tokens.spacing.sm);
                ui.label(
                    RichText::new("No groups yet — create one to start chatting together")
                        .size(14.0)
                        .color(tokens.palette.text_secondary),
                );
            });
            return;
        }

        ScrollArea::vertical().show(ui, |ui| {
            let groups = state.groups.clone();
            for g in &groups {
                let name = g.name.clone();
                let member_count = g.members.len();
                let gid = g.id.clone();
                if ui
                    .add_sized(
                        [ui.available_width(), 52.0],
                        egui::Button::new(
                            RichText::new(format!("👥 {name}  ·  {member_count} members"))
                                .size(14.0)
                                .color(tokens.palette.text_primary),
                        )
                        .fill(tokens.palette.surface)
                        .rounding(tokens.spacing.button_rounding),
                    )
                    .clicked()
                {
                    state.open_group = Some(gid);
                    state.page = Page::GroupChat;
                }
                ui.add_space(tokens.spacing.xs);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Group chat page
// ---------------------------------------------------------------------------

pub struct GroupChatPage {
    input: String,
    messages: Vec<Message>,
    seen_ids: std::collections::HashSet<String>,
    last_group_id: String,
    last_poll: Instant,
    scroll_to_bottom: bool,
    show_members: bool,
    rename_mode: bool,
    rename_input: String,
}

impl Default for GroupChatPage {
    fn default() -> Self {
        Self {
            input: String::new(),
            messages: Vec::new(),
            seen_ids: std::collections::HashSet::new(),
            last_group_id: String::new(),
            last_poll: Instant::now(),
            scroll_to_bottom: true,
            show_members: false,
            rename_mode: false,
            rename_input: String::new(),
        }
    }
}

impl GroupChatPage {
    pub fn enter(&mut self, state: &mut AppState) {
        if let Some(gid) = state.open_group.clone() {
            if gid != self.last_group_id {
                self.messages.clear();
                self.seen_ids.clear();
                self.last_group_id = gid.clone();
                self.last_poll = Instant::now()
                    .checked_sub(std::time::Duration::from_secs(2))
                    .unwrap_or_else(Instant::now);
                self.scroll_to_bottom = true;
                self.show_members = false;
                self.rename_mode = false;
                self.input.clear();
            }
            // Poll group messages.
            if self.last_poll.elapsed() >= std::time::Duration::from_millis(500) {
                self.last_poll = Instant::now();
                let rt = tokio::runtime::Handle::current();
                let all = rt.block_on(state.daemon.get_group_messages(&gid));
                for m in all {
                    if self.seen_ids.insert(m.id.clone()) {
                        self.messages.push(m);
                        self.scroll_to_bottom = true;
                    }
                }
            }
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, state: &mut AppState) {
        let tokens = DesignTokens::current();
        let Some(gid) = state.open_group.clone() else { return };

        // Resolve the group (fresh copy from state).
        let group = state.groups.iter().find(|g| g.id == gid).cloned();

        // Header.
        egui::TopBottomPanel::top("group_chat_header")
            .exact_height(52.0)
            .frame(design::panel_frame(&tokens).fill(tokens.palette.chat_header))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .add_sized(
                            [40.0, 40.0],
                            egui::Button::new(RichText::new("←").size(18.0)).frame(false),
                        )
                        .clicked()
                    {
                        state.open_group = None;
                        state.page = Page::Home;
                    }
                    if let Some(g) = &group {
                        if self.rename_mode {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.rename_input)
                                    .desired_width(160.0),
                            );
                            if ui.button("Save").clicked() {
                                let rt = tokio::runtime::Handle::current();
                                let _ = rt.block_on(state.daemon.rename_group(&gid, self.rename_input.clone()));
                                let groups = rt.block_on(state.daemon.get_groups());
                                state.groups = groups;
                                self.rename_mode = false;
                            }
                        } else {
                            ui.label(
                                RichText::new(&g.name)
                                    .size(17.0)
                                    .color(tokens.palette.text_primary),
                            );
                            ui.label(
                                RichText::new(format!(" · {} members", g.members.len()))
                                    .size(12.0)
                                    .color(tokens.palette.text_secondary),
                            );
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("👥").clicked() {
                            self.show_members = !self.show_members;
                        }
                        if ui.button("✏️").clicked() {
                            self.rename_mode = !self.rename_mode;
                            self.rename_input = group.as_ref().map(|g| g.name.clone()).unwrap_or_default();
                        }
                    });
                });
            });

        // Members panel.
        if self.show_members {
            if let Some(g) = &group {
                egui::TopBottomPanel::top("group_members")
                    .exact_height(200.0)
                    .frame(design::panel_frame(&tokens).fill(tokens.palette.bg_secondary))
                    .show_inside(ui, |ui| {
                        ui.label(RichText::new("Members").size(14.0).strong());
                        ScrollArea::vertical().show(ui, |ui| {
                            for m in &g.members {
                                ui.horizontal(|ui| {
                                    ui.label(format!("{} — {}", m.public_key.chars().take(12).collect::<String>(), m.role_name()));
                                });
                            }
                        });
                        // Remove member buttons (for members who aren't the owner of this view).
                        ui.add_space(tokens.spacing.sm);
                        for m in &g.members {
                            let pk = m.public_key.clone();
                            if ui
                                .small_button(format!("Remove {}", pk.chars().take(10).collect::<String>()))
                                .clicked()
                            {
                                let rt = tokio::runtime::Handle::current();
                                let _ = rt.block_on(state.daemon.remove_group_members(&gid, vec![pk]));
                                let groups = rt.block_on(state.daemon.get_groups());
                                state.groups = groups;
                            }
                        }
                    });
            }
        }

        // Message list + composer.
        egui::CentralPanel::default()
            .frame(design::panel_frame(&tokens).fill(tokens.palette.bg_primary))
            .show_inside(ui, |ui| {
                let bubble_max_w = ui.available_width() * 0.78;
                let mut scroll = ScrollArea::vertical().auto_shrink([false, false]);
                if self.scroll_to_bottom {
                    scroll = scroll.vertical_scroll_offset(f32::MAX);
                    self.scroll_to_bottom = false;
                }
                scroll.show(ui, |ui| {
                    ui.add_space(tokens.spacing.sm);
                    if self.messages.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.label(
                                RichText::new("No messages yet — say hello!")
                                    .color(tokens.palette.text_secondary),
                            );
                        });
                    }
                    for m in &self.messages {
                        let label = if m.outbound {
                            "You".to_string()
                        } else {
                            m.sender_pk.as_deref()
                                .map(|s| s.chars().take(10).collect::<String>())
                                .unwrap_or_else(|| "Member".into())
                        };
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(label)
                                    .size(11.0)
                                    .color(tokens.palette.text_disabled),
                            );
                        });
                        message_bubble(ui, m, bubble_max_w, Some(tokens.palette.accent), &self.messages);
                        ui.add_space(tokens.spacing.xxs);
                    }
                    ui.add_space(tokens.spacing.sm);
                });

                // Composer.
                egui::TopBottomPanel::bottom("group_composer")
                    .exact_height(52.0)
                    .frame(design::panel_frame(&tokens).fill(tokens.palette.bg_secondary))
                    .show_inside(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.input)
                                    .hint_text("Message the group…")
                                    .desired_width(ui.available_width() - 70.0),
                            );
                            let send = ui.button("➤").clicked()
                                || (ui.input(|i| i.key_pressed(egui::Key::Enter))
                                    && !self.input.trim().is_empty());
                            if send && !self.input.trim().is_empty() {
                                let text = self.input.trim().to_owned();
                                self.input.clear();
                                let rt = tokio::runtime::Handle::current();
                                match rt.block_on(state.daemon.send_group_text(&gid, text)) {
                                    Ok(m) => {
                                        if self.seen_ids.insert(m.id.clone()) {
                                            self.messages.push(m);
                                            self.scroll_to_bottom = true;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("[group] send failed: {e}");
                                    }
                                }
                            }
                        });
                    });
            });
    }
}