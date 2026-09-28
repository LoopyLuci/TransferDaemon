//! Settings page — identity info, QR code, theme, about.
//!
//! Redesigned with the new design system for a modern, accessible experience.

use crate::app::AppState;
use crate::design::{self, Accent, DesignTokens, Theme, UiPreferences};
use crate::widgets::qr_widget::QrWidget;
use egui::{Color32, Context, RichText, Ui, Vec2};

#[derive(Default)]
pub struct SettingsPage {
    qr: QrWidget,
    show_qr: bool,
    show_full_key: bool,
    show_phrase: bool,
    phrase_confirmed: bool,
    relay_enabled: bool,
    /// App-lock PIN entry (new PIN + confirm).
    pin_input: String,
    pin_input2: String,
    /// Pending app-lock action: `Some(Some(hash))` sets the PIN,
    /// `Some(None)` clears it. Drained by the home page.
    pending_pin: Option<Option<String>>,
    /// Last manual update-check result.
    update_status: Option<crate::types::UpdateStatus>,
    relay_status: String,
    relay_bandwidth_input: String,
    relay_settings_loaded: bool,
}

impl SettingsPage {
    pub fn show(&mut self, ui: &mut Ui, ctx: &Context, state: &mut AppState) {
        let tokens = DesignTokens::current();

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(tokens.spacing.md);

            // ── Identity Section ──────────────────────────────────────────────
            self.section_header(ui, "Identity", &tokens);

            if let Some(id) = &state.identity {
                design::card_frame(&tokens).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Display name:")
                                .color(tokens.palette.text_secondary),
                        );
                        ui.label(
                            RichText::new(&id.display_name)
                                .strong()
                                .color(tokens.palette.text_primary),
                        );
                    });
                    ui.add_space(tokens.spacing.xs);

                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Public key:")
                                .color(tokens.palette.text_secondary),
                        );
                        let display = if self.show_full_key {
                            id.public_key.clone()
                        } else {
                            truncate_key(&id.public_key)
                        };
                        ui.label(
                            RichText::new(&display)
                                .monospace()
                                .color(tokens.palette.text_primary),
                        );
                        if ui
                            .small_button(if self.show_full_key {
                                "Collapse"
                            } else {
                                "Expand"
                            })
                            .clicked()
                        {
                            self.show_full_key = !self.show_full_key;
                        }
                        if ui.small_button("Copy").clicked() {
                            ui.output_mut(|o| o.copied_text = id.public_key.clone());
                        }
                    });

                    if self.show_full_key {
                        ui.add_space(tokens.spacing.xs);
                        design::input_frame(&tokens).show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut id.public_key.clone())
                                    .font(egui::FontId::monospace(11.0))
                                    .desired_width(ui.available_width())
                                    .interactive(false)
                                    .margin(Vec2::new(8.0, 6.0)),
                            );
                        });
                        ui.label(
                            RichText::new(format!(
                                "{} hex chars (Ed25519 public key)",
                                id.public_key.len()
                            ))
                            .size(11.0)
                            .color(tokens.palette.text_disabled),
                        );
                    }

                    ui.add_space(tokens.spacing.sm);
                    if ui
                        .add_sized(
                            [ui.available_width(), 36.0],
                            egui::Button::new(
                                RichText::new(if self.show_qr {
                                    "Hide QR code"
                                } else {
                                    "Show QR code"
                                })
                                .color(tokens.palette.text_primary),
                            )
                            .fill(tokens.palette.surface)
                            .rounding(tokens.spacing.button_rounding),
                        )
                        .clicked()
                    {
                        self.show_qr = !self.show_qr;
                    }
                    if self.show_qr {
                        ui.add_space(tokens.spacing.sm);
                        ui.centered_and_justified(|ui| {
                            self.qr.show(ui, ctx, &id.public_key, 200.0);
                        });
                        ui.add_space(tokens.spacing.xs);
                        ui.label(
                            RichText::new("Share this QR code so others can add you as a contact.")
                                .size(12.0)
                                .color(tokens.palette.text_disabled),
                        );
                    }
                });
            } else {
                ui.label(
                    RichText::new("No identity set up.")
                        .color(tokens.palette.text_secondary),
                );
            }

            ui.add_space(tokens.spacing.lg);
            ui.separator();
            ui.add_space(tokens.spacing.sm);

            // ── Recovery Phrase Section ────────────────────────────────────────
            self.section_header(ui, "Recovery Phrase", &tokens);

            if state.recovery_phrase.is_some() {
                design::card_frame(&tokens).show(ui, |ui| {
                    if !self.show_phrase {
                        ui.label(
                            RichText::new("Your 12-word recovery phrase is available this session.")
                                .color(tokens.palette.text_secondary)
                                .size(13.0),
                        );
                        ui.add_space(tokens.spacing.sm);
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("⚠ Reveal Recovery Phrase")
                                        .color(tokens.palette.warning),
                                )
                                .fill(tokens.palette.surface)
                                .rounding(tokens.spacing.button_rounding),
                            )
                            .clicked()
                        {
                            self.phrase_confirmed = false;
                            self.show_phrase = true;
                        }
                    } else {
                        // Warning card
                        egui::Frame::none()
                            .fill(tokens.palette.error_subtle)
                            .rounding(tokens.spacing.card_rounding)
                            .inner_margin(Vec2::new(tokens.spacing.sm, tokens.spacing.xs))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new("⚠ Write these words down. Anyone with this phrase can access your identity.")
                                        .color(tokens.palette.error)
                                        .size(13.0),
                                );
                            });
                        ui.add_space(tokens.spacing.sm);

                        if let Some(phrase) = &state.recovery_phrase {
                            let words: Vec<&str> = phrase.split_whitespace().collect();
                            egui::Grid::new("settings_phrase_grid")
                                .num_columns(3)
                                .spacing([16.0, 6.0])
                                .show(ui, |ui| {
                                    for (i, word) in words.iter().enumerate() {
                                        egui::Frame::none()
                                            .fill(tokens.palette.bg_tertiary)
                                            .rounding(4.0)
                                            .inner_margin(Vec2::new(6.0, 3.0))
                                            .show(ui, |ui| {
                                                ui.label(
                                                    RichText::new(format!("{}. {}", i + 1, word))
                                                        .size(14.0)
                                                        .monospace()
                                                        .color(tokens.palette.text_primary),
                                                );
                                            });
                                        if (i + 1) % 3 == 0 {
                                            ui.end_row();
                                        }
                                    }
                                });
                            ui.add_space(tokens.spacing.sm);
                            if ui.small_button("Copy phrase").clicked() {
                                ui.output_mut(|o| o.copied_text = phrase.clone());
                            }
                        }
                        ui.add_space(tokens.spacing.sm);
                        if ui.small_button("Hide phrase").clicked() {
                            self.show_phrase = false;
                        }
                    }
                });
            } else {
                ui.label(
                    RichText::new(
                        "Recovery phrase is only available in the session when it was created.\n\
                         Restart the app and create a new identity to generate a new phrase.",
                    )
                    .size(13.0)
                    .color(tokens.palette.text_disabled),
                );
            }

            ui.add_space(tokens.spacing.lg);
            ui.separator();
            ui.add_space(tokens.spacing.sm);

            // ── Network Section ────────────────────────────────────────────────
            self.section_header(ui, "Network", &tokens);

            design::card_frame(&tokens).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Relay lanes:")
                            .color(tokens.palette.text_secondary),
                    );
                    ui.label(
                        RichText::new("1 active")
                            .color(tokens.palette.success),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Daemon:")
                            .color(tokens.palette.text_secondary),
                    );
                    if state.daemon_is_live {
                        ui.label(
                            RichText::new("gRPC (live)")
                                .color(tokens.palette.success)
                                .size(12.0),
                        );
                    } else {
                        ui.label(
                            RichText::new("Mock (offline)")
                                .color(tokens.palette.warning)
                                .size(12.0),
                        );
                    }
                });
            });

            // Load relay settings once on first render.
            if !self.relay_settings_loaded {
                self.relay_settings_loaded = true;
                let rt = tokio::runtime::Handle::current();
                self.relay_enabled = rt
                    .block_on(state.daemon.get_setting("relay.enabled"))
                    .map(|v| v == "true" || v == "1")
                    .unwrap_or(true);
                self.relay_bandwidth_input = rt
                    .block_on(state.daemon.get_setting("relay.bandwidth_kbps"))
                    .unwrap_or_else(|| "10000".into());
                self.relay_status = rt
                    .block_on(state.daemon.get_setting("relay.status"))
                    .unwrap_or_else(|| "stopped".into());
            }

            ui.add_space(tokens.spacing.sm);

            // ── Relay Mesh Section ─────────────────────────────────────────────
            self.section_header(ui, "Relay Mesh", &tokens);

            design::card_frame(&tokens).show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "Embedded anonymous relay — lets other TransferDaemon peers route through this node.",
                    )
                    .size(12.0)
                    .color(tokens.palette.text_disabled),
                );
                ui.add_space(tokens.spacing.xs);

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Enable relay:")
                            .color(tokens.palette.text_secondary),
                    );
                    let mut toggled = self.relay_enabled;
                    if ui.checkbox(&mut toggled, "").changed() {
                        self.relay_enabled = toggled;
                        let rt = tokio::runtime::Handle::current();
                        let val = if toggled { "true" } else { "false" };
                        let _ = rt.block_on(
                            state.daemon.set_setting("relay.enabled", val),
                        );
                        self.relay_settings_loaded = false;
                        ctx.request_repaint();
                    }
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Bandwidth cap (kbps):")
                            .color(tokens.palette.text_secondary),
                    );
                    let input_frame = design::input_frame(&tokens);
                    input_frame.show(ui, |ui| {
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut self.relay_bandwidth_input)
                                .desired_width(80.0)
                                .margin(Vec2::new(8.0, 6.0)),
                        );
                        if response.lost_focus() {
                            let rt = tokio::runtime::Handle::current();
                            let _ = rt.block_on(state.daemon.set_setting(
                                "relay.bandwidth_kbps",
                                &self.relay_bandwidth_input,
                            ));
                        }
                    });
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Status:")
                            .color(tokens.palette.text_secondary),
                    );
                    let (color, label) = if self.relay_status.starts_with("running") {
                        (tokens.palette.success, self.relay_status.as_str())
                    } else {
                        (tokens.palette.error, "stopped")
                    };
                    ui.label(
                        RichText::new(label).color(color).size(12.0),
                    );
                    if ui.small_button("Refresh").clicked() {
                        let rt = tokio::runtime::Handle::current();
                        self.relay_status = rt
                            .block_on(state.daemon.get_setting("relay.status"))
                            .unwrap_or_else(|| "stopped".into());
                    }
                });
            });

            ui.add_space(tokens.spacing.lg);
            ui.separator();
            ui.add_space(tokens.spacing.sm);

            // ── Appearance Section ─────────────────────────────────────────────────
            self.section_header(ui, "Appearance", &tokens);

            // The settings page edits a copy of the prefs; any change is
            // pushed back as a `pending_appearance` that the app applies +
            // persists next frame.
            let mut prefs = state.prefs;

            design::card_frame(&tokens).show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                // ── Theme ──────────────────────────────────────────────────
                ui.label(
                    RichText::new("Theme")
                        .size(14.0)
                        .strong()
                        .color(tokens.palette.text_primary),
                );
                ui.add_space(tokens.spacing.xs);
                ui.horizontal_wrapped(|ui| {
                    for (theme, label) in [
                        (Theme::Oled, "OLED"),
                        (Theme::Dark, "Dark"),
                        (Theme::Light, "Light"),
                        (Theme::HighContrast, "High Contrast"),
                    ] {
                        let is_active = prefs.theme == theme;
                        let bg = if is_active {
                            tokens.palette.accent
                        } else {
                            tokens.palette.surface
                        };
                        let text_color = if is_active {
                            tokens.palette.text_inverse
                        } else {
                            tokens.palette.text_primary
                        };
                        if ui
                            .add_sized(
                                [82.0, 34.0],
                                egui::Button::new(
                                    RichText::new(label)
                                        .size(11.0)
                                        .color(text_color),
                                )
                                .fill(bg)
                                .rounding(8.0),
                            )
                            .clicked()
                        {
                            prefs = prefs.with_theme(theme);
                        }
                    }
                });

                ui.add_space(tokens.spacing.md);
                ui.separator();
                ui.add_space(tokens.spacing.sm);

                // ── Accent color ───────────────────────────────────────────
                ui.label(
                    RichText::new("Accent color")
                        .size(14.0)
                        .strong()
                        .color(tokens.palette.text_primary),
                );
                ui.add_space(tokens.spacing.xs);
                ui.horizontal_wrapped(|ui| {
                    for accent in Accent::ALL {
                        let is_active = prefs.accent == accent;
                        let c = accent.color();
                        let fill = if is_active {
                            c
                        } else {
                            c.gamma_multiply(0.45)
                        };
                        let ring = if is_active {
                            tokens.palette.text_primary
                        } else {
                            Color32::TRANSPARENT
                        };
                        let r = ui
                            .add_sized(
                                [34.0, 34.0],
                                egui::Button::new("")
                                    .fill(fill)
                                    .stroke(egui::Stroke::new(2.0_f32, ring))
                                    .rounding(17.0),
                            )
                            .on_hover_text(accent.label());
                        if r.clicked() {
                            prefs = prefs.with_accent(accent);
                        }
                    }
                });

                ui.add_space(tokens.spacing.md);
                ui.separator();
                ui.add_space(tokens.spacing.sm);

                // ── UI scaling ─────────────────────────────────────────────
                self.scale_control(
                    ui,
                    &tokens,
                    "UI scaling",
                    "Zooms the whole interface — layouts, buttons and spacing.",
                    &mut prefs.ui_scale,
                    &UiPreferences::UI_SCALE_PRESETS,
                    UiPreferences::UI_SCALE_RANGE,
                );

                ui.add_space(tokens.spacing.md);
                ui.separator();
                ui.add_space(tokens.spacing.sm);

                // ── Text size ──────────────────────────────────────────────
                self.scale_control(
                    ui,
                    &tokens,
                    "Text size",
                    "Makes text larger without changing the layout density.",
                    &mut prefs.font_scale,
                    &UiPreferences::FONT_SCALE_PRESETS,
                    UiPreferences::FONT_SCALE_RANGE,
                );
            });

            // Push any change back to the app (applies + persists next frame).
            if prefs != state.prefs {
                state.prefs = prefs;
                ctx.data_mut(|d| {
                    d.insert_persisted(
                        egui::Id::new("pending_appearance"),
                        prefs,
                    );
                });
            }

            ui.add_space(tokens.spacing.lg);
            ui.separator();
            ui.add_space(tokens.spacing.sm);

            // ── About Section ──────────────────────────────────────────────────
            self.section_header(ui, "About", &tokens);

            design::card_frame(&tokens).show(ui, |ui| {
                ui.label(
                    RichText::new("TransferDaemon")
                        .strong()
                        .color(tokens.palette.text_primary),
                );
                ui.label(
                    RichText::new("Version 1.0.0")
                        .color(tokens.palette.text_secondary),
                );
                ui.add_space(tokens.spacing.xs);
                ui.label(
                    RichText::new(
                        "Sovereign, zero-knowledge, universal data transfer.\n\
                         No third-party services. No telemetry. No compromise.",
                    )
                    .size(13.0)
                    .color(tokens.palette.text_disabled),
                );
            });

            ui.add_space(tokens.spacing.sm);

            // ── App lock (privacy) ─────────────────────────────────────────────
            self.section_header(ui, "App lock", &tokens);
            design::card_frame(&tokens).show(ui, |ui| {
                if state.pin_hash.is_some() {
                    ui.label(
                        RichText::new("A PIN lock is active — the app requests it on launch.")
                            .size(13.0)
                            .color(tokens.palette.text_secondary),
                    );
                    ui.add_space(tokens.spacing.xs);
                    if ui
                        .add_sized(
                            [160.0, 34.0],
                            egui::Button::new(
                                RichText::new("Remove PIN lock")
                                    .color(tokens.palette.text_primary),
                            )
                            .fill(tokens.palette.surface)
                            .rounding(tokens.spacing.button_rounding),
                        )
                        .clicked()
                    {
                        self.pending_pin = Some(None);
                    }
                } else {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("New PIN:")
                                .size(13.0)
                                .color(tokens.palette.text_secondary),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.pin_input)
                                .password(true)
                                .desired_width(140.0),
                        );
                    });
                    ui.add_space(tokens.spacing.xxs);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Confirm:")
                                .size(13.0)
                                .color(tokens.palette.text_secondary),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.pin_input2)
                                .password(true)
                                .desired_width(140.0),
                        );
                    });
                    ui.add_space(tokens.spacing.xxs);
                    let can_set = !self.pin_input.is_empty()
                        && self.pin_input.len() >= 4
                        && self.pin_input == self.pin_input2;
                    ui.add_enabled_ui(can_set, |ui| {
                        if ui
                            .add_sized(
                                [160.0, 34.0],
                                egui::Button::new(
                                    RichText::new("Set PIN lock")
                                        .color(tokens.palette.text_inverse),
                                )
                                .fill(tokens.palette.accent)
                                .rounding(tokens.spacing.button_rounding),
                            )
                            .clicked()
                        {
                            let hash = blake3::hash(self.pin_input.as_bytes()).to_hex().to_string();
                            self.pending_pin = Some(Some(hash));
                            self.pin_input.clear();
                            self.pin_input2.clear();
                        }
                    });
                    if !can_set && !self.pin_input.is_empty() {
                        ui.label(
                            RichText::new("PIN must be 4+ digits and match the confirmation.")
                                .size(11.0)
                                .color(tokens.palette.text_disabled),
                        );
                    }
                }
            });

            ui.add_space(tokens.spacing.sm);

            // ── Updates (manual, opt-in) ───────────────────────────────────────
            self.section_header(ui, "Updates", &tokens);
            design::card_frame(&tokens).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Check for updates manually — TransferDaemon never phones home automatically.")
                            .size(12.0)
                            .color(tokens.palette.text_disabled),
                    );
                });
                ui.add_space(tokens.spacing.xs);
                if ui
                        .add_sized(
                            [180.0, 34.0],
                            egui::Button::new(
                                RichText::new("Check for updates")
                                    .color(tokens.palette.text_inverse),
                            )
                            .fill(tokens.palette.accent)
                            .rounding(tokens.spacing.button_rounding),
                        )
                        .clicked()
                    {
                        let rt = tokio::runtime::Handle::current();
                        let status = rt.block_on(state.daemon.check_for_updates());
                        self.update_status = Some(status);
                    }
                if let Some(u) = &self.update_status {
                    ui.add_space(tokens.spacing.xs);
                    if !u.current_version.is_empty() {
                        ui.label(
                            RichText::new(format!("Current version: {}", u.current_version))
                                .size(12.0)
                                .color(tokens.palette.text_secondary),
                        );
                    }
                    if u.has_update {
                        ui.label(
                            RichText::new(format!("Update available: {}", u.new_version))
                                .size(13.0)
                                .strong()
                                .color(tokens.palette.accent),
                        );
                        if !u.release_notes.is_empty() {
                            ui.add_space(tokens.spacing.xxs);
                            ui.label(
                                RichText::new(&u.release_notes)
                                    .size(11.0)
                                    .color(tokens.palette.text_disabled),
                            );
                        }
                        ui.add_space(tokens.spacing.xs);
                        if ui
                            .add_sized(
                                [180.0, 34.0],
                                egui::Button::new(
                                    RichText::new("Download & install")
                                        .color(tokens.palette.text_inverse),
                                )
                                .fill(tokens.palette.accent)
                                .rounding(tokens.spacing.button_rounding),
                            )
                            .clicked()
                        {
                            let rt = tokio::runtime::Handle::current();
                            let _ = rt.block_on(state.daemon.apply_update());
                        }
                    } else if !u.error.is_empty() {
                        ui.label(
                            RichText::new(format!("Update check failed: {}", u.error))
                                .size(12.0)
                                .color(tokens.palette.error),
                        );
                    } else {
                        ui.label(
                            RichText::new("You're up to date.")
                                .size(12.0)
                                .color(tokens.palette.success),
                        );
                    }
                }
            });

            ui.add_space(tokens.spacing.xl);
        });
    }

    /// Drain a pending app-lock action: `Some(Some(hash))` set, `Some(None)` clear.
    pub fn take_pending_pin(&mut self) -> Option<Option<String>> {
        self.pending_pin.take()
    }

    fn section_header(&self, ui: &mut Ui, title: &str, tokens: &DesignTokens) {
        ui.label(
            RichText::new(title.to_uppercase())
                .size(12.0)
                .strong()
                .color(tokens.palette.text_disabled),
        );
        ui.add_space(tokens.spacing.xs);
    }

    /// A polished scaling control: title + "Default" reset, a row of preset
    /// quick-picks, then a slider with a manual numeric input beside it.
    #[allow(clippy::too_many_arguments)]
    fn scale_control(
        &self,
        ui: &mut Ui,
        tokens: &DesignTokens,
        title: &str,
        hint: &str,
        value: &mut f32,
        presets: &[(&'static str, f32)],
        range: std::ops::RangeInclusive<f32>,
    ) {
        // Title + Default reset.
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(title)
                    .size(14.0)
                    .strong()
                    .color(tokens.palette.text_primary),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .small_button("Default")
                    .on_hover_text("Back to the comfortable default")
                    .clicked()
                {
                    *value = 1.1;
                }
            });
        });
        ui.add_space(tokens.spacing.xs);

        // Preset quick-picks (segmented).
        ui.horizontal_wrapped(|ui| {
            let active = UiPreferences::active_preset(*value, presets);
            for (label, v) in presets {
                let is_active = active == Some(*label);
                let bg = if is_active {
                    tokens.palette.accent
                } else {
                    tokens.palette.surface
                };
                let text_color = if is_active {
                    tokens.palette.text_inverse
                } else {
                    tokens.palette.text_primary
                };
                let btn = egui::Button::new(
                    RichText::new(*label)
                        .size(11.0)
                        .strong()
                        .color(text_color),
                )
                .fill(bg)
                .stroke(egui::Stroke::new(
                    1.0_f32,
                    if is_active {
                        tokens.palette.accent
                    } else {
                        tokens.palette.border_subtle
                    },
                ))
                .rounding(8.0)
                .min_size(egui::vec2(0.0, 30.0));
                if ui
                    .add_sized([72.0, 30.0], btn)
                    .on_hover_text(format!("{title}: {v:.2}\u{00d7}"))
                    .clicked()
                {
                    *value = *v;
                }
            }
        });
        ui.add_space(tokens.spacing.xs);

        // Slider + manual input.
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("A")
                    .size(11.0)
                    .color(tokens.palette.text_tertiary),
            );
            ui.add(
                egui::Slider::new(value, range.clone())
                    .step_by(0.05)
                    .fixed_decimals(2)
                    .show_value(false),
            );
            ui.add(
                egui::DragValue::new(value)
                    .range(range)
                    .speed(0.01)
                    .fixed_decimals(2)
                    .suffix("\u{00d7}"),
            );
            ui.label(
                RichText::new("A")
                    .size(17.0)
                    .color(tokens.palette.text_tertiary),
            );
        });
        ui.add_space(tokens.spacing.xxs);
        ui.label(
            RichText::new(hint)
                .size(11.0)
                .color(tokens.palette.text_tertiary),
        );
        ui.add_space(tokens.spacing.md);
    }
}

fn truncate_key(key: &str) -> String {
    if key.len() <= 16 {
        return key.to_owned();
    }
    format!("{}…{}", &key[..8], &key[key.len() - 8..])
}
