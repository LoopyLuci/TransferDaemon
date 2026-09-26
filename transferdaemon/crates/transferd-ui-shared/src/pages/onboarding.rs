//! Onboarding page — create or restore a TransferDaemon identity.
//!
//! Redesigned with the new design system for a modern, accessible experience.

use crate::app::{AppState, Page};
use crate::animations::Fade;
use crate::design::{self, DesignTokens};
use crate::platform_hooks;
use egui::{Context, RichText, Ui, Vec2};

// Minimum tap target size — comfortable on mobile, fine on desktop.
const BTN: [f32; 2] = [280.0, 52.0];

#[derive(Default, PartialEq)]
enum Step {
    #[default]
    Welcome,
    CreateName,
    ShowPhrase,
    Restore,
}

#[derive(Default)]
pub struct OnboardingPage {
    step: Step,
    display_name: String,
    phrase_input: String,
    recovery_phrase: String,
    error: Option<String>,
    /// True on the first frame of a step that has a text field — triggers focus + IME.
    focus_requested: bool,
    /// Set to the expiry instant when the user taps "Copy"; drives the "Copied!" label.
    copy_feedback_until: Option<std::time::Instant>,
    /// Animation state for page transitions.
    #[allow(dead_code)]
    fade: Fade,
}

impl OnboardingPage {
    pub fn show(&mut self, ui: &mut Ui, _ctx: &Context, state: &mut AppState) {
        let tokens = DesignTokens::current();

        ui.vertical_centered(|ui| {
            ui.add_space(tokens.spacing.xl);

            // Logo / brand area
            ui.label(
                RichText::new("🔒")
                    .size(48.0)
                    .color(tokens.palette.accent),
            );
            ui.add_space(tokens.spacing.sm);

            match self.step {
                Step::Welcome    => self.show_welcome(ui, &tokens),
                Step::CreateName => self.show_create_name(ui, state, &tokens),
                Step::ShowPhrase => self.show_phrase(ui, state, &tokens),
                Step::Restore    => self.show_restore(ui, state, &tokens),
            }
        });
    }

    fn show_welcome(&mut self, ui: &mut Ui, tokens: &DesignTokens) {
        ui.label(
            RichText::new("TransferDaemon")
                .size(36.0)
                .strong()
                .color(tokens.palette.text_primary),
        );
        ui.add_space(tokens.spacing.xs);
        ui.label(
            RichText::new("Sovereign. Zero-knowledge. Universal transfer.")
                .size(16.0)
                .color(tokens.palette.text_secondary),
        );
        ui.add_space(tokens.spacing.xl * 1.5);

        // Primary action
        if ui
            .add_sized(
                BTN,
                egui::Button::new(
                    RichText::new("Create new identity")
                        .size(16.0)
                        .color(tokens.palette.text_inverse),
                )
                .fill(tokens.palette.accent)
                .rounding(tokens.spacing.button_rounding),
            )
            .clicked()
        {
            self.step = Step::CreateName;
            self.focus_requested = true;
        }
        ui.add_space(tokens.spacing.sm);

        // Secondary action
        if ui
            .add_sized(
                BTN,
                egui::Button::new(
                    RichText::new("Restore from phrase")
                        .size(16.0)
                        .color(tokens.palette.text_primary),
                )
                .fill(tokens.palette.surface)
                .rounding(tokens.spacing.button_rounding),
            )
            .clicked()
        {
            self.step = Step::Restore;
            self.focus_requested = true;
        }

        ui.add_space(tokens.spacing.xl);

        // Security badge
        egui::Frame::none()
            .fill(tokens.palette.bg_tertiary)
            .rounding(tokens.spacing.card_rounding)
            .inner_margin(Vec2::new(tokens.spacing.md, tokens.spacing.sm))
            .show(ui, |ui| {
                ui.set_max_width(BTN[0]);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🛡").size(14.0));
                    ui.label(
                        RichText::new("End-to-end encrypted • No servers • No tracking")
                            .size(11.0)
                            .color(tokens.palette.text_tertiary),
                    );
                });
            });
    }

    fn show_create_name(&mut self, ui: &mut Ui, state: &mut AppState, tokens: &DesignTokens) {
        ui.label(
            RichText::new("Choose a display name")
                .size(24.0)
                .strong()
                .color(tokens.palette.text_primary),
        );
        ui.add_space(tokens.spacing.xs);
        ui.label(
            RichText::new("This is only shown to people you choose to share it with.")
                .size(14.0)
                .color(tokens.palette.text_secondary),
        );
        ui.add_space(tokens.spacing.lg);

        // Input field with proper styling
        let input_frame = design::input_frame(tokens);
        input_frame.show(ui, |ui| {
            let te = egui::TextEdit::singleline(&mut self.display_name)
                .hint_text("Display name…")
                .font(egui::FontId::proportional(16.0))
                .desired_width(300.0)
                .margin(Vec2::new(8.0, 8.0));
            let response = ui.add(te);

            // On the first frame of this step, grab focus so the Android IME appears.
            if self.focus_requested {
                response.request_focus();
                self.focus_requested = false;
                platform_hooks::request_show_keyboard();
                ui.ctx().request_repaint();
            }
        });

        if let Some(e) = &self.error {
            ui.add_space(tokens.spacing.xs);
            egui::Frame::none()
                .fill(tokens.palette.error_subtle)
                .rounding(tokens.spacing.button_rounding)
                .inner_margin(Vec2::new(tokens.spacing.sm, tokens.spacing.xs))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!("⚠ {e}"))
                            .color(tokens.palette.error)
                            .size(13.0),
                    );
                });
        }

        ui.add_space(tokens.spacing.lg);

        let can_continue = !self.display_name.trim().is_empty();
        ui.add_enabled_ui(can_continue, |ui| {
            if ui
                .add_sized(
                    BTN,
                    egui::Button::new(
                        RichText::new("Continue")
                            .size(16.0)
                            .color(tokens.palette.text_inverse),
                    )
                    .fill(tokens.palette.accent)
                    .rounding(tokens.spacing.button_rounding),
                )
                .clicked()
            {
                let name = self.display_name.trim().to_owned();
                let rt = tokio::runtime::Handle::current();
                match rt.block_on(state.daemon.create_identity(name)) {
                    Ok(p) => {
                        self.recovery_phrase = p.clone();
                        state.recovery_phrase = Some(p);
                        state.identity = rt.block_on(state.daemon.get_identity());
                        self.step = Step::ShowPhrase;
                    }
                    Err(e) => self.error = Some(e.to_string()),
                }
            }
        });
        ui.add_space(tokens.spacing.sm);

        if ui
            .add_sized(
                [BTN[0], 40.0],
                egui::Button::new(
                    RichText::new("← Back")
                        .size(14.0)
                        .color(tokens.palette.text_secondary),
                )
                .fill(tokens.palette.surface)
                .rounding(tokens.spacing.button_rounding),
            )
            .clicked()
        {
            self.step = Step::Welcome;
        }
    }

    fn show_phrase(&mut self, ui: &mut Ui, state: &mut AppState, tokens: &DesignTokens) {
        ui.label(
            RichText::new("Your recovery phrase")
                .size(24.0)
                .strong()
                .color(tokens.palette.text_primary),
        );
        ui.add_space(tokens.spacing.xs);

        // Warning card
        egui::Frame::none()
            .fill(tokens.palette.warning_subtle)
            .rounding(tokens.spacing.card_rounding)
            .inner_margin(Vec2::new(tokens.spacing.md, tokens.spacing.sm))
            .show(ui, |ui| {
                ui.set_max_width(BTN[0]);
                ui.label(
                    RichText::new("⚠ Write these 12 words down in order. Anyone with this phrase can restore your identity.")
                        .size(13.0)
                        .color(tokens.palette.warning),
                );
            });

        ui.add_space(tokens.spacing.lg);

        // Scrollable on small screens.
        egui::ScrollArea::vertical()
            .max_height(250.0)
            .show(ui, |ui| {
                let words: Vec<&str> = self.recovery_phrase.split_whitespace().collect();
                egui::Grid::new("phrase_grid")
                    .num_columns(3)
                    .spacing([16.0, 10.0])
                    .show(ui, |ui| {
                        for (i, word) in words.iter().enumerate() {
                            // Word number
                            ui.label(
                                RichText::new(format!("{}.", i + 1))
                                    .size(13.0)
                                    .color(tokens.palette.text_tertiary),
                            );
                            // Word
                            egui::Frame::none()
                                .fill(tokens.palette.bg_tertiary)
                                .rounding(6.0)
                                .inner_margin(Vec2::new(8.0, 4.0))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(*word)
                                            .size(15.0)
                                            .monospace()
                                            .color(tokens.palette.text_primary),
                                    );
                                });
                            if (i + 1) % 3 == 0 {
                                ui.end_row();
                            }
                        }
                    });
            });

        ui.add_space(tokens.spacing.lg);

        // Copy button — writes all 12 words to clipboard in one tap.
        let copied = self
            .copy_feedback_until
            .map(|t| t > std::time::Instant::now())
            .unwrap_or(false);
        if copied {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
        let copy_label = if copied {
            "✓ Copied!"
        } else {
            "Copy recovery phrase"
        };
        let copy_color = if copied {
            tokens.palette.success
        } else {
            tokens.palette.surface
        };
        if ui
            .add_sized(
                [BTN[0], 44.0],
                egui::Button::new(RichText::new(copy_label).size(15.0).color(tokens.palette.text_primary))
                    .fill(copy_color)
                    .rounding(tokens.spacing.button_rounding),
            )
            .clicked()
        {
            ui.output_mut(|o| o.copied_text = self.recovery_phrase.clone());
            self.copy_feedback_until =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(2));
        }

        ui.add_space(tokens.spacing.sm);

        if ui
            .add_sized(
                BTN,
                egui::Button::new(
                    RichText::new("I've written it down — Continue")
                        .size(16.0)
                        .color(tokens.palette.text_inverse),
                )
                .fill(tokens.palette.accent)
                .rounding(tokens.spacing.button_rounding),
            )
            .clicked()
        {
            state.page = Page::Home;
        }
    }

    fn show_restore(&mut self, ui: &mut Ui, state: &mut AppState, tokens: &DesignTokens) {
        ui.label(
            RichText::new("Restore identity")
                .size(24.0)
                .strong()
                .color(tokens.palette.text_primary),
        );
        ui.add_space(tokens.spacing.xs);
        ui.label(
            RichText::new("Enter your 12-word recovery phrase, separated by spaces.")
                .size(14.0)
                .color(tokens.palette.text_secondary),
        );
        ui.add_space(tokens.spacing.lg);

        let input_frame = design::input_frame(tokens);
        input_frame.show(ui, |ui| {
            let te_response = ui.add(
                egui::TextEdit::multiline(&mut self.phrase_input)
                    .hint_text("word1 word2 word3 …")
                    .font(egui::FontId::monospace(14.0))
                    .desired_rows(4)
                    .desired_width(320.0)
                    .margin(Vec2::new(8.0, 8.0)),
            );
            if self.focus_requested {
                te_response.request_focus();
                self.focus_requested = false;
                platform_hooks::request_show_keyboard();
                ui.ctx().request_repaint();
            }
        });

        if let Some(e) = &self.error {
            ui.add_space(tokens.spacing.xs);
            egui::Frame::none()
                .fill(tokens.palette.error_subtle)
                .rounding(tokens.spacing.button_rounding)
                .inner_margin(Vec2::new(tokens.spacing.sm, tokens.spacing.xs))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!("⚠ {e}"))
                            .color(tokens.palette.error)
                            .size(13.0),
                    );
                });
        }

        ui.add_space(tokens.spacing.lg);

        let can_restore = self.phrase_input.split_whitespace().count() >= 12;
        ui.add_enabled_ui(can_restore, |ui| {
            if ui
                .add_sized(
                    BTN,
                    egui::Button::new(
                        RichText::new("Restore identity")
                            .size(16.0)
                            .color(tokens.palette.text_inverse),
                    )
                    .fill(tokens.palette.accent)
                    .rounding(tokens.spacing.button_rounding),
                )
                .clicked()
            {
                let rt = tokio::runtime::Handle::current();
                match rt.block_on(
                    state
                        .daemon
                        .restore_identity(self.phrase_input.trim().to_owned()),
                ) {
                    Ok(id) => {
                        state.identity = Some(id);
                        state.page = Page::Home;
                    }
                    Err(e) => self.error = Some(e.to_string()),
                }
            }
        });
        ui.add_space(tokens.spacing.sm);

        if ui
            .add_sized(
                [BTN[0], 40.0],
                egui::Button::new(
                    RichText::new("← Back")
                        .size(14.0)
                        .color(tokens.palette.text_secondary),
                )
                .fill(tokens.palette.surface)
                .rounding(tokens.spacing.button_rounding),
            )
            .clicked()
        {
            self.step = Step::Welcome;
            self.error = None;
        }
    }
}
