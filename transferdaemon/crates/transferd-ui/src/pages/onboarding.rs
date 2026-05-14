//! Onboarding page — create or restore a TransferDaemon identity.

use crate::app::{AppState, Page};
use egui::{Color32, Context, RichText, Ui};

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
}

impl OnboardingPage {
    pub fn show(&mut self, ui: &mut Ui, _ctx: &Context, state: &mut AppState) {
        ui.vertical_centered(|ui| {
            ui.add_space(48.0);

            match self.step {
                Step::Welcome => self.show_welcome(ui),
                Step::CreateName => self.show_create_name(ui, state),
                Step::ShowPhrase => self.show_phrase(ui, state),
                Step::Restore => self.show_restore(ui, state),
            }
        });
    }

    fn show_welcome(&mut self, ui: &mut Ui) {
        ui.label(
            RichText::new("TransferDaemon")
                .size(32.0)
                .strong()
                .color(Color32::WHITE),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new("Sovereign. Zero-knowledge. Universal transfer.")
                .size(15.0)
                .color(Color32::from_gray(180)),
        );
        ui.add_space(48.0);

        if ui
            .add_sized([240.0, 44.0], egui::Button::new(
                RichText::new("Create new identity").size(16.0),
            ).fill(Color32::from_rgb(0, 122, 255)))
            .clicked()
        {
            self.step = Step::CreateName;
        }

        ui.add_space(12.0);

        if ui
            .add_sized([240.0, 44.0], egui::Button::new(
                RichText::new("Restore from phrase").size(16.0),
            ).fill(Color32::from_rgb(44, 44, 46)))
            .clicked()
        {
            self.step = Step::Restore;
        }
    }

    fn show_create_name(&mut self, ui: &mut Ui, state: &mut AppState) {
        ui.label(RichText::new("Choose a display name").size(22.0).strong().color(Color32::WHITE));
        ui.add_space(8.0);
        ui.label(
            RichText::new("This is only shown to people you choose to share it with.")
                .size(13.0)
                .color(Color32::from_gray(160)),
        );
        ui.add_space(24.0);

        let name_field = egui::TextEdit::singleline(&mut self.display_name)
            .hint_text("Display name…")
            .font(egui::FontId::proportional(16.0))
            .desired_width(280.0);
        ui.add(name_field);

        if let Some(e) = &self.error {
            ui.add_space(8.0);
            ui.label(RichText::new(e).color(Color32::RED));
        }

        ui.add_space(24.0);

        let can_continue = !self.display_name.trim().is_empty();
        ui.add_enabled_ui(can_continue, |ui| {
            if ui.add_sized([240.0, 44.0], egui::Button::new("Continue")
                .fill(Color32::from_rgb(0, 122, 255))).clicked()
            {
                let name = self.display_name.trim().to_owned();
                // Blocking call to mock daemon (real daemon call is async — use channel).
                let rt = tokio::runtime::Handle::current();
                let phrase = rt.block_on(state.daemon.create_identity(name));
                match phrase {
                    Ok(p) => {
                        self.recovery_phrase = p.clone();
                        // Keep phrase in AppState so Settings can offer a reveal button.
                        state.recovery_phrase = Some(p);
                        // Refresh identity so Settings sees it immediately after creation.
                        state.identity = rt.block_on(state.daemon.get_identity());
                        self.step = Step::ShowPhrase;
                    }
                    Err(e) => self.error = Some(e.to_string()),
                }
            }
        });

        ui.add_space(12.0);
        if ui.small_button("← Back").clicked() {
            self.step = Step::Welcome;
        }
    }

    fn show_phrase(&mut self, ui: &mut Ui, state: &mut AppState) {
        ui.label(RichText::new("Your recovery phrase").size(22.0).strong().color(Color32::WHITE));
        ui.add_space(8.0);
        ui.label(
            RichText::new("Write these 12 words down in order. Anyone with this phrase can\nrestore your identity. Never share it.")
                .size(13.0)
                .color(Color32::from_rgb(255, 214, 10)), // amber warning
        );
        ui.add_space(24.0);

        // Render phrase in a 3×4 grid.
        let words: Vec<&str> = self.recovery_phrase.split_whitespace().collect();
        egui::Grid::new("phrase_grid")
            .num_columns(3)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                for (i, word) in words.iter().enumerate() {
                    ui.label(
                        RichText::new(format!("{}. {}", i + 1, word))
                            .size(15.0)
                            .monospace()
                            .color(Color32::WHITE),
                    );
                    if (i + 1) % 3 == 0 { ui.end_row(); }
                }
            });

        ui.add_space(32.0);

        if ui.add_sized([240.0, 44.0], egui::Button::new("I've written it down — Continue")
            .fill(Color32::from_rgb(0, 122, 255))).clicked()
        {
            state.page = Page::Home;
        }
    }

    fn show_restore(&mut self, ui: &mut Ui, state: &mut AppState) {
        ui.label(RichText::new("Restore identity").size(22.0).strong().color(Color32::WHITE));
        ui.add_space(8.0);
        ui.label(
            RichText::new("Enter your 12-word recovery phrase, separated by spaces.")
                .size(13.0)
                .color(Color32::from_gray(160)),
        );
        ui.add_space(24.0);

        let phrase_field = egui::TextEdit::multiline(&mut self.phrase_input)
            .hint_text("word1 word2 word3 …")
            .font(egui::FontId::monospace(14.0))
            .desired_rows(3)
            .desired_width(320.0);
        ui.add(phrase_field);

        if let Some(e) = &self.error {
            ui.add_space(8.0);
            ui.label(RichText::new(e).color(Color32::RED));
        }

        ui.add_space(24.0);

        let can_restore = self.phrase_input.split_whitespace().count() >= 12;
        ui.add_enabled_ui(can_restore, |ui| {
            if ui.add_sized([240.0, 44.0], egui::Button::new("Restore")
                .fill(Color32::from_rgb(0, 122, 255))).clicked()
            {
                let rt = tokio::runtime::Handle::current();
                match rt.block_on(state.daemon.restore_identity(self.phrase_input.trim().to_owned())) {
                    Ok(id) => {
                        state.identity = Some(id);
                        state.page = Page::Home;
                    }
                    Err(e) => self.error = Some(e.to_string()),
                }
            }
        });

        ui.add_space(12.0);
        if ui.small_button("← Back").clicked() {
            self.step = Step::Welcome;
            self.error = None;
        }
    }
}
