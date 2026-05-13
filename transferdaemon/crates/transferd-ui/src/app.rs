//! App struct — implements `eframe::App`, owns all UI state, drives the page router.

use crate::daemon::{DaemonApi, MockDaemon};
use crate::pages::{chat::ChatPage, home::HomePage, onboarding::OnboardingPage, settings::SettingsPage};
use crate::types::{Contact, Identity, TransferStatus};
use egui::{Color32, Context};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Page enum
// ---------------------------------------------------------------------------

#[derive(Default, PartialEq, Clone, Copy)]
pub enum Page {
    #[default]
    Onboarding,
    Home,
    Chat,
    Settings,
}

// ---------------------------------------------------------------------------
// Shared app state (accessible to all pages)
// ---------------------------------------------------------------------------

pub struct AppState {
    pub page: Page,
    pub daemon: Arc<dyn DaemonApi>,
    pub daemon_is_live: bool, // true = gRPC daemon, false = MockDaemon
    pub identity: Option<Identity>,
    pub contacts: Vec<Contact>,
    pub transfers: Vec<TransferStatus>,
    pub open_chat: Option<String>, // contact ID
}

impl AppState {
    fn new(daemon: Arc<dyn DaemonApi>, daemon_is_live: bool) -> Self {
        let rt = tokio::runtime::Handle::current();
        let contacts = rt.block_on(daemon.get_contacts());
        let transfers = rt.block_on(daemon.get_transfers());
        let identity = rt.block_on(daemon.get_identity());
        // If an identity already exists, skip onboarding and go straight to Home.
        let page = if identity.is_some() { Page::Home } else { Page::Onboarding };
        Self {
            page,
            daemon,
            daemon_is_live,
            identity,
            contacts,
            transfers,
            open_chat: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level eframe App
// ---------------------------------------------------------------------------

pub struct TransferDaemonApp {
    state: AppState,
    onboarding: OnboardingPage,
    home: HomePage,
    chat: ChatPage,
    settings: SettingsPage,
}

impl TransferDaemonApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::with_daemon(cc, Arc::new(MockDaemon::new()), false)
    }

    pub fn with_daemon(cc: &eframe::CreationContext<'_>, daemon: Arc<dyn DaemonApi>, is_live: bool) -> Self {
        apply_theme(&cc.egui_ctx);
        let state = AppState::new(daemon, is_live);
        Self {
            state,
            onboarding: OnboardingPage::default(),
            home: HomePage::default(),
            chat: ChatPage::default(),
            settings: SettingsPage::default(),
        }
    }
}

impl eframe::App for TransferDaemonApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // Dark background for the whole window.
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(Color32::from_rgb(0, 0, 0)))
            .show(ctx, |ui| {
                // Settings gear — always available from Home onward.
                if self.state.page != Page::Onboarding {
                    egui::TopBottomPanel::top("global_bar").show_inside(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.set_min_height(44.0);
                            ui.label(
                                egui::RichText::new("TransferDaemon")
                                    .size(17.0)
                                    .strong()
                                    .color(Color32::WHITE),
                            );
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("⚙").clicked() {
                                    self.state.page = Page::Settings;
                                }
                            });
                        });
                    });
                }

                egui::CentralPanel::default().show_inside(ui, |ui| {
                    // Enter hooks — called once when switching to a page.
                    match self.state.page {
                        Page::Chat => self.chat.enter(&mut self.state),
                        _ => {}
                    }

                    match self.state.page {
                        Page::Onboarding => self.onboarding.show(ui, ctx, &mut self.state),
                        Page::Home       => self.home.show(ui, &mut self.state),
                        Page::Chat       => self.chat.show(ui, &mut self.state),
                        Page::Settings   => {
                            if ui.button("← Back").clicked() {
                                self.state.page = Page::Home;
                            }
                            self.settings.show(ui, ctx, &self.state);
                        }
                    }
                });
            });

        // Continuous repaint while transfers are active so progress bars animate.
        if !self.state.transfers.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
    }
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

fn apply_theme(ctx: &Context) {
    let mut visuals = egui::Visuals::dark();

    // Pure black background (OLED-friendly, matches Apple dark mode).
    visuals.panel_fill = Color32::from_rgb(0, 0, 0);
    visuals.window_fill = Color32::from_rgb(18, 18, 18);
    visuals.extreme_bg_color = Color32::from_rgb(0, 0, 0);
    visuals.faint_bg_color = Color32::from_rgb(28, 28, 30);

    // System blue accent.
    visuals.selection.bg_fill = Color32::from_rgb(0, 122, 255);
    visuals.hyperlink_color = Color32::from_rgb(0, 122, 255);

    // Subtle widget rounding.
    visuals.widgets.noninteractive.rounding = 8.0.into();
    visuals.widgets.inactive.rounding = 8.0.into();
    visuals.widgets.hovered.rounding = 8.0.into();
    visuals.widgets.active.rounding = 8.0.into();

    ctx.set_visuals(visuals);

    // Typography: slightly larger default font.
    let mut fonts = egui::FontDefinitions::default();
    for (_name, data) in fonts.font_data.iter_mut() {
        let _ = data; // use defaults
    }
    ctx.set_fonts(fonts);

    ctx.style_mut(|s| {
        s.spacing.item_spacing = egui::Vec2::new(8.0, 6.0);
        s.spacing.button_padding = egui::Vec2::new(12.0, 6.0);
    });
}
