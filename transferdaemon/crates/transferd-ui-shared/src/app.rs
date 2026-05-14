//! App struct — implements `eframe::App`, owns all UI state, drives the page router.

use crate::daemon::{DaemonApi, MockDaemon};
use crate::pages::{chat::ChatPage, home::HomePage, onboarding::OnboardingPage};
use crate::types::{Contact, Conversation, Identity, Message, TransferStatus};
use egui::{Color32, Context};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Default, PartialEq, Clone, Copy)]
pub enum Page {
    #[default]
    Onboarding,
    Home,
    Chat,
}

pub struct AppState {
    pub page: Page,
    pub daemon: Arc<dyn DaemonApi>,
    pub daemon_is_live: bool,
    pub identity: Option<Identity>,
    pub recovery_phrase: Option<String>,
    pub contacts: Vec<Contact>,
    pub transfers: Vec<TransferStatus>,
    pub open_chat: Option<String>,
    /// Derived conversation summaries shown in the chat list.
    pub conversations: Vec<Conversation>,
    /// Last-message preview per contact_id — updated by ChatPage when it loads messages.
    pub message_previews: HashMap<String, (String, u64)>, // contact_id → (text, ts)
}

impl AppState {
    pub fn new(daemon: Arc<dyn DaemonApi>, daemon_is_live: bool) -> Self {
        let rt = tokio::runtime::Handle::current();
        let contacts = rt.block_on(daemon.get_contacts());
        let transfers = rt.block_on(daemon.get_transfers());
        let identity = rt.block_on(daemon.get_identity());
        let page = if identity.is_some() { Page::Home } else { Page::Onboarding };
        let conversations = build_conversations(&contacts, &HashMap::new());
        Self {
            page, daemon, daemon_is_live, identity,
            recovery_phrase: None, contacts, transfers, open_chat: None,
            conversations, message_previews: HashMap::new(),
        }
    }

    /// Rebuild conversation list from current contacts + cached previews.
    pub fn rebuild_conversations(&mut self) {
        self.conversations = build_conversations(&self.contacts, &self.message_previews);
    }
}

/// Build a sorted conversation list from contacts + message preview cache.
/// Conversations with recent messages sort above those without.
fn build_conversations(
    contacts: &[Contact],
    previews: &HashMap<String, (String, u64)>,
) -> Vec<Conversation> {
    let mut convs: Vec<Conversation> = contacts.iter().map(|c| {
        let (last_message, last_time_sec) = previews
            .get(&c.id)
            .cloned()
            .unwrap_or_default();
        Conversation {
            contact_id: c.id.clone(),
            display_name: c.name.clone(),
            online: c.online,
            last_message,
            last_time_sec,
            unread: 0, // populated later when messages are fetched
        }
    }).collect();
    // Most-recent conversations first.
    convs.sort_by(|a, b| b.last_time_sec.cmp(&a.last_time_sec));
    convs
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const REFRESH_INTERVAL: Duration = Duration::from_secs(3);

pub struct TransferDaemonApp {
    pub state: AppState,
    onboarding: OnboardingPage,
    pub home: HomePage,
    chat: ChatPage,
    last_refresh: Instant,
    /// Platform hook: called each frame to check whether the native file picker
    /// has produced a result.  Set by the Android platform layer; `None` on desktop.
    pub poll_file_pick: Option<Box<dyn Fn() -> Option<String> + Send + Sync>>,
}

impl TransferDaemonApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::with_daemon(cc, Arc::new(MockDaemon::new()), false)
    }

    /// Direct access to the ChatPage so platform layers can wire callbacks.
    pub fn chat_page_mut(&mut self) -> &mut ChatPage {
        &mut self.chat
    }

    pub fn with_daemon(cc: &eframe::CreationContext<'_>, daemon: Arc<dyn DaemonApi>, is_live: bool) -> Self {
        apply_theme(&cc.egui_ctx);
        let state = AppState::new(daemon, is_live);
        Self {
            state,
            onboarding: OnboardingPage::default(),
            home: HomePage::default(),
            chat: ChatPage::default(),
            last_refresh: Instant::now(),
            poll_file_pick: None,
        }
    }

    /// Refresh contacts, transfers, and conversation list from the daemon.
    fn refresh(&mut self) {
        let rt = tokio::runtime::Handle::current();
        self.state.contacts  = rt.block_on(self.state.daemon.get_contacts());
        self.state.transfers = rt.block_on(self.state.daemon.get_transfers());
        self.state.identity  = rt.block_on(self.state.daemon.get_identity());
        self.state.rebuild_conversations();
    }
}

impl eframe::App for TransferDaemonApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // Drain any file path delivered by the platform's native file picker.
        if let Some(ref poll) = self.poll_file_pick {
            if let Some(path) = poll() {
                self.chat.pending_file_path = Some(path);
            }
        }

        // Periodic background refresh.
        if self.last_refresh.elapsed() > REFRESH_INTERVAL && self.state.page != Page::Onboarding {
            self.last_refresh = Instant::now();
            self.refresh();
        }

        match self.state.page {
            Page::Onboarding => {
                egui::CentralPanel::default()
                    .frame(egui::Frame::none().fill(Color32::from_rgb(0, 0, 0)))
                    .show(ctx, |ui| {
                        self.onboarding.show(ui, ctx, &mut self.state);
                    });
            }

            Page::Home => {
                // Enter hook: Chat tab needs to load messages when switching contacts.
                self.home.show(ctx, &mut self.state, &mut self.chat);
            }

            Page::Chat => {
                egui::CentralPanel::default()
                    .frame(egui::Frame::none().fill(Color32::from_rgb(0, 0, 0)))
                    .show(ctx, |ui| {
                        self.chat.enter(&mut self.state);
                        self.chat.show(ui, &mut self.state);
                    });
            }
        }

        // Keep transfers and active calls animated.
        if !self.state.transfers.is_empty() || self.state.page == Page::Chat {
            ctx.request_repaint_after(Duration::from_millis(250));
        } else {
            // Gentle poll so the conversation list stays fresh.
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

pub fn apply_theme(ctx: &Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill       = Color32::from_rgb(0, 0, 0);
    visuals.window_fill      = Color32::from_rgb(18, 18, 18);
    visuals.extreme_bg_color = Color32::from_rgb(0, 0, 0);
    visuals.faint_bg_color   = Color32::from_rgb(28, 28, 30);
    visuals.selection.bg_fill = Color32::from_rgb(0, 122, 255);
    visuals.hyperlink_color  = Color32::from_rgb(0, 122, 255);
    visuals.widgets.noninteractive.rounding = 8.0.into();
    visuals.widgets.inactive.rounding       = 8.0.into();
    visuals.widgets.hovered.rounding        = 8.0.into();
    visuals.widgets.active.rounding         = 8.0.into();
    ctx.set_visuals(visuals);
    ctx.set_fonts(egui::FontDefinitions::default());
    ctx.style_mut(|s| {
        s.spacing.item_spacing   = egui::Vec2::new(8.0, 6.0);
        s.spacing.button_padding = egui::Vec2::new(12.0, 6.0);
    });
}

// Helper visible to other modules (e.g. tests) that need to fabricate AppState.
#[allow(dead_code)]
pub fn preview_message(msg: &Message) -> (String, u64) {
    let text = match &msg.content {
        crate::types::MessageContent::Text(t) => t.clone(),
        crate::types::MessageContent::File { name, .. } => format!("📁 {name}"),
    };
    (text, msg.timestamp_ts)
}
