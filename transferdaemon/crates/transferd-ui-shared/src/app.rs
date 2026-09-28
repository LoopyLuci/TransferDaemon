//! App struct — implements `eframe::App`, owns all UI state, drives the page router.
//!
//! Uses the design system for consistent theming, animations, and accessibility.

use crate::animations::ToastManager;
use crate::daemon::{DaemonApi, MockDaemon};
use crate::db::LocalDb;
use crate::design::{self, DesignTokens, LayoutMode, Theme};
use crate::notifications::{self, NotificationLevel};
use crate::pages::{chat::ChatPage, home::HomePage, home::Tab, onboarding::OnboardingPage};
use crate::tray_channel::{TrayCommand, TrayUpdate};
use crate::types::{Contact, Conversation, Group, Identity, TransferStatus};
use egui::{Color32, Context};
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::Arc;

/// Poller for OS share intents: returns `(kind, payload)` where kind ∈
/// {"file", "text"} or `None` when idle.
type SharePoller = Box<dyn Fn() -> Option<(String, String)> + Send + Sync>;
use std::time::{Duration, Instant};

type LoadResult = (Vec<Contact>, Vec<TransferStatus>, Option<Identity>, Vec<Group>);

#[derive(Default, PartialEq, Clone, Copy)]
pub enum Page {
    #[default]
    Onboarding,
    Home,
    Chat,
    GroupChat,
}

pub struct AppState {
    pub page: Page,
    pub daemon: Arc<dyn DaemonApi>,
    pub daemon_is_live: bool,
    /// gRPC endpoint address used for the telemetry stream (e.g. "http://127.0.0.1:50051").
    /// `None` when running against a mock daemon.
    pub daemon_addr: Option<String>,
    pub identity: Option<Identity>,
    pub recovery_phrase: Option<String>,
    pub contacts: Vec<Contact>,
    pub groups: Vec<Group>,
    pub transfers: Vec<TransferStatus>,
    pub open_chat: Option<String>,
    pub open_group: Option<String>,
    pub conversations: Vec<Conversation>,
    pub message_previews: HashMap<String, (String, u64)>,
    /// Per-contact inbound bubble color overrides.
    pub contact_colors: HashMap<String, Color32>,
    /// Auto-saved per-conversation drafts.
    pub drafts: HashMap<String, String>,
    /// Current layout mode (responsive).
    pub layout_mode: LayoutMode,
    /// Current theme.
    pub theme: Theme,
    /// App-lock: when `locked`, a PIN screen gates the UI. `pin_hash` is the
    /// BLAKE3 hash of the PIN (stored via daemon settings).
    pub locked: bool,
    pub pin_hash: Option<String>,
    pub lock_input: String,
    /// Pending OS share payload `(kind, payload)` where kind ∈ {"file", "text"}.
    /// Set from the mobile share bridge; consumed when a chat opens.
    pub pending_share: Option<(String, String)>,
}

impl AppState {
    pub fn new(daemon: Arc<dyn DaemonApi>, daemon_is_live: bool) -> Self {
        Self {
            page: Page::Onboarding,
            daemon,
            daemon_is_live,
            daemon_addr: None,
            identity: None,
            recovery_phrase: None,
            contacts: vec![],
            groups: vec![],
            transfers: vec![],
            open_chat: None,
            open_group: None,
            conversations: build_conversations(&[], &HashMap::new()),
            message_previews: HashMap::new(),
            contact_colors: HashMap::new(),
            drafts: HashMap::new(),
            layout_mode: LayoutMode::Compact,
            theme: Theme::Oled,
            locked: false,
            pin_hash: None,
            lock_input: String::new(),
            pending_share: None,
        }
    }

    pub fn rebuild_conversations(&mut self) {
        self.conversations = build_conversations(&self.contacts, &self.message_previews);
    }
}

/// Stable name for a theme, used when persisting to the local DB.
fn theme_name(theme: Theme) -> &'static str {
    match theme {
        Theme::Dark => "dark",
        Theme::Light => "light",
        Theme::HighContrast => "high_contrast",
        Theme::Oled => "oled",
    }
}

/// Parse a theme back from its persisted name.
fn theme_from_name(s: &str) -> Option<Theme> {
    match s {
        "dark" => Some(Theme::Dark),
        "light" => Some(Theme::Light),
        "high_contrast" => Some(Theme::HighContrast),
        "oled" => Some(Theme::Oled),
        _ => None,
    }
}

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
            display_name: c.display_name().to_owned(),
            online: c.online,
            last_message,
            last_time_sec,
            unread: 0,
        }
    }).collect();
    convs.sort_by_key(|b| std::cmp::Reverse(b.last_time_sec));
    convs
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const REFRESH_INTERVAL: Duration = Duration::from_secs(3);

static REFRESH_RESULT: std::sync::Mutex<Option<LoadResult>> =
    std::sync::Mutex::new(None);

pub struct TransferDaemonApp {
    pub state: AppState,
    onboarding: OnboardingPage,
    pub home: HomePage,
    chat: ChatPage,
    group_chat: crate::pages::groups::GroupChatPage,
    last_refresh: Instant,
    load_rx: Option<tokio::sync::oneshot::Receiver<LoadResult>>,
    pub poll_file_pick: Option<Box<dyn Fn() -> Option<String> + Send + Sync>>,
    /// Optional OS share-bridge poller: returns `(kind, payload)` where kind ∈
    /// {"file", "text"}. Drained each frame into `state.pending_share`.
    pub poll_share: Option<SharePoller>,
    /// Local SQLite DB for session persistence, nicknames, and colors.
    pub db: Option<LocalDb>,
    /// True once we've applied the local DB identity cache (prevents repeated attempts).
    db_identity_loaded: bool,
    /// True once we've restored the persisted theme from the DB (prevents repeated attempts).
    db_theme_loaded: bool,
    /// True once we've applied the local DB contact colors (prevents repeated attempts).
    db_colors_loaded: bool,
    /// Tracks the last keyboard-wanted state so show/hide is only called on change.
    #[cfg(target_os = "android")]
    keyboard_was_wanted: bool,
    /// Toast notification manager.
    pub toasts: ToastManager,
    /// Last frame time for animation updates.
    last_frame_time: Instant,

    // ── System tray ──────────────────────────────────────────────────────────
    /// Sender for updating the tray icon (badge, tooltip).
    tray_tx: Option<mpsc::Sender<TrayUpdate>>,
    /// Receiver for tray commands (ShowWindow, Quit).
    tray_rx: Option<mpsc::Receiver<TrayCommand>>,

    // ── Notification diff tracking ───────────────────────────────────────────
    /// Previous online state per contact — used to detect online→offline changes.
    prev_online: HashMap<String, bool>,
    /// Previous transferred bytes per transfer ID — used to detect completion.
    prev_transfer_bytes: HashMap<String, u64>,
    /// Previous message count per contact — used to detect new messages.
    prev_msg_count: HashMap<String, usize>,
}

impl TransferDaemonApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::with_daemon(cc, Arc::new(MockDaemon::new()), false)
    }

    pub fn chat_page_mut(&mut self) -> &mut ChatPage {
        &mut self.chat
    }

    pub fn with_daemon(
        cc: &eframe::CreationContext<'_>,
        daemon: Arc<dyn DaemonApi>,
        is_live: bool,
    ) -> Self {
        // Initialize design system with OLED theme (default)
        design::apply_theme(&cc.egui_ctx, Theme::Oled);

        let (tx, rx) = tokio::sync::oneshot::channel::<LoadResult>();
        let d = Arc::clone(&daemon);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let contacts  = d.get_contacts().await;
                let transfers = d.get_transfers().await;
                let identity  = d.get_identity().await;
                let groups    = d.get_groups().await;
                let _ = tx.send((contacts, transfers, identity, groups));
            });
        }

        let state = AppState::new(daemon, is_live);

        // Store the egui context so JNI keyboard threads can request immediate
        // repaints when they push events into INJECTED_EVENTS.
        #[cfg(target_os = "android")]
        crate::platform_hooks::register_egui_ctx(cc.egui_ctx.clone());

        Self {
            state,
            onboarding: OnboardingPage::default(),
            home: HomePage::default(),
            chat: ChatPage::default(),
            group_chat: crate::pages::groups::GroupChatPage::default(),
            last_refresh: Instant::now(),
            load_rx: Some(rx),
            poll_file_pick: None,
            poll_share: None,
            db: None,
            db_identity_loaded: false,
            db_theme_loaded: false,
            db_colors_loaded: false,
            #[cfg(target_os = "android")]
            keyboard_was_wanted: false,
            toasts: ToastManager::new(),
            last_frame_time: Instant::now(),
            tray_tx: None,
            tray_rx: None,
            prev_online: HashMap::new(),
            prev_transfer_bytes: HashMap::new(),
            prev_msg_count: HashMap::new(),
        }
    }

    /// Initialize the local SQLite DB. Call this right after `with_daemon()`.
    pub fn init_db(&mut self, path: impl AsRef<std::path::Path>) {
        match LocalDb::open(path) {
            Ok(db) => { self.db = Some(db); }
            Err(e) => {
                tracing::error!("[TDDb] Failed to open local DB: {e}");
                self.toasts.error(format!("Failed to open database: {e}"));
            }
        }
    }

    fn spawn_refresh(&self) {
        let d = Arc::clone(&self.state.daemon);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let contacts  = d.get_contacts().await;
                let transfers = d.get_transfers().await;
                let identity  = d.get_identity().await;
                let groups    = d.get_groups().await;
                crate::call_caps::update_call_kbps(d.get_setting("limits.call_kbps").await);
                *REFRESH_RESULT.lock().unwrap_or_else(|e| e.into_inner()) = Some((contacts, transfers, identity, groups));
            });
        }
    }

    /// Persist the current identity to the local DB cache.
    fn save_identity_to_db(&self) {
        if let (Some(db), Some(id)) = (&self.db, &self.state.identity) {
            let _ = db.cache_identity(&id.public_key, &id.display_name);
        }
    }

    /// Persist the recovery phrase to the local DB for auto-restore.
    fn save_recovery_phrase_to_db(&self) {
        if let (Some(db), Some(id)) = (&self.db, &self.state.identity) {
            let _ = db.cache_recovery_phrase(&id.phrase);
        }
    }

    /// Load data from the local SQLite cache (fallback when daemon can't be restored).
    fn load_from_local_cache(&mut self) {
        if let Some(db) = &self.db {
                                if let Ok(Some((pk, name))) = db.load_cached_identity() {
                                    self.state.identity = Some(Identity {
                                        public_key: pk,
                                        display_name: name,
                                        phrase: String::new(),
                                    });
                // Also load locally-cached contacts (with nicknames).
                if let Ok(cached) = db.load_contacts() {
                    if !cached.is_empty() {
                        self.state.contacts = cached;
                    }
                }
                self.state.page = Page::Home;
            } else {
                self.state.page = Page::Onboarding;
            }
        } else {
            self.state.page = Page::Onboarding;
        }
    }

    /// Load the cached recovery phrase from the local DB.
    fn load_cached_recovery_phrase(&self) -> Option<String> {
        self.db.as_ref().and_then(|db| {
            db.load_cached_recovery_phrase().ok().flatten()
        })
    }

    /// Persist all current contacts (with nicknames) to the local DB.
    fn save_contacts_to_db(&self) {
        if let Some(db) = &self.db {
            for c in &self.state.contacts {
                let _ = db.upsert_contact(c);
            }
        }
    }

    /// Apply a contact-color change: update AppState and persist to DB.
    pub fn set_contact_color(&mut self, contact_id: String, color: Color32) {
        self.state.contact_colors.insert(contact_id.clone(), color);
        if let Some(db) = &self.db {
            let _ = db.set_contact_color(&contact_id, color);
        }
    }

    /// Persist a contact's nickname to DB and rebuild conversations.
    pub fn set_contact_nickname(&mut self, contact_id: &str, nickname: Option<String>) {
        if let Some(c) = self.state.contacts.iter_mut().find(|c| c.id == contact_id) {
            c.nickname = nickname.clone();
        }
        if let Some(db) = &self.db {
            let _ = db.set_contact_nickname(contact_id, nickname.as_deref());
        }
        self.state.rebuild_conversations();
    }

    /// Switch theme at runtime and persist the choice to the local DB.
    pub fn set_theme(&mut self, theme: Theme, ctx: &Context) {
        self.state.theme = theme;
        design::apply_theme(ctx, theme);
        if let Some(db) = &self.db {
            let _ = db.set_setting("theme", theme_name(theme));
        }
        self.toasts.info(format!("Theme switched to {:?}", theme));
    }

    // ── System tray integration ────────────────────────────────────────────────

    /// Attach the system tray channel pair. Call this right after construction.
    pub fn set_tray_channels(
        &mut self,
        tx: mpsc::Sender<TrayUpdate>,
        rx: mpsc::Receiver<TrayCommand>,
    ) {
        self.tray_tx = Some(tx);
        self.tray_rx = Some(rx);
    }

    /// Drain any pending tray commands (ShowWindow, Quit).
    fn handle_tray_events(&mut self, ctx: &Context) {
        let Some(ref rx) = self.tray_rx else { return };
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                TrayCommand::ShowWindow => {
                    ctx.request_repaint();
                }
                TrayCommand::Quit => {
                    tracing::info!("[App] Quit requested from tray");
                    std::process::exit(0);
                }
            }
        }
    }

    /// Send an update to the tray thread (badge, tooltip).
    fn update_tray(&self, update: TrayUpdate) {
        if let Some(ref tx) = self.tray_tx {
            let _ = tx.send(update);
        }
    }

    // ── Notification diff logic ────────────────────────────────────────────────

    /// Called after each refresh to detect changes and fire notifications.
    fn diff_and_notify(&mut self) {
        let contacts = &self.state.contacts;
        let transfers = &self.state.transfers;

        // Detect contacts coming online
        for c in contacts {
            let was_online = self.prev_online.get(&c.id).copied().unwrap_or(false);
            if c.online && !was_online {
                let name = c.display_name();
                self.toasts.info(format!("{name} is online"));
                notifications::send_notification(
                    "Contact Online",
                    &format!("{name} is now online"),
                    NotificationLevel::Info,
                );
            }
        }
        self.prev_online = contacts.iter().map(|c| (c.id.clone(), c.online)).collect();

        // Detect transfer completion
        for t in transfers {
            let prev = self.prev_transfer_bytes.get(&t.id).copied().unwrap_or(0);
            let just_completed = prev > 0
                && prev < t.size_bytes
                && t.transferred_bytes >= t.size_bytes;
            if just_completed {
                let action = if t.outbound { "Sent" } else { "Received" };
                self.toasts.success(format!("{action} {}", t.file_name));
                notifications::send_notification(
                    "Transfer Complete",
                    &format!("{action} {}", t.file_name),
                    NotificationLevel::TransferComplete,
                );
            }
        }
        self.prev_transfer_bytes = transfers
            .iter()
            .map(|t| (t.id.clone(), t.transferred_bytes))
            .collect();

        // Detect new messages (check max 5 contacts per refresh to limit RPCs)
        let daemon = self.state.daemon.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            for c in contacts.iter().take(5) {
                let prev = self.prev_msg_count.get(&c.id).copied().unwrap_or(0);
                let msgs = rt.block_on(daemon.get_messages(&c.id));
                let count = msgs.len();
                if prev > 0 && count > prev {
                    for msg in msgs.iter().rev().take(count.saturating_sub(prev)) {
                        if !msg.outbound {
                            let preview = msg.content.preview();
                            let name = c.display_name();
                            self.toasts.info(format!("{name}: {preview}"));
                            notifications::send_notification(
                                name,
                                &preview,
                                NotificationLevel::NewMessage,
                            );
                            break;
                        }
                    }
                }
                self.prev_msg_count.insert(c.id.clone(), count);
            }
        }

        // Update tray badge with online contact count
        let online_count = contacts.iter().filter(|c| c.online).count() as u32;
        if online_count > 0 {
            self.update_tray(TrayUpdate::SetBadge(Some(online_count)));
        } else {
            self.update_tray(TrayUpdate::SetBadge(None));
        }
    }
}

impl eframe::App for TransferDaemonApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // ── Handle system tray events (ShowWindow, Quit) ─────────────────────
        self.handle_tray_events(ctx);

        // ── Calculate delta time for animations ──────────────────────────────
        let now = Instant::now();
        let dt = now.duration_since(self.last_frame_time).as_secs_f32();
        self.last_frame_time = now;

        // ── Update responsive layout mode ────────────────────────────────────
        let screen_rect = ctx.screen_rect();
        let new_mode = LayoutMode::from_width(screen_rect.width());
        if new_mode != self.state.layout_mode {
            self.state.layout_mode = new_mode;
        }

        // ── Android: apply device density so scale tracks Display-size changes ─
        #[cfg(target_os = "android")]
        {
            use crate::platform_hooks::DEVICE_PPP;
            use std::sync::atomic::Ordering;
            let bits = DEVICE_PPP.load(Ordering::Relaxed);
            if bits != 0 {
                let device_ppp = f32::from_bits(bits);
                if (device_ppp - ctx.pixels_per_point()).abs() > 0.005 {
                    ctx.set_pixels_per_point(device_ppp);
                }
            }
        }

        // ── Android: reserve exact pixel height for system bars ────────────────
        #[cfg(target_os = "android")]
        {
            use crate::platform_hooks::{SYSTEM_INSET_TOP, SYSTEM_INSET_BOTTOM};
            use std::sync::atomic::Ordering;
            let top_px    = SYSTEM_INSET_TOP.load(Ordering::Relaxed);
            let bottom_px = SYSTEM_INSET_BOTTOM.load(Ordering::Relaxed);
            if top_px > 0 {
                let pts = top_px as f32 / ctx.pixels_per_point();
                let tokens = DesignTokens::current();
                egui::TopBottomPanel::top("__status_bar_inset")
                    .exact_height(pts)
                    .frame(design::panel_frame(&tokens).fill(tokens.palette.bg_primary))
                    .show(ctx, |_ui| {});
            }
            if bottom_px > 0 {
                let pts = bottom_px as f32 / ctx.pixels_per_point();
                let tokens = DesignTokens::current();
                egui::TopBottomPanel::bottom("__nav_bar_inset")
                    .exact_height(pts)
                    .frame(design::panel_frame(&tokens).fill(tokens.palette.bg_primary))
                    .show(ctx, |_ui| {});
            }
        }

        // ── Handle global keyboard shortcuts ──────────────────────────────────
        ctx.input_mut(|i| {
            let mut idx = 0;
            while idx < i.events.len() {
                let consume = match &i.events[idx] {
                    egui::Event::Key { key, pressed, modifiers, .. } if *pressed => {
                        match (key, modifiers.ctrl, modifiers.shift) {
                            (egui::Key::N, true, false) if self.state.page != Page::Onboarding => {
                                self.state.page = Page::Home;
                                self.home.tab = Tab::Contacts;
                                true
                            }
                            (egui::Key::Comma, true, false) if self.state.page != Page::Onboarding => {
                                self.state.page = Page::Home;
                                self.home.tab = Tab::Settings;
                                true
                            }
                            (egui::Key::Escape, false, false) if self.state.page == Page::Chat => {
                                self.state.page = Page::Home;
                                true
                            }
                            (egui::Key::Tab, true, false) if self.state.page == Page::Home => {
                                let tabs = &[Tab::Chats, Tab::Contacts, Tab::Transfers, Tab::Settings];
                                if let Some(pos) = tabs.iter().position(|t| *t == self.home.tab) {
                                    self.home.tab = tabs[(pos + 1) % tabs.len()];
                                }
                                true
                            }
                            _ => false,
                        }
                    }
                    _ => false,
                };
                if consume {
                    i.events.remove(idx);
                } else {
                    idx += 1;
                }
            }
        });

        // ── Handle drag-and-drop file ─────────────────────────────────────────
        {
            let dropped: Vec<egui::DroppedFile> = ctx.input(|i| i.raw.dropped_files.clone());
            if !dropped.is_empty() {
                for f in &dropped {
                    if let Some(path) = &f.path {
                        if self.state.page == Page::Chat {
                            self.chat.pending_file_path = Some(path.to_string_lossy().to_string());
                        } else if !self.state.contacts.is_empty() {
                            // Drop on home page: start chat with first contact
                            self.state.open_chat = Some(self.state.contacts[0].id.clone());
                            self.state.page = Page::Chat;
                            self.chat.pending_file_path = Some(path.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }

        // ── Drain injected keyboard events (Android TextWatcher → egui) ───────
        {
            let injected: Vec<egui::Event> = crate::platform_hooks::INJECTED_EVENTS
                .lock()
                .map(|mut g| g.drain(..).collect())
                .unwrap_or_default();
            if !injected.is_empty() {
                ctx.input_mut(|i| i.events.extend(injected));
                ctx.request_repaint();
            }
        }

        // ── Drain native file-picker result ────────────────────────────────────
        if let Some(ref poll) = self.poll_file_pick {
            if let Some(path) = poll() {
                self.chat.pending_file_path = Some(path);
            }
        }

        // ── Drain OS share intent ─────────────────────────────────────────────
        if let Some(ref poll) = self.poll_share {
            if let Some(share) = poll() {
                self.state.pending_share = Some(share);
                // If the user isn't in a chat yet, drop them into the first
                // contact so the shared payload has an obvious target.
                if self.state.page == Page::Home && !self.state.contacts.is_empty() {
                    let first = self.state.contacts[0].id.clone();
                    self.state.open_chat = Some(first);
                    self.state.page = Page::Chat;
                }
            }
        }

        // ── Load local DB colors once (first frame after DB is available) ──────
        if !self.db_colors_loaded {
            if let Some(db) = &self.db {
                if let Ok(colors) = db.load_all_contact_colors() {
                    for (id, color) in colors {
                        self.state.contact_colors.insert(id, color);
                    }
                }
                self.db_colors_loaded = true;
            }
        }

        // ── Restore the persisted theme once the DB is available ──────────────
        if !self.db_theme_loaded {
            if let Some(db) = &self.db {
                if let Ok(Some(name)) = db.get_setting("theme") {
                    if let Some(theme) = theme_from_name(&name) {
                        self.set_theme(theme, ctx);
                    }
                }
                self.db_theme_loaded = true;
            }
        }

        // ── Apply a pending theme selection from the settings page ────────────
        let pending_theme = ctx.data_mut(|d| d.get_persisted::<usize>(egui::Id::new("pending_theme")));
        if let Some(pending) = pending_theme {
            let theme = match pending {
                0 => Theme::Dark,
                1 => Theme::Light,
                2 => Theme::HighContrast,
                _ => Theme::Oled,
            };
            if theme != self.state.theme {
                self.set_theme(theme, ctx);
            }
            ctx.data_mut(|d| {
                d.remove::<usize>(egui::Id::new("pending_theme"));
            });
        }

        // ── Apply initial load (contacts + transfers + identity from daemon) ───
        if let Some(mut rx) = self.load_rx.take() {
            match rx.try_recv() {
                Ok((contacts, transfers, identity, groups)) => {
                    let has_identity = identity.is_some();
                    self.state.identity = identity;
                    self.state.contacts = contacts;
                    self.state.groups = groups;
                    self.state.transfers = transfers;

                    // App lock: if a PIN is configured, gate the UI.
                    let rt = tokio::runtime::Handle::current();
                    if let Some(pin_hash) = rt.block_on(self.state.daemon.get_setting("app.lock.pin")) {
                        if !pin_hash.is_empty() {
                            self.state.pin_hash = Some(pin_hash);
                            self.state.locked = true;
                        }
                    }

                    if has_identity {
                        self.state.page = Page::Home;
                        self.save_identity_to_db();
                        self.save_recovery_phrase_to_db();
                        self.save_contacts_to_db();
                    } else {
                        // Daemon has no identity — try to restore from cached phrase
                        if !self.db_identity_loaded {
                            self.db_identity_loaded = true;

                            // Try to restore from cached recovery phrase
                            if let Some(phrase) = self.load_cached_recovery_phrase() {
                                tracing::info!("[App] Found cached recovery phrase, attempting restore");
                                let rt = tokio::runtime::Handle::current();
                                match rt.block_on(self.state.daemon.restore_identity(phrase)) {
                                    Ok(id) => {
                                        self.state.identity = Some(id);
                                        self.state.page = Page::Home;
                                        // Refresh contacts and transfers after restore
                                        let contacts = rt.block_on(self.state.daemon.get_contacts());
                                        let transfers = rt.block_on(self.state.daemon.get_transfers());
                                        self.state.contacts = contacts;
                                        self.state.transfers = transfers;
                                        self.save_identity_to_db();
                                        self.save_contacts_to_db();
                                        tracing::info!("[App] Successfully restored identity from cached phrase");
                                    }
                                    Err(e) => {
                                        tracing::warn!("[App] Failed to restore from cached phrase: {e}");
                                        // Fall back to local DB cache
                                        self.load_from_local_cache();
                                    }
                                }
                            } else {
                                // No cached phrase — fall back to local DB cache
                                self.load_from_local_cache();
                            }
                        }
                    }

                    self.state.rebuild_conversations();
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                    self.load_rx = Some(rx);
                    ctx.request_repaint_after(Duration::from_millis(50));
                }
                Err(_) => { /* sender dropped */ }
            }
        }

        // ── Drain periodic refresh result ──────────────────────────────────────
        if let Ok(mut slot) = REFRESH_RESULT.try_lock() {
            if let Some((contacts, transfers, identity, groups)) = slot.take() {
                // Merge daemon contacts with local nicknames.
                let local_nicknames: HashMap<String, Option<String>> = self.state.contacts
                    .iter()
                    .map(|c| (c.id.clone(), c.nickname.clone()))
                    .collect();
                let mut merged_contacts = contacts;
                for c in &mut merged_contacts {
                    if let Some(nick) = local_nicknames.get(&c.id) {
                        c.nickname = nick.clone();
                    }
                }
                self.state.contacts = merged_contacts;
                self.state.groups = groups;
                self.state.transfers = transfers;
                if identity.is_some() {
                    self.state.identity = identity;
                    self.save_identity_to_db();
                    self.save_recovery_phrase_to_db();
                }
                self.save_contacts_to_db();
                self.state.rebuild_conversations();

                // Detect changes and fire OS notifications
                self.diff_and_notify();
            }
        }

        // ── Schedule next background refresh ──────────────────────────────────
        if self.last_refresh.elapsed() > REFRESH_INTERVAL && self.state.page != Page::Onboarding {
            self.last_refresh = Instant::now();
            self.spawn_refresh();
        }

        // ── Update toasts ─────────────────────────────────────────────────────
        self.toasts.update(dt);

        // ── Page routing ───────────────────────────────────────────────────────
        let tokens = DesignTokens::current();

        // ── App lock ──────────────────────────────────────────────────────────
        if self.state.locked {
            egui::CentralPanel::default()
                .frame(design::panel_frame(&tokens))
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() / 4.0);
                        ui.label(
                            egui::RichText::new("🔒")
                                .size(56.0)
                                .color(tokens.palette.text_disabled),
                        );
                        ui.add_space(tokens.spacing.md);
                        ui.label(
                            egui::RichText::new("TransferDaemon is locked")
                                .size(18.0)
                                .color(tokens.palette.text_primary),
                        );
                        ui.add_space(tokens.spacing.sm);
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut self.state.lock_input)
                                .password(true)
                                .hint_text("Enter PIN…")
                                .desired_width(220.0),
                        );
                        resp.request_focus();
                        let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                        let mut attempt = || {
                            let digest = blake3::hash(self.state.lock_input.as_bytes()).to_hex().to_string();
                            if Some(&digest) == self.state.pin_hash.as_ref() {
                                self.state.locked = false;
                                self.state.lock_input.clear();
                            }
                        };
                        if enter && resp.has_focus() {
                            attempt();
                        }
                        if ui
                            .add_sized(
                                [220.0, 36.0],
                                egui::Button::new(
                                    egui::RichText::new("Unlock")
                                        .color(tokens.palette.text_inverse),
                                )
                                .fill(tokens.palette.accent)
                                .rounding(tokens.spacing.button_rounding),
                            )
                            .clicked()
                        {
                            attempt();
                        }
                    });
                });
            return;
        }

        match self.state.page {
            Page::Onboarding => {
                egui::CentralPanel::default()
                    .frame(design::panel_frame(&tokens))
                    .show(ctx, |ui| {
                        self.onboarding.show(ui, ctx, &mut self.state);
                    });

                // After identity created/restored via onboarding, persist it.
                if self.state.page != Page::Onboarding {
                    self.save_identity_to_db();
                    self.save_recovery_phrase_to_db();
                    self.save_contacts_to_db();
                }
            }

            Page::Home => {
                let layout_mode = self.state.layout_mode;
                self.home.show(ctx, &mut self.state, &mut self.chat, layout_mode);
                // Persist any nickname saved by the inline editor.
                if let Some((id, nick)) = self.home.take_pending_nickname_save() {
                    self.set_contact_nickname(&id, nick);
                }
            }

            Page::Chat => {
                egui::CentralPanel::default()
                    .frame(design::panel_frame(&tokens))
                    .show(ctx, |ui| {
                        self.chat.enter(&mut self.state);
                        self.chat.show(ui, &mut self.state);
                    });

                // Persist any color changes set by the chat settings panel.
                if let Some((id, color)) = self.chat.take_pending_color_save() {
                    self.set_contact_color(id, color);
                }

                // Persist any nickname changes set by the chat header (future extension).
            }

            Page::GroupChat => {
                egui::CentralPanel::default()
                    .frame(design::panel_frame(&tokens))
                    .show(ctx, |ui| {
                        self.group_chat.enter(&mut self.state);
                        self.group_chat.show(ui, &mut self.state);
                    });
            }
        }

        // ── Render toasts ─────────────────────────────────────────────────────
        self.toasts.show(ctx);

        // ── Android: relay egui clipboard output to ClipboardManager ──────────
        #[cfg(target_os = "android")]
        {
            let copied = ctx.output(|o| o.copied_text.clone());
            if !copied.is_empty() {
                crate::platform_hooks::request_copy_to_clipboard(copied);
            }
        }

        // ── Android: global keyboard show/hide based on egui focus state ───────
        // Only fires on state CHANGE — avoids resetting the IME InputConnection
        // every frame (which causes text-doubling on devices like Nokia 7.2).
        #[cfg(target_os = "android")]
        {
            let wants = ctx.wants_keyboard_input();
            if wants != self.keyboard_was_wanted {
                self.keyboard_was_wanted = wants;
                if wants {
                    crate::platform_hooks::request_show_keyboard();
                } else {
                    crate::platform_hooks::request_hide_keyboard();
                }
            }
        }

        // ── Repaint scheduling ─────────────────────────────────────────────────
        // During text input use a 100 ms heartbeat as a fallback for any event
        // that might have been queued between notify_repaint() and the next frame.
        #[cfg(target_os = "android")]
        if ctx.wants_keyboard_input() {
            ctx.request_repaint_after(Duration::from_millis(100));
        } else if !self.state.transfers.is_empty() || self.state.page == Page::Chat {
            ctx.request_repaint_after(Duration::from_millis(250));
        } else {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        #[cfg(not(target_os = "android"))]
        if !self.state.transfers.is_empty() || self.state.page == Page::Chat {
            ctx.request_repaint_after(Duration::from_millis(250));
        } else {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }
}

// ---------------------------------------------------------------------------
// Theme (kept for backwards compatibility — delegates to design module)
// ---------------------------------------------------------------------------

pub fn apply_theme(ctx: &Context) {
    design::apply_theme(ctx, Theme::Oled);
}
