use crate::daemon::DaemonApi;
use crate::types::*;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use transferd_tui_video::VideoCallOverlay;
use transferd_webrtc::{new_default_capture, SimulatedCallSession};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Chats,
    Contacts,
    Transfers,
    Settings,
    Telemetry,
}

impl Tab {
    pub fn index(self) -> usize {
        match self {
            Self::Chats     => 0,
            Self::Contacts  => 1,
            Self::Transfers => 2,
            Self::Settings  => 3,
            Self::Telemetry => 4,
        }
    }
}

// ---------------------------------------------------------------------------
// Telemetry state
// ---------------------------------------------------------------------------

pub struct TelemetryState {
    pub cpu_pct:         f32,
    pub mem_rss_kb:      u64,
    pub uptime_secs:     u64,
    pub active_sessions: u32,
    /// Recent event summaries: (age_label, kind_tag, summary)
    pub log: VecDeque<(String, &'static str, String)>,
    /// Per-second ATE event timestamps for the sparkline.
    pub ate_ts: VecDeque<u64>,
    pub stream_rx: Option<tokio::sync::mpsc::UnboundedReceiver<transferd_api::TelemetryEventMsg>>,
}

impl Default for TelemetryState {
    fn default() -> Self {
        Self {
            cpu_pct: 0.0,
            mem_rss_kb: 0,
            uptime_secs: 0,
            active_sessions: 0,
            log: VecDeque::with_capacity(200),
            ate_ts: VecDeque::with_capacity(3_000),
            stream_rx: None,
        }
    }
}

impl TelemetryState {
    pub fn drain(&mut self) {
        let mut collected = vec![];
        if let Some(rx) = &mut self.stream_rx {
            while let Ok(msg) = rx.try_recv() {
                collected.push(msg);
            }
        }
        for msg in collected {
            use transferd_api::proto::telemetry_event_msg::Event;
            let Some(ev) = msg.event else { continue };
            match ev {
                Event::SystemHealth(h) => {
                    self.cpu_pct = h.cpu_pct;
                    self.mem_rss_kb = h.mem_rss_kb;
                    self.uptime_secs = h.uptime_secs;
                    self.active_sessions = h.active_sessions;
                    let summary = format!(
                        "CPU {:.1}%  RSS {}MiB  up {}s  sessions {}",
                        h.cpu_pct,
                        h.mem_rss_kb / 1024,
                        h.uptime_secs,
                        h.active_sessions,
                    );
                    self.push_log("SYS", summary);
                }
                Event::AteLane(a) => {
                    while self.ate_ts.len() >= 3_000 { self.ate_ts.pop_front(); }
                    self.ate_ts.push_back(a.ts);
                    let summary = format!(
                        "lane {}  gsn {}  rtt {:.1}ms  bw {:.0}Kbps",
                        a.selected_lane, a.gsn, a.rtt_ms, a.bandwidth_bps as f64 / 1_000.0,
                    );
                    self.push_log("ATE", summary);
                }
            }
        }
    }

    fn push_log(&mut self, tag: &'static str, summary: String) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if self.log.len() >= 200 { self.log.pop_front(); }
        self.log.push_back((format!("{ts}"), tag, summary));
    }

    /// Compute per-second ATE event counts for the last `secs` seconds.
    pub fn sparkline(&self, secs: usize) -> Vec<u32> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut counts = vec![0u32; secs];
        for &ts in &self.ate_ts {
            let age = now.saturating_sub(ts) as usize;
            if age < secs {
                counts[secs - 1 - age] += 1;
            }
        }
        counts
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardingStep {
    Welcome,
    EnterName,
    ShowPhrase { phrase: String },
    ConfirmPhrase { phrase: String },
    EnterPhrase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    Onboarding(OnboardingStep),
    Main,
}

/// Which pane has keyboard focus in the Chats tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatFocus {
    ContactList,
    Messages,
    Input,
}

/// Active modal / popup layer.
#[derive(Debug, Clone)]
pub enum Modal {
    AddContact { key_input: String, name_input: String, field: usize },
    SendFile { path_input: String },
    ConfirmDelete { label: String, contact_id: String },
    ShowQr { hex: String },
    RevealPhrase { phrase: String },
}

/// Live call state — wraps the WebRTC session and terminal video overlay.
pub struct CallState {
    pub contact_name: String,
    pub call_id: String,
    pub started_at: Instant,
    pub muted: bool,
    pub video_enabled: bool,
    /// Terminal video renderer; `None` for audio-only calls.
    pub video: Option<VideoCallOverlay>,
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    pub daemon: Arc<dyn DaemonApi>,
    pub daemon_live: bool,
    /// gRPC endpoint address for the telemetry stream (e.g. "http://127.0.0.1:50051").
    pub daemon_addr: Option<String>,

    pub screen: Screen,
    pub tab: Tab,
    pub chat_focus: ChatFocus,

    pub identity: Option<Identity>,
    pub recovery_phrase: Option<String>,

    pub contacts: Vec<Contact>,
    pub messages: HashMap<String, Vec<Message>>,
    pub transfers: Vec<TransferStatus>,

    pub selected_contact: usize,
    pub contacts_selected: usize,
    pub transfers_selected: usize,

    pub msg_scroll: usize,

    pub modal: Option<Modal>,
    pub call_state: Option<CallState>,

    pub input: String,

    pub status: String,
    pub last_tick: Instant,

    pub telemetry: TelemetryState,
}

impl App {
    pub async fn new(daemon: Arc<dyn DaemonApi>, daemon_live: bool, daemon_addr: Option<String>) -> Self {
        let identity = daemon.get_identity().await;
        let contacts = daemon.get_contacts().await;
        let transfers = daemon.get_transfers().await;

        let screen = if identity.is_none() {
            Screen::Onboarding(OnboardingStep::Welcome)
        } else {
            Screen::Main
        };

        let mut messages = HashMap::new();
        for c in &contacts {
            let msgs = daemon.get_messages(&c.id).await;
            if !msgs.is_empty() {
                messages.insert(c.id.clone(), msgs);
            }
        }

        Self {
            daemon,
            daemon_live,
            daemon_addr,
            screen,
            tab: Tab::Chats,
            chat_focus: ChatFocus::ContactList,
            identity,
            recovery_phrase: None,
            contacts,
            messages,
            transfers,
            selected_contact: 0,
            contacts_selected: 0,
            transfers_selected: 0,
            msg_scroll: 0,
            modal: None,
            call_state: None,
            input: String::new(),
            status: String::new(),
            last_tick: Instant::now(),
            telemetry: TelemetryState::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    pub fn open_contact_id(&self) -> Option<&str> {
        self.contacts.get(self.selected_contact).map(|c| c.id.as_str())
    }

    pub fn open_contact_name(&self) -> Option<&str> {
        self.contacts.get(self.selected_contact).map(|c| c.name.as_str())
    }

    pub fn open_messages(&self) -> &[Message] {
        match self.open_contact_id() {
            Some(id) => self.messages.get(id).map(|v| v.as_slice()).unwrap_or(&[]),
            None => &[],
        }
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
    }

    pub fn clamp_contact_sel(&mut self) {
        if self.contacts.is_empty() { self.selected_contact = 0; }
        else { self.selected_contact = self.selected_contact.min(self.contacts.len() - 1); }
    }

    pub fn clamp_contacts_tab_sel(&mut self) {
        if self.contacts.is_empty() { self.contacts_selected = 0; }
        else { self.contacts_selected = self.contacts_selected.min(self.contacts.len() - 1); }
    }

    pub fn clamp_transfers_sel(&mut self) {
        if self.transfers.is_empty() { self.transfers_selected = 0; }
        else { self.transfers_selected = self.transfers_selected.min(self.transfers.len() - 1); }
    }

    // -----------------------------------------------------------------------
    // Periodic refresh
    // -----------------------------------------------------------------------

    pub async fn tick(&mut self) {
        self.transfers = self.daemon.get_transfers().await;
        // Refresh messages for open contact.
        if let Some(id) = self.open_contact_id().map(|s| s.to_owned()) {
            let msgs = self.daemon.get_messages(&id).await;
            self.messages.insert(id, msgs);
        }
        // Drain new video frames into the overlay.
        if let Some(cs) = &mut self.call_state {
            if let Some(video) = &mut cs.video {
                video.tick();
            }
        }
        // Drain telemetry events.
        self.telemetry.drain();
        self.last_tick = Instant::now();
    }

    /// Start a call to the currently selected contact.
    pub async fn start_call_to_selected(&mut self, video: bool) {
        let contact_name = match self.contacts.get(self.selected_contact) {
            Some(c) => c.name.clone(),
            None => { self.set_status("No contact selected."); return; }
        };
        let contact_id = self.contacts[self.selected_contact].id.clone();

        // Create the WebRTC session — real hardware when available, mock in CI.
        let media = new_default_capture(video);
        let session = SimulatedCallSession::new_outgoing(
            contact_id.clone(),
            video,
            Arc::clone(&media),
        ).await;
        session.activate().await;
        let call_id = session.call_id.clone();

        // Also tell the daemon (for gRPC signaling).
        let _ = self.daemon.start_call(&contact_id).await;

        // Build the video overlay if video is enabled.
        let video_overlay = if video {
            let mut overlay = VideoCallOverlay::new(contact_name.clone());
            if let Some(rx) = session.remote_video_rx {
                // remote_video_rx has been moved out — store it in the overlay.
                // (The session field below won't have it; that's fine for mock mode.)
                overlay.set_frame_rx(rx);
            }
            Some(overlay)
        } else {
            None
        };

        self.call_state = Some(CallState {
            contact_name: contact_name.clone(),
            call_id,
            started_at: Instant::now(),
            muted: false,
            video_enabled: video,
            video: video_overlay,
        });

        let mode = if video { "video" } else { "audio" };
        self.set_status(format!("Call started ({mode}). [M] mute  [H] hang up  [V] toggle video"));
    }
}
