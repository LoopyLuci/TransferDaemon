use crate::daemon::DaemonApi;
use crate::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Chats,
    Contacts,
    Transfers,
    Settings,
}

impl Tab {
    pub fn index(self) -> usize {
        match self { Self::Chats => 0, Self::Contacts => 1, Self::Transfers => 2, Self::Settings => 3 }
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

/// Live call state.
pub struct CallState {
    pub contact_name: String,
    pub call_id: String,
    pub started_at: Instant,
    pub muted: bool,
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    pub daemon: Arc<dyn DaemonApi>,
    pub daemon_live: bool,

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

    /// Single-line text input buffer shared across input contexts.
    pub input: String,
    /// Secondary input (e.g. name field in add-contact, confirm phrase).
    pub input2: String,

    pub status: String,
    pub last_tick: Instant,
}

impl App {
    pub async fn new(daemon: Arc<dyn DaemonApi>, daemon_live: bool) -> Self {
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
            input2: String::new(),
            status: String::new(),
            last_tick: Instant::now(),
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
        self.last_tick = Instant::now();
    }
}
