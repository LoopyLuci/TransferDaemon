use crate::types::*;
use async_trait::async_trait;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait DaemonApi: Send + Sync {
    async fn get_identity(&self) -> Option<Identity>;
    async fn create_identity(&self, display_name: String) -> Result<String, DaemonError>;
    async fn restore_identity(&self, phrase: String) -> Result<Identity, DaemonError>;
    async fn get_contacts(&self) -> Vec<Contact>;
    async fn add_contact(&self, public_key: String, name: String) -> Result<Contact, DaemonError>;
    /// Full rename UI lives in the egui app; the TUI wires block/unblock/delete.
    #[allow(dead_code)]
    async fn rename_contact(&self, contact_id: String, name: String) -> Result<Contact, DaemonError>;
    async fn remove_contact(&self, contact_id: String) -> Result<(), DaemonError>;
    async fn block_contact(&self, contact_id: String) -> Result<Contact, DaemonError>;
    async fn unblock_contact(&self, contact_id: String) -> Result<Contact, DaemonError>;
    async fn get_messages(&self, contact_id: &str) -> Vec<Message>;
    async fn send_text(&self, contact_id: &str, text: String) -> Result<Message, DaemonError>;
    async fn get_transfers(&self) -> Vec<TransferStatus>;
    async fn send_file(&self, contact_id: &str, path: String) -> Result<Message, DaemonError>;
    async fn start_call(&self, contact_id: &str) -> Result<String, DaemonError>;
    async fn end_call(&self, call_id: &str) -> Result<(), DaemonError>;
    // Groups (wired in the egui app; TUI exposes them for completeness)
    #[allow(dead_code)]
    async fn get_groups(&self) -> Vec<Group>;
    #[allow(dead_code)]
    async fn create_group(&self, name: String, member_ids: Vec<String>) -> Result<Group, DaemonError>;
    #[allow(dead_code)]
    async fn send_group_text(&self, group_id: &str, text: String) -> Result<Message, DaemonError>;
    #[allow(dead_code)]
    async fn get_group_messages(&self, group_id: &str) -> Vec<Message>;
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, thiserror::Error)]
pub enum DaemonError {
    #[error("Daemon not reachable: {0}")]
    NotReachable(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

// ---------------------------------------------------------------------------
// MockDaemon
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    identity: Option<Identity>,
    contacts: Vec<Contact>,
    groups: Vec<Group>,
    messages: HashMap<String, Vec<Message>>,
    transfers: Vec<TransferStatus>,
    next_id: u64,
}

impl MockState {
    fn next_id(&mut self) -> String {
        self.next_id += 1;
        format!("id-{}", self.next_id)
    }
}

pub struct MockDaemon {
    state: Arc<Mutex<MockState>>,
}

impl MockDaemon {
    pub fn new() -> Self {
        let mut state = MockState::default();

        let alice = Contact {
            id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            name: "Alice".into(),
            last_seen_ts: Some(now_ts() - 120),
            online: true,
            blocked: false,
        };
        let bob = Contact {
            id: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3".into(),
            name: "Bob".into(),
            last_seen_ts: Some(now_ts() - 3600),
            online: false,
            blocked: false,
        };
        let alice_msgs = vec![
            Message {
                id: "m1".into(),
                contact_id: alice.id.clone(),
                outbound: false,
                content: MessageContent::Text("Hey! Did you get the files?".into()),
                timestamp_ts: now_ts() - 300,
                status: MessageStatus::Read,
            },
            Message {
                id: "m2".into(),
                contact_id: alice.id.clone(),
                outbound: true,
                content: MessageContent::Text("Yes, all 50 GB arrived. The relay route was flawless.".into()),
                timestamp_ts: now_ts() - 240,
                status: MessageStatus::Read,
            },
        ];
        let transfers = vec![TransferStatus {
            id: "t1".into(),
            contact_name: "Alice".into(),
            file_name: "dataset_v2.parquet".into(),
            size_bytes: 104_857_600,
            transferred_bytes: 37_748_736,
            outbound: true,
            lanes_active: 2,
            bps: 8_000_000,
        }];
        state.messages.insert(alice.id.clone(), alice_msgs);
        state.contacts.push(alice);
        state.contacts.push(bob);
        state.transfers = transfers;
        Self { state: Arc::new(Mutex::new(state)) }
    }
}

impl Default for MockDaemon {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl DaemonApi for MockDaemon {
    async fn get_identity(&self) -> Option<Identity> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).identity.clone()
    }

    async fn create_identity(&self, display_name: String) -> Result<String, DaemonError> {
        let mut entropy = [0u8; 16];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| DaemonError::InvalidInput(format!("mnemonic: {e}")))?;
        let phrase = mnemonic.to_string();
        let seed = mnemonic.to_seed("");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            seed[..32].try_into().expect("seed slice"),
        );
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        self.state.lock().unwrap_or_else(|e| e.into_inner()).identity = Some(Identity { public_key, display_name });
        Ok(phrase)
    }

    async fn restore_identity(&self, phrase: String) -> Result<Identity, DaemonError> {
        let mnemonic = phrase.trim().parse::<bip39::Mnemonic>()
            .map_err(|e| DaemonError::InvalidInput(format!("Invalid phrase: {e}")))?;
        let seed = mnemonic.to_seed("");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            seed[..32].try_into().expect("seed slice"),
        );
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let identity = Identity { public_key, display_name: "Restored".into() };
        self.state.lock().unwrap_or_else(|e| e.into_inner()).identity = Some(identity.clone());
        Ok(identity)
    }

    async fn get_contacts(&self) -> Vec<Contact> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).contacts.clone()
    }

    async fn add_contact(&self, public_key: String, name: String) -> Result<Contact, DaemonError> {
        if public_key.len() != 64 {
            return Err(DaemonError::InvalidInput("Public key must be 64 hex chars".into()));
        }
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.contacts.iter().any(|c| c.id == public_key) {
            return Err(DaemonError::InvalidInput("Contact already exists".into()));
        }
        let c = Contact { id: public_key, name, last_seen_ts: None, online: false, blocked: false };
        s.contacts.push(c.clone());
        Ok(c)
    }

    // Full rename UI lives in the egui app; the TUI wires block/unblock/delete.
    #[allow(dead_code)]
    async fn rename_contact(&self, contact_id: String, name: String) -> Result<Contact, DaemonError> {
        if name.trim().is_empty() {
            return Err(DaemonError::InvalidInput("name required".into()));
        }
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let contact = s.contacts.iter_mut().find(|c| c.id == contact_id)
            .ok_or(DaemonError::InvalidInput("contact not found".into()))?;
        contact.name = name;
        Ok(contact.clone())
    }

    async fn remove_contact(&self, contact_id: String) -> Result<(), DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.contacts.retain(|c| c.id != contact_id);
        s.messages.remove(&contact_id);
        Ok(())
    }

    async fn block_contact(&self, contact_id: String) -> Result<Contact, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let contact = s.contacts.iter_mut().find(|c| c.id == contact_id)
            .ok_or(DaemonError::InvalidInput("contact not found".into()))?;
        contact.blocked = true;
        Ok(contact.clone())
    }

    async fn unblock_contact(&self, contact_id: String) -> Result<Contact, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let contact = s.contacts.iter_mut().find(|c| c.id == contact_id)
            .ok_or(DaemonError::InvalidInput("contact not found".into()))?;
        contact.blocked = false;
        Ok(contact.clone())
    }

    async fn get_messages(&self, contact_id: &str) -> Vec<Message> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).messages.get(contact_id).cloned().unwrap_or_default()
    }

    async fn send_text(&self, contact_id: &str, text: String) -> Result<Message, DaemonError> {
        if text.trim().is_empty() {
            return Err(DaemonError::InvalidInput("Empty message".into()));
        }
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let id = s.next_id();
        let msg = Message {
            id,
            contact_id: contact_id.to_owned(),
            outbound: true,
            content: MessageContent::Text(text),
            timestamp_ts: now_ts(),
            status: MessageStatus::Sent,
        };
        s.messages.entry(contact_id.to_owned()).or_default().push(msg.clone());
        Ok(msg)
    }

    async fn get_transfers(&self) -> Vec<TransferStatus> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).transfers.clone()
    }

    async fn send_file(&self, contact_id: &str, path: String) -> Result<Message, DaemonError> {
        let p = std::path::Path::new(&path);
        let file_name = p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
        let size_bytes = std::fs::metadata(p)
            .map(|m| m.len())
            .map_err(|e| DaemonError::InvalidInput(format!("cannot read file: {e}")))?;
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let id = s.next_id();
        let msg = Message {
            id,
            contact_id: contact_id.to_owned(),
            outbound: true,
            content: MessageContent::File {
                name: file_name.clone(),
                size_bytes,
                transferred_bytes: 0,
                mime: None,
            },
            timestamp_ts: now_ts(),
            status: MessageStatus::Sent,
        };
        s.messages.entry(contact_id.to_owned()).or_default().push(msg.clone());
        let tid = s.next_id();
        s.transfers.push(TransferStatus {
            id: tid,
            contact_name: contact_id.to_owned(),
            file_name,
            size_bytes,
            transferred_bytes: 0,
            outbound: true,
            lanes_active: 1,
            bps: 0,
        });
        Ok(msg)
    }

    async fn start_call(&self, _contact_id: &str) -> Result<String, DaemonError> {
        Ok(format!("mock-call-{}", now_ts()))
    }

    async fn end_call(&self, _call_id: &str) -> Result<(), DaemonError> {
        Ok(())
    }

    async fn get_groups(&self) -> Vec<Group> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).groups.clone()
    }

    async fn create_group(&self, name: String, _member_ids: Vec<String>) -> Result<Group, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let id = s.next_id();
        let g = Group {
            id,
            name,
            owner: "self".into(),
            members: vec![],
            created_at: now_ts(),
        };
        s.groups.push(g.clone());
        Ok(g)
    }

    async fn send_group_text(&self, group_id: &str, text: String) -> Result<Message, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let id = s.next_id();
        let msg = Message {
            id,
            contact_id: group_id.to_owned(),
            outbound: true,
            content: MessageContent::Text(text),
            timestamp_ts: now_ts(),
            status: MessageStatus::Sent,
        };
        s.messages.entry(group_id.to_owned()).or_default().push(msg.clone());
        Ok(msg)
    }

    async fn get_group_messages(&self, group_id: &str) -> Vec<Message> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
            .messages.get(group_id).cloned().unwrap_or_default()
    }
}
