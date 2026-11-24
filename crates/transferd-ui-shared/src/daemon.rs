//! DaemonApi — async interface to the transferd daemon.

use crate::types::{
    Connection, Contact, Group, GroupMember, Identity, Message, MessageContent, MessageStatus,
    TransferStatus, UpdateStatus,
};
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
    async fn add_contact(&self, public_key: String, name: String, address: Option<String>) -> Result<Contact, DaemonError>;
    async fn rename_contact(&self, contact_id: &str, name: String) -> Result<Contact, DaemonError>;
    async fn remove_contact(&self, contact_id: &str) -> Result<(), DaemonError>;
    async fn block_contact(&self, contact_id: &str) -> Result<Contact, DaemonError>;
    async fn unblock_contact(&self, contact_id: &str) -> Result<Contact, DaemonError>;
    async fn get_messages(&self, contact_id: &str) -> Vec<Message>;
    async fn search_messages(&self, contact_id: &str, query: &str) -> Vec<Message>;
    async fn send_text(&self, contact_id: &str, text: String) -> Result<Message, DaemonError>;
    async fn send_reply(&self, contact_id: &str, text: String, reply_to: String) -> Result<Message, DaemonError>;
    async fn send_typing(&self, contact_id: &str, is_typing: bool);
    async fn toggle_reaction(&self, contact_id: &str, target_msg_id: &str, emoji: &str);
    async fn get_transfers(&self) -> Vec<TransferStatus>;
    async fn send_file(&self, contact_id: &str, path: String) -> Result<Message, DaemonError>;
    async fn cancel_transfer(&self, transfer_id: &str) -> Result<(), DaemonError>;
    async fn pause_transfer(&self, transfer_id: &str) -> Result<(), DaemonError>;
    async fn resume_transfer(&self, transfer_id: &str) -> Result<(), DaemonError>;
    async fn get_public_key_hex(&self) -> Option<String>;
    async fn get_setting(&self, key: &str) -> Option<String>;
    async fn set_setting(&self, key: &str, value: &str) -> Result<(), DaemonError>;
    // Groups
    async fn get_groups(&self) -> Vec<Group>;
    async fn create_group(&self, name: String, member_ids: Vec<String>) -> Result<Group, DaemonError>;
    async fn rename_group(&self, group_id: &str, name: String) -> Result<Group, DaemonError>;
    async fn add_group_members(&self, group_id: &str, member_ids: Vec<String>) -> Result<Group, DaemonError>;
    async fn remove_group_members(&self, group_id: &str, member_ids: Vec<String>) -> Result<Group, DaemonError>;
    async fn leave_group(&self, group_id: &str) -> Result<(), DaemonError>;
    async fn delete_group(&self, group_id: &str) -> Result<(), DaemonError>;
    async fn get_group_messages(&self, group_id: &str) -> Vec<Message>;
    async fn send_group_text(&self, group_id: &str, text: String) -> Result<Message, DaemonError>;
    // Connections (transport control center)
    async fn get_connections(&self) -> Vec<Connection>;
    async fn set_connection_policy(&self, connection_id: &str, policy: &str) -> Result<(), DaemonError>;
    // Safety numbers
    async fn get_safety_number(&self, contact_id: &str) -> (String, bool);
    // Updates (manual, opt-in)
    async fn check_for_updates(&self) -> UpdateStatus;
    async fn apply_update(&self) -> Result<(), DaemonError>;
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
    #[error("Not set up")]
    NotSetUp,
}

// ---------------------------------------------------------------------------
// MockDaemon
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    identity: Option<Identity>,
    contacts: Vec<Contact>,
    messages: HashMap<String, Vec<Message>>,
    transfers: Vec<TransferStatus>,
    groups: HashMap<String, Group>,
    settings: HashMap<String, String>,
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
            nickname: None,
            last_seen_ts: Some(now_ts() - 120),
            online: true,
            blocked: false,
            typing: false,
        };
        let bob = Contact {
            id: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3".into(),
            name: "Bob".into(),
            nickname: None,
            last_seen_ts: Some(now_ts() - 3600),
            online: false,
            blocked: false,
            typing: false,
        };

        let alice_msgs = vec![
            Message {
                id: "m1".into(),
                contact_id: alice.id.clone(),
                outbound: false,
                content: MessageContent::Text("Hey! Did you get the files?".into()),
                timestamp_ts: now_ts() - 300,
                status: MessageStatus::Read,
                group_id: None,
                sender_pk: None,
                reply_to: None,
                reactions: Vec::new(),
            },
            Message {
                id: "m2".into(),
                contact_id: alice.id.clone(),
                outbound: true,
                content: MessageContent::Text("Yes, all 50 GB arrived — zero corruption. The relay route was flawless.".into()),
                timestamp_ts: now_ts() - 240,
                status: MessageStatus::Read,
                group_id: None,
                sender_pk: None,
                reply_to: None,
                reactions: Vec::new(),
            },
            Message {
                id: "m3".into(),
                contact_id: alice.id.clone(),
                outbound: false,
                content: MessageContent::File {
                    name: "archive_2026.tar.zst".into(),
                    size_bytes: 52_428_800,
                    transferred_bytes: 52_428_800,
                    mime: Some("application/zstd".into()),
                },
                timestamp_ts: now_ts() - 60,
                status: MessageStatus::Delivered,
                group_id: None,
                sender_pk: None,
                reply_to: None,
                reactions: Vec::new(),
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
            paused: false,
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
        let identity = Identity { public_key, display_name, phrase: phrase.clone() };
        self.state.lock().unwrap_or_else(|e| e.into_inner()).identity = Some(identity);
        Ok(phrase)
    }

    async fn restore_identity(&self, phrase: String) -> Result<Identity, DaemonError> {
        let mnemonic = phrase.trim().parse::<bip39::Mnemonic>()
            .map_err(|e| DaemonError::InvalidInput(format!("Invalid recovery phrase: {e}")))?;
        let seed = mnemonic.to_seed("");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            seed[..32].try_into().expect("seed slice"),
        );
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let identity = Identity { public_key, display_name: "Restored User".into(), phrase };
        self.state.lock().unwrap_or_else(|e| e.into_inner()).identity = Some(identity.clone());
        Ok(identity)
    }

    async fn get_contacts(&self) -> Vec<Contact> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).contacts.clone()
    }

    async fn add_contact(&self, public_key: String, name: String, address: Option<String>) -> Result<Contact, DaemonError> {
        if public_key.len() != 64 {
            return Err(DaemonError::InvalidInput("Public key must be 64 hex chars".into()));
        }
        let contact = Contact {
            id: public_key,
            name,
            nickname: None,
            last_seen_ts: None,
            online: false,
            blocked: false,
            typing: false,
        };
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.contacts.iter().any(|c| c.id == contact.id) {
            return Err(DaemonError::InvalidInput("contact already exists".into()));
        }
        s.contacts.push(contact.clone());
        let _ = address;
        Ok(contact)
    }

    async fn rename_contact(&self, contact_id: &str, name: String) -> Result<Contact, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let c = s.contacts.iter_mut().find(|c| c.id == contact_id)
            .ok_or(DaemonError::NotSetUp)?;
        c.nickname = Some(name);
        Ok(c.clone())
    }

    async fn remove_contact(&self, contact_id: &str) -> Result<(), DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.contacts.retain(|c| c.id != contact_id);
        Ok(())
    }

    async fn block_contact(&self, contact_id: &str) -> Result<Contact, DaemonError> {
        self.set_blocked(contact_id, true)
    }

    async fn unblock_contact(&self, contact_id: &str) -> Result<Contact, DaemonError> {
        self.set_blocked(contact_id, false)
    }

    async fn get_messages(&self, contact_id: &str) -> Vec<Message> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
            .messages.get(contact_id).cloned().unwrap_or_default()
    }

    async fn search_messages(&self, contact_id: &str, query: &str) -> Vec<Message> {
        let q = query.to_lowercase();
        self.state.lock().unwrap_or_else(|e| e.into_inner())
            .messages.get(contact_id)
            .map(|msgs| msgs.iter()
                .filter(|m| m.content.preview().to_lowercase().contains(&q))
                .cloned().collect())
            .unwrap_or_default()
    }

    async fn send_text(&self, contact_id: &str, text: String) -> Result<Message, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let id = s.next_id();
        let msg = Message {
            id,
            contact_id: contact_id.to_owned(),
            outbound: true,
            content: MessageContent::Text(text),
            timestamp_ts: now_ts(),
            status: MessageStatus::Sent,
            group_id: None,
            sender_pk: None,
            reply_to: None,
            reactions: Vec::new(),
        };
        s.messages.entry(contact_id.to_owned()).or_default().push(msg.clone());
        Ok(msg)
    }

    async fn send_reply(&self, contact_id: &str, text: String, reply_to: String) -> Result<Message, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let id = s.next_id();
        let msg = Message {
            id,
            contact_id: contact_id.to_owned(),
            outbound: true,
            content: MessageContent::Text(text),
            timestamp_ts: now_ts(),
            status: MessageStatus::Sent,
            group_id: None,
            sender_pk: None,
            reply_to: Some(reply_to),
            reactions: Vec::new(),
        };
        s.messages.entry(contact_id.to_owned()).or_default().push(msg.clone());
        Ok(msg)
    }

    async fn send_typing(&self, _contact_id: &str, _is_typing: bool) {}

    async fn toggle_reaction(&self, contact_id: &str, target_msg_id: &str, emoji: &str) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for msgs in s.messages.values_mut() {
            if let Some(m) = msgs.iter_mut().find(|m| m.id == target_msg_id) {
                if let Some(pos) = m.reactions.iter().position(|(e, _)| e == emoji) {
                    m.reactions.remove(pos);
                } else {
                    m.reactions.push((emoji.to_owned(), contact_id.to_owned()));
                }
                return;
            }
        }
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
                transferred_bytes: size_bytes,
                mime: None,
            },
            timestamp_ts: now_ts(),
            status: MessageStatus::Sent,
            group_id: None,
            sender_pk: None,
            reply_to: None,
            reactions: Vec::new(),
        };
        s.messages.entry(contact_id.to_owned()).or_default().push(msg.clone());
        let tid = s.next_id();
        s.transfers.push(TransferStatus {
            id: tid,
            contact_name: contact_id.to_owned(),
            file_name,
            size_bytes,
            transferred_bytes: size_bytes,
            outbound: true,
            lanes_active: 1,
            bps: 0,
            paused: false,
        });
        Ok(msg)
    }

    async fn cancel_transfer(&self, _transfer_id: &str) -> Result<(), DaemonError> { Ok(()) }

    async fn pause_transfer(&self, _transfer_id: &str) -> Result<(), DaemonError> { Ok(()) }

    async fn resume_transfer(&self, _transfer_id: &str) -> Result<(), DaemonError> { Ok(()) }

    async fn get_public_key_hex(&self) -> Option<String> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).identity.as_ref().map(|id| id.public_key.clone())
    }

    async fn get_setting(&self, key: &str) -> Option<String> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).settings.get(key).cloned()
    }

    async fn set_setting(&self, key: &str, value: &str) -> Result<(), DaemonError> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).settings.insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    async fn get_groups(&self) -> Vec<Group> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).groups.values().cloned().collect()
    }

    async fn create_group(&self, name: String, member_ids: Vec<String>) -> Result<Group, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let owner = s.identity.as_ref().map(|i| i.public_key.clone()).unwrap_or_default();
        let group = Group {
            id: s.next_id(),
            name,
            owner: owner.clone(),
            members: member_ids.into_iter().map(|pk| GroupMember { public_key: pk, role: 2 }).collect(),
            created_at: now_ts(),
        };
        s.groups.insert(group.id.clone(), group.clone());
        Ok(group)
    }

    async fn rename_group(&self, group_id: &str, name: String) -> Result<Group, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let g = s.groups.get_mut(group_id).ok_or(DaemonError::NotSetUp)?;
        g.name = name;
        Ok(g.clone())
    }

    async fn add_group_members(&self, group_id: &str, member_ids: Vec<String>) -> Result<Group, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let g = s.groups.get_mut(group_id).ok_or(DaemonError::NotSetUp)?;
        for pk in member_ids {
            if !g.members.iter().any(|m| m.public_key == pk) {
                g.members.push(GroupMember { public_key: pk, role: 0 });
            }
        }
        Ok(g.clone())
    }

    async fn remove_group_members(&self, group_id: &str, member_ids: Vec<String>) -> Result<Group, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let g = s.groups.get_mut(group_id).ok_or(DaemonError::NotSetUp)?;
        g.members.retain(|m| !member_ids.contains(&m.public_key));
        Ok(g.clone())
    }

    async fn leave_group(&self, group_id: &str) -> Result<(), DaemonError> {
        self.delete_group(group_id).await
    }

    async fn delete_group(&self, group_id: &str) -> Result<(), DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.groups.remove(group_id);
        Ok(())
    }

    async fn get_group_messages(&self, group_id: &str) -> Vec<Message> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
            .messages.get(group_id).cloned().unwrap_or_default()
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
            group_id: Some(group_id.to_owned()),
            sender_pk: s.identity.as_ref().map(|i| i.public_key.clone()),
            reply_to: None,
            reactions: Vec::new(),
        };
        s.messages.entry(group_id.to_owned()).or_default().push(msg.clone());
        Ok(msg)
    }

    async fn get_connections(&self) -> Vec<Connection> {
        vec![
            Connection {
                id: "if:wlan0".into(),
                name: "wlan0".into(),
                kind: "wifi".into(),
                enabled: true,
                online: true,
                link_speed_bps: 650_000_000,
                rtt_ms: 12.0,
                bandwidth_bps: 50_000_000,
                policy: String::new(),
            },
            Connection {
                id: "if:eth0".into(),
                name: "eth0".into(),
                kind: "ethernet".into(),
                enabled: true,
                online: true,
                link_speed_bps: 1_000_000_000,
                rtt_ms: 1.0,
                bandwidth_bps: 900_000_000,
                policy: String::new(),
            },
        ]
    }

    async fn set_connection_policy(&self, _connection_id: &str, _policy: &str) -> Result<(), DaemonError> {
        Ok(())
    }

    async fn get_safety_number(&self, contact_id: &str) -> (String, bool) {
        // Mock: deterministic Signal-style number derived from the contact id.
        let digest = blake3::hash(contact_id.as_bytes());
        let mut out = String::with_capacity(71);
        for g in 0..12 {
            if g > 0 {
                out.push(' ');
            }
            for k in 0..5 {
                let idx = (g * 5 + k) % 32;
                out.push(char::from(b'0' + (digest.as_bytes()[idx] % 10)));
            }
        }
        (out, true)
    }

    async fn check_for_updates(&self) -> UpdateStatus {
        UpdateStatus {
            current_version: "0.1.0".into(),
            has_update: false,
            ..Default::default()
        }
    }

    async fn apply_update(&self) -> Result<(), DaemonError> {
        Err(DaemonError::NotSetUp)
    }
}

impl MockDaemon {
    fn set_blocked(&self, contact_id: &str, blocked: bool) -> Result<Contact, DaemonError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let c = s.contacts.iter_mut().find(|c| c.id == contact_id)
            .ok_or(DaemonError::NotSetUp)?;
        c.blocked = blocked;
        Ok(c.clone())
    }
}