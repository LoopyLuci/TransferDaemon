//! DaemonApi — async interface to the transferd daemon.
//!
//! The `DaemonApi` trait abstracts over the actual IPC mechanism (future: gRPC
//! over Unix socket / named pipe) and a `MockDaemon` for tests and offline dev.
//!
//! When the gRPC daemon API is implemented (Phase 7), `GrpcDaemon` will satisfy
//! this trait. Until then, `MockDaemon` drives the full UI without a running daemon.

use crate::types::{Contact, Identity, Message, MessageContent, MessageStatus, TransferStatus};
use async_trait::async_trait;
use rand::rngs::OsRng;
use rand::RngCore;
// bip39, ed25519_dalek, hex used in MockDaemon crypto methods below.
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
    /// Returns the node's own identity, or `None` if not yet set up.
    async fn get_identity(&self) -> Option<Identity>;

    /// Creates a new identity with the given display name.
    /// Returns the 12-word BIP-39-style recovery phrase.
    async fn create_identity(&self, display_name: String) -> Result<String, DaemonError>;

    /// Restores an identity from a recovery phrase.
    async fn restore_identity(&self, phrase: String) -> Result<Identity, DaemonError>;

    async fn get_contacts(&self) -> Vec<Contact>;

    async fn add_contact(&self, public_key: String, name: String) -> Result<Contact, DaemonError>;

    async fn get_messages(&self, contact_id: &str) -> Vec<Message>;

    async fn send_text(&self, contact_id: &str, text: String) -> Result<Message, DaemonError>;

    async fn get_transfers(&self) -> Vec<TransferStatus>;

    /// Send a local file to a contact. Returns the resulting file message.
    async fn send_file(&self, contact_id: &str, path: String) -> Result<Message, DaemonError>;

    /// Returns the hex-encoded public key for QR code display.
    async fn get_public_key_hex(&self) -> Option<String>;
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
// MockDaemon — in-memory implementation for tests and offline development
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    identity: Option<Identity>,
    contacts: Vec<Contact>,
    messages: HashMap<String, Vec<Message>>, // contact_id → messages
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

        // Pre-populate with demo data so the UI looks alive on first launch.
        let alice = Contact {
            id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            name: "Alice".into(),
            last_seen_ts: Some(now_ts() - 120),
            online: true,
        };
        let bob = Contact {
            id: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3".into(),
            name: "Bob".into(),
            last_seen_ts: Some(now_ts() - 3600),
            online: false,
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
                content: MessageContent::Text("Yes, all 50 GB arrived — zero corruption. The relay route was flawless.".into()),
                timestamp_ts: now_ts() - 240,
                status: MessageStatus::Read,
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
        self.state.lock().unwrap().identity.clone()
    }

    async fn create_identity(&self, display_name: String) -> Result<String, DaemonError> {
        // Generate 128 bits of fresh OS entropy → 12-word BIP-39 mnemonic.
        let mut entropy = [0u8; 16];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| DaemonError::InvalidInput(format!("mnemonic: {e}")))?;
        let phrase = mnemonic.to_string();

        // Derive Ed25519 key from BIP-39 seed (empty passphrase).
        let seed = mnemonic.to_seed("");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            seed[..32].try_into().expect("seed slice"),
        );
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());

        let identity = Identity { public_key, display_name };
        self.state.lock().unwrap().identity = Some(identity);
        Ok(phrase)
    }

    async fn restore_identity(&self, phrase: String) -> Result<Identity, DaemonError> {
        // Parse and validate the BIP-39 phrase.
        let mnemonic = phrase.trim().parse::<bip39::Mnemonic>()
            .map_err(|e| DaemonError::InvalidInput(format!("Invalid recovery phrase: {e}")))?;

        // Re-derive the same Ed25519 key deterministically.
        let seed = mnemonic.to_seed("");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            seed[..32].try_into().expect("seed slice"),
        );
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());

        let identity = Identity { public_key, display_name: "Restored User".into() };
        self.state.lock().unwrap().identity = Some(identity.clone());
        Ok(identity)
    }

    async fn get_contacts(&self) -> Vec<Contact> {
        self.state.lock().unwrap().contacts.clone()
    }

    async fn add_contact(&self, public_key: String, name: String) -> Result<Contact, DaemonError> {
        if public_key.len() != 64 {
            return Err(DaemonError::InvalidInput("Public key must be 64 hex chars".into()));
        }
        let contact = Contact { id: public_key, name, last_seen_ts: None, online: false };
        self.state.lock().unwrap().contacts.push(contact.clone());
        Ok(contact)
    }

    async fn get_messages(&self, contact_id: &str) -> Vec<Message> {
        self.state.lock().unwrap()
            .messages.get(contact_id).cloned().unwrap_or_default()
    }

    async fn send_text(&self, contact_id: &str, text: String) -> Result<Message, DaemonError> {
        let mut s = self.state.lock().unwrap();
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
        self.state.lock().unwrap().transfers.clone()
    }

    async fn send_file(&self, contact_id: &str, path: String) -> Result<Message, DaemonError> {
        let p = std::path::Path::new(&path);
        let file_name = p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
        let size_bytes = std::fs::metadata(p)
            .map(|m| m.len())
            .map_err(|e| DaemonError::InvalidInput(format!("cannot read file: {e}")))?;
        let mut s = self.state.lock().unwrap();
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
        });
        Ok(msg)
    }

    async fn get_public_key_hex(&self) -> Option<String> {
        self.state.lock().unwrap().identity.as_ref().map(|id| id.public_key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_create_identity() {
        let d = MockDaemon::new();
        assert!(d.get_identity().await.is_none());
        let phrase = d.create_identity("Alice".into()).await.unwrap();
        assert!(phrase.split_whitespace().count() >= 12);
        let id = d.get_identity().await.unwrap();
        assert_eq!(id.display_name, "Alice");
    }

    #[tokio::test]
    async fn test_mock_restore_identity_bad_phrase() {
        let d = MockDaemon::new();
        let err = d.restore_identity("too short".into()).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_mock_send_and_receive_message() {
        let d = MockDaemon::new();
        let contacts = d.get_contacts().await;
        let alice = contacts.iter().find(|c| c.name == "Alice").unwrap();
        let before = d.get_messages(&alice.id).await.len();

        d.send_text(&alice.id, "Hello from test".into()).await.unwrap();

        let after = d.get_messages(&alice.id).await;
        assert_eq!(after.len(), before + 1);
        assert!(matches!(after.last().unwrap().content, MessageContent::Text(_)));
    }

    #[tokio::test]
    async fn test_mock_add_contact_bad_key() {
        let d = MockDaemon::new();
        let err = d.add_contact("tooshort".into(), "Eve".into()).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_transfer_progress() {
        let t = TransferStatus {
            id: "t".into(),
            contact_name: "Bob".into(),
            file_name: "test.bin".into(),
            size_bytes: 1000,
            transferred_bytes: 250,
            outbound: true,
            lanes_active: 1,
            bps: 100,
        };
        assert!((t.progress() - 0.25).abs() < 0.001);
        assert_eq!(t.eta_secs(), Some(7)); // 750 bytes / 100 bps
    }
}
