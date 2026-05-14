//! DaemonState — shared in-memory state for all gRPC service implementations.
//!
//! Persistence is write-through: every mutation calls `try_save()`, which
//! encrypts and writes `~/.local/share/transferdaemon/user_data.enc` (or the
//! platform equivalent) when a store path is configured.  In tests the path is
//! left `None` so saves are no-ops and no filesystem activity occurs.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use transferd_store::{PersistedUserData, StoreParams};
use zeroize::Zeroizing;

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Identity {
    /// Hex-encoded 32-byte Ed25519 verifying key (classical component).
    pub public_key:          String,
    /// Hex-encoded 2624-byte hybrid public key: `ed25519_pk ‖ ml_dsa_87_pk`.
    /// Empty on very old records that pre-date the quantum upgrade.
    pub hybrid_public_key:   String,
    pub display_name:        String,
    pub phrase:              String, // 12-word recovery phrase (kept in memory for auto-save)
}

// ---------------------------------------------------------------------------
// Contact
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Contact {
    pub id:           String,
    pub name:         String,
    pub last_seen_ts: u64,
    pub online:       bool,
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id:           String,
    pub contact_id:   String,
    pub outbound:     bool,
    pub content_type: String, // "text" | "file"
    pub text:         String,
    pub file_name:    String,
    pub file_size:    u64,
    pub file_xferd:   u64,
    pub file_mime:    String,
    pub timestamp_ts: u64,
    pub status:       String, // "pending" | "sent" | "delivered" | "read" | "failed"
}

impl StoredMessage {
    pub fn new_text(id: String, contact_id: String, outbound: bool, text: String) -> Self {
        Self {
            id,
            contact_id,
            outbound,
            content_type: "text".into(),
            text,
            file_name: String::new(),
            file_size: 0,
            file_xferd: 0,
            file_mime: String::new(),
            timestamp_ts: now_secs(),
            status: if outbound { "sent".into() } else { "delivered".into() },
        }
    }
}

// ---------------------------------------------------------------------------
// Transfer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Transfer {
    pub id:           String,
    pub contact_name: String,
    pub file_name:    String,
    pub size_bytes:   u64,
    pub xferd_bytes:  u64,
    pub outbound:     bool,
    pub lanes_active: u32,
    pub bps:          u64,
}

// ---------------------------------------------------------------------------
// Call
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CallRecord {
    pub conv_id:   String,
    pub video:     bool,
    pub local_sdp: String,
    pub state:     String, // "calling" | "active" | "rejected" | "ended"
}

// ---------------------------------------------------------------------------
// DaemonState
// ---------------------------------------------------------------------------

pub struct DaemonState {
    pub identity:  Option<Identity>,
    pub contacts:  Vec<Contact>,
    /// contact_id → messages
    pub messages:  HashMap<String, Vec<StoredMessage>>,
    pub transfers: Vec<Transfer>,
    pub settings:  HashMap<String, String>,
    pub calls:     HashMap<String, CallRecord>,
    pub next_id:   u64,

    // ── Persistence ──────────────────────────────────────────────────────────
    /// Path to the encrypted user data file.  `None` → persistence disabled
    /// (default for in-memory / test mode).
    pub store_path:   Option<PathBuf>,
    /// Argon2 parameters used for key derivation.
    pub store_params: StoreParams,
    /// 32-byte AES key derived from the recovery phrase.  Set on
    /// `create_identity` / `restore_identity`; zeroised on drop.
    store_key: Option<Zeroizing<Vec<u8>>>,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self {
            identity:     None,
            contacts:     Vec::new(),
            messages:     HashMap::new(),
            transfers:    Vec::new(),
            settings:     HashMap::new(),
            calls:        HashMap::new(),
            next_id:      0,
            store_path:   None,
            store_params: StoreParams::production(),
            store_key:    None,
        }
    }
}

impl DaemonState {
    /// Create a state that persists to `path` using `params`.
    pub fn with_store(path: PathBuf, params: StoreParams) -> Self {
        Self { store_path: Some(path), store_params: params, ..Default::default() }
    }

    pub fn next_id(&mut self) -> String {
        self.next_id += 1;
        format!("d-{}", self.next_id)
    }

    // ── Persistence helpers ───────────────────────────────────────────────────

    /// Serialize the current in-memory state into a `PersistedUserData` snapshot.
    fn snapshot(&self) -> PersistedUserData {
        let id = self.identity.as_ref();
        PersistedUserData {
            version:              1,
            display_name:         id.map(|i| i.display_name.clone()).unwrap_or_default(),
            public_key_hex:       id.map(|i| i.public_key.clone()).unwrap_or_default(),
            hybrid_public_key_hex: id.map(|i| i.hybrid_public_key.clone()).unwrap_or_default(),
            recovery_phrase:      id.map(|i| i.phrase.clone()).unwrap_or_default(),
            contacts: self.contacts.iter().map(|c| transferd_store::PersistedContact {
                id:           c.id.clone(),
                name:         c.name.clone(),
                last_seen_ts: c.last_seen_ts,
                online:       c.online,
            }).collect(),
            messages: self.messages.iter().map(|(cid, msgs)| {
                let pm = msgs.iter().map(|m| transferd_store::PersistedMessage {
                    id:           m.id.clone(),
                    contact_id:   m.contact_id.clone(),
                    outbound:     m.outbound,
                    content_type: m.content_type.clone(),
                    text:         m.text.clone(),
                    file_name:    m.file_name.clone(),
                    file_size:    m.file_size,
                    file_xferd:   m.file_xferd,
                    file_mime:    m.file_mime.clone(),
                    timestamp_ts: m.timestamp_ts,
                    status:       m.status.clone(),
                }).collect();
                (cid.clone(), pm)
            }).collect(),
            settings:      self.settings.clone(),
            next_id:       self.next_id,
            created_at:    0,
            last_modified: now_secs(),
        }
    }

    /// Populate in-memory state from a `PersistedUserData` snapshot (loaded
    /// from disk after successful decryption).
    fn apply(&mut self, data: PersistedUserData) {
        self.identity = Some(Identity {
            public_key:        data.public_key_hex,
            hybrid_public_key: data.hybrid_public_key_hex,
            display_name:      data.display_name,
            phrase:            data.recovery_phrase,
        });
        self.contacts = data.contacts.into_iter().map(|c| Contact {
            id:           c.id,
            name:         c.name,
            last_seen_ts: c.last_seen_ts,
            online:       c.online,
        }).collect();
        self.messages = data.messages.into_iter().map(|(cid, msgs)| {
            let sm = msgs.into_iter().map(|m| StoredMessage {
                id:           m.id,
                contact_id:   m.contact_id,
                outbound:     m.outbound,
                content_type: m.content_type,
                text:         m.text,
                file_name:    m.file_name,
                file_size:    m.file_size,
                file_xferd:   m.file_xferd,
                file_mime:    m.file_mime,
                timestamp_ts: m.timestamp_ts,
                status:       m.status,
            }).collect();
            (cid, sm)
        }).collect();
        self.settings = data.settings;
        self.next_id  = data.next_id;
    }

    /// Set the in-memory key used for subsequent saves.  Called after
    /// deriving the key on `create_identity` / `restore_identity`.
    pub fn set_phrase(&mut self, phrase: &str) {
        // Derive the key now and cache it so saves don't need to re-derive.
        // We store the phrase itself (in a Zeroizing wrapper) rather than the
        // derived key, because re-deriving per-save is actually fine for the
        // async path (saves happen on the tokio runtime, not the hot path).
        self.store_key = Some(Zeroizing::new(phrase.as_bytes().to_vec()));
        // Also record the phrase in the identity for snapshot().
        if let Some(id) = &mut self.identity {
            id.phrase = phrase.to_owned();
        }
    }

    /// Encrypt the current state and write it to `store_path`.
    /// No-op when `store_path` is `None` or no phrase has been set yet.
    pub fn try_save(&self) {
        let (path, phrase_bytes) = match (&self.store_path, &self.store_key) {
            (Some(p), Some(k)) => (p, k),
            _ => return,
        };
        let phrase = match std::str::from_utf8(phrase_bytes) {
            Ok(s) => s,
            Err(_) => return,
        };
        let data = self.snapshot();
        if let Err(e) = transferd_store::save(path, phrase, &data, &self.store_params) {
            eprintln!("transferd: store save failed: {e}");
        }
    }

    /// Attempt to load persisted data from disk using `phrase`.
    ///
    /// Returns `true` and populates in-memory state on success.
    /// Returns `false` (without modifying state) if no file exists or the
    /// phrase is wrong.
    pub fn try_load(&mut self, phrase: &str) -> bool {
        let path = match &self.store_path {
            Some(p) => p.clone(),
            None    => return false,
        };
        if !transferd_store::file_exists(&path) {
            return false;
        }
        match transferd_store::load(&path, phrase, &self.store_params) {
            Ok(data) => {
                self.apply(data);
                self.store_key = Some(Zeroizing::new(phrase.as_bytes().to_vec()));
                true
            }
            Err(e) => {
                eprintln!("transferd: store load failed: {e}");
                false
            }
        }
    }
}
