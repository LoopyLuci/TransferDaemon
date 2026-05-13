//! DaemonState — shared in-memory state for all gRPC service implementations.
//!
//! In production this would be backed by SQLite + the ATE session manager.
//! For Phase 9.5 we use in-memory collections so the daemon can be fully tested
//! without filesystem or cryptographic dependencies.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Identity {
    pub public_key:   String, // hex-encoded 32-byte Ed25519 key
    pub display_name: String,
    pub phrase:       String, // 12-word recovery phrase (shown once)
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
    pub id:              String,
    pub contact_name:    String,
    pub file_name:       String,
    pub size_bytes:      u64,
    pub xferd_bytes:     u64,
    pub outbound:        bool,
    pub lanes_active:    u32,
    pub bps:             u64,
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
// Settings
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// DaemonState
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct DaemonState {
    pub identity:   Option<Identity>,
    pub contacts:   Vec<Contact>,
    /// contact_id → messages
    pub messages:   HashMap<String, Vec<StoredMessage>>,
    pub transfers:  Vec<Transfer>,
    pub settings:   HashMap<String, String>,
    pub calls:      HashMap<String, CallRecord>,
    pub next_id:    u64,
}

impl DaemonState {
    pub fn next_id(&mut self) -> String {
        self.next_id += 1;
        format!("d-{}", self.next_id)
    }
}
