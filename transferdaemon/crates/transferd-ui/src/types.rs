//! Shared domain types used across the UI, daemon client, and local database.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Hex-encoded Ed25519 public key (32 bytes → 64 hex chars).
    pub public_key: String,
    /// Human-readable display name chosen by the user.
    pub display_name: String,
}

// ---------------------------------------------------------------------------
// Contact
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contact {
    /// Unique identifier — hex-encoded public key of the remote peer.
    pub id: String,
    pub name: String,
    pub last_seen_ts: Option<u64>, // Unix seconds
    pub online: bool,
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,       // UUIDv4 or GSN-derived
    pub contact_id: String,
    pub outbound: bool,   // true = we sent it
    pub content: MessageContent,
    pub timestamp_ts: u64,
    pub status: MessageStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text(String),
    File {
        name: String,
        size_bytes: u64,
        transferred_bytes: u64,
        mime: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    Pending,
    Sent,
    Delivered,
    Read,
    Failed,
}

impl MessageStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending   => "…",
            Self::Sent      => "✓",
            Self::Delivered => "✓✓",
            Self::Read      => "✓✓",
            Self::Failed    => "✗",
        }
    }
}

// ---------------------------------------------------------------------------
// Active transfers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TransferStatus {
    pub id: String,
    pub contact_name: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub transferred_bytes: u64,
    pub outbound: bool,
    pub lanes_active: u8,
    pub bps: u64, // current throughput
}

impl TransferStatus {
    pub fn progress(&self) -> f32 {
        if self.size_bytes == 0 { return 0.0; }
        (self.transferred_bytes as f32 / self.size_bytes as f32).clamp(0.0, 1.0)
    }

    pub fn eta_secs(&self) -> Option<u64> {
        if self.bps == 0 { return None; }
        let remaining = self.size_bytes.saturating_sub(self.transferred_bytes);
        Some(remaining / self.bps)
    }
}
