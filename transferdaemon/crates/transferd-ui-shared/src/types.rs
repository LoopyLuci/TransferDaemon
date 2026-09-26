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
    /// 12-word recovery phrase (for persistence).
    #[serde(default)]
    pub phrase: String,
}

// ---------------------------------------------------------------------------
// Contact
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contact {
    /// Unique identifier — hex-encoded public key of the remote peer.
    pub id: String,
    /// The name the remote peer advertises (or the alias the user typed when adding them).
    pub name: String,
    /// Local nickname override — shown instead of `name` when set.
    #[serde(default)]
    pub nickname: Option<String>,
    pub last_seen_ts: Option<u64>, // Unix seconds
    pub online: bool,
    /// Whether this contact is blocked.
    #[serde(default)]
    pub blocked: bool,
    /// Whether the contact is currently typing (live indicator).
    #[serde(default)]
    pub typing: bool,
}

impl Contact {
    /// The name to display in the UI — nickname if set, otherwise the contact's name.
    pub fn display_name(&self) -> &str {
        self.nickname.as_deref().unwrap_or(&self.name)
    }
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/// A group thread.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Group {
    pub id:         String,
    pub name:       String,
    pub owner:      String,
    pub members:    Vec<GroupMember>,
    pub created_at: u64,
}

/// A member of a group with their role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupMember {
    pub public_key: String,
    pub role:       u8,
}

impl GroupMember {
    pub fn role_name(&self) -> &'static str {
        match self.role {
            1 => "Owner",
            2 => "Admin",
            _ => "Member",
        }
    }
}

// ---------------------------------------------------------------------------
// Connections (transport control center)
// ---------------------------------------------------------------------------

/// A network interface or virtual transport exposed by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Connection {
    pub id: String,
    pub name: String,
    /// "wifi" | "ethernet" | "usb" | "bluetooth" | "vpn" | "proxy" | "relay" | "direct"
    pub kind: String,
    pub enabled: bool,
    pub online: bool,
    pub link_speed_bps: u64,
    pub rtt_ms: f64,
    pub bandwidth_bps: u64,
    pub policy: String,
}

impl Connection {
    /// A human-friendly label for the kind.
    pub fn kind_label(&self) -> &'static str {
        match self.kind.as_str() {
            "wifi" => "Wi-Fi",
            "ethernet" => "Ethernet",
            "usb" => "USB",
            "bluetooth" => "Bluetooth",
            "vpn" => "VPN",
            "proxy" => "Proxy",
            "relay" => "Relay",
            "direct" => "Direct TCP",
            "loopback" => "Loopback",
            _ => "Network",
        }
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub contact_id: String,
    pub outbound: bool,
    pub content: MessageContent,
    pub timestamp_ts: u64,
    pub status: MessageStatus,
    /// Set for group-thread messages; `sender_pk` identifies the author.
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub sender_pk: Option<String>,
    /// Id of the message this one quotes (reply), resolved in the same thread.
    #[serde(default)]
    pub reply_to: Option<String>,
    /// Aggregated emoji reactions: `(emoji, reactor_public_key)`.
    #[serde(default)]
    pub reactions: Vec<(String, String)>,
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

impl MessageContent {
    pub fn preview(&self) -> String {
        match self {
            MessageContent::Text(t) => {
                if t.len() > 80 {
                    format!("{}…", &t[..77])
                } else {
                    t.clone()
                }
            }
            MessageContent::File { name, .. } => format!("📁 {name}"),
        }
    }
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
// Conversation summary (chat list row)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Conversation {
    /// Same as the contact's public-key id.
    pub contact_id: String,
    pub display_name: String,
    pub online: bool,
    /// Most-recent message text (empty = no messages yet).
    pub last_message: String,
    /// Unix timestamp of the most-recent message, or 0.
    pub last_time_sec: u64,
    /// Number of unread inbound messages.
    pub unread: u32,
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
    pub bps: u64,
    pub paused: bool,
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

// ---------------------------------------------------------------------------
// Updates (manual, opt-in)
// ---------------------------------------------------------------------------

/// Result of a manual update check.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub current_version: String,
    pub has_update: bool,
    pub new_version: String,
    pub release_notes: String,
    pub error: String,
}
