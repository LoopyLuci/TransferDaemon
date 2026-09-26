use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub public_key: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contact {
    pub id: String,
    pub name: String,
    pub last_seen_ts: Option<u64>,
    pub online: bool,
    #[serde(default)]
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupMember {
    pub public_key: String,
    pub role: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub members: Vec<GroupMember>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub contact_id: String,
    pub outbound: bool,
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
}

impl TransferStatus {
    pub fn progress(&self) -> f64 {
        if self.size_bytes == 0 { return 0.0; }
        (self.transferred_bytes as f64 / self.size_bytes as f64).clamp(0.0, 1.0)
    }

    pub fn eta_secs(&self) -> Option<u64> {
        if self.bps == 0 { return None; }
        let remaining = self.size_bytes.saturating_sub(self.transferred_bytes);
        Some(remaining / self.bps)
    }
}

pub fn fmt_bytes(b: u64) -> String {
    if b >= 1_073_741_824 { format!("{:.1} GB", b as f64 / 1_073_741_824.0) }
    else if b >= 1_048_576 { format!("{:.1} MB", b as f64 / 1_048_576.0) }
    else if b >= 1_024    { format!("{:.1} KB", b as f64 / 1_024.0) }
    else                   { format!("{} B", b) }
}
