//! Wire message envelope — the application payload carried inside transport chunks.
//!
//! The transport layer (`TcpLane` / `RelayLane`) already authenticates and
//! encrypts every chunk (AES-256-GCM). The payload of a chunk is one of these
//! messages, bincode-encoded. Keeping an explicit application-level envelope
//! lets peers distinguish text, file metadata, delivery acks, and read receipts
//! on the same lane.

use serde::{Deserialize, Serialize};

/// Application-level messages exchanged over a transport lane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMsg {
    /// A text message. `sender` is the sender's public key hex (64 chars);
    /// `msg_id` is the sender's local message id (used for acks).
    /// `group_id` is set for group-thread messages (recipient stores under the
    /// group id and uses `sender` as the author).
    /// `reply_to` references another message id in the same thread.
    Text {
        sender:   String,
        msg_id:   String,
        text:     String,
        ts:       u64,
        group_id: Option<String>,
        reply_to: Option<String>,
    },
    /// File transfer chunk. `msg_id` is the sender's message/transfer id and is
    /// used for delivery acks; `seq`/`total_chunks` reassemble the file.
    File {
        sender:       String,
        msg_id:       String,
        file_name:    String,
        file_size:    u64,
        mime:         String,
        ts:           u64,
        /// 0-based sequence of this chunk within the file.
        seq:          u32,
        /// Total number of chunks in the transfer (last chunk carries `seq + 1 == total`).
        total_chunks: u32,
        data:         Vec<u8>,
    },
    /// Delivery acknowledgment for a previously sent message.
    Ack { msg_id: String },
    /// Read receipt for a previously sent message.
    Read { msg_id: String },
    /// Ephemeral typing indicator (not stored). `sender` is the sender's
    /// public key hex. Not persisted on the recipient.
    Typing { sender: String, is_typing: bool },
    /// Toggle an emoji reaction on a previously received message.
    /// `target_msg_id` is the id of the message in the same thread.
    Reaction { sender: String, target_msg_id: String, emoji: String },
}

impl WireMsg {
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}