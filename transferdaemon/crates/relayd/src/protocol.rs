//! Wire protocol for the blind relay.
//!
//! All messages are prefixed with a 1-byte tag so the relay can dispatch without
//! deserialising the full payload first. Serialisation is `bincode` (little-endian,
//! fixed-size integers where possible).
//!
//! Zero-knowledge property:
//!   The `session_token` is `blake3::derive_key("relay-token", key_bytes || relay_id)`.
//!   Without the 32-byte `SessionKey`, the relay cannot link a token to any identity.

use serde::{Deserialize, Serialize};

/// Message-type discriminant prepended to every datagram.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Register  = 0x01,
    Forward   = 0x02,
    Keepalive = 0x03,
    Challenge = 0x04,
    Error     = 0x05,
    Ack       = 0x06,
}

impl Tag {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Register),
            0x02 => Some(Self::Forward),
            0x03 => Some(Self::Keepalive),
            0x04 => Some(Self::Challenge),
            0x05 => Some(Self::Error),
            0x06 => Some(Self::Ack),
            _    => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Client → Relay
// ---------------------------------------------------------------------------

/// Recipient registers its session token so the relay knows where to send messages.
///
/// PoW: blake3(challenge ‖ session_token ‖ pow_nonce) must have `difficulty` leading zero bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMsg {
    /// Opaque 32-byte token derived from the `SessionKey`.
    pub session_token: [u8; 32],
    /// PoW nonce satisfying the current relay challenge.
    pub pow_nonce: u64,
    /// Monotonically increasing sequence number; used for replay detection.
    pub seq: u32,
}

/// Sender forwards an encrypted payload to a registered recipient.
///
/// The relay does not inspect `ciphertext`; it blindly copies it to the recipient's address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardMsg {
    pub session_token: [u8; 32],
    pub pow_nonce: u64,
    /// Per-message sequence number for the sender (replaces TCP ordering).
    pub sender_seq: u16,
    /// AES-GCM encrypted payload (tunnel proposal or data fragment).
    pub ciphertext: Vec<u8>,
}

/// Refreshes the TTL for a registered session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeepaliveMsg {
    pub session_token: [u8; 32],
    pub pow_nonce: u64,
}

// ---------------------------------------------------------------------------
// Relay → Client
// ---------------------------------------------------------------------------

/// PoW challenge broadcast periodically (rotated every `challenge_interval_secs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeMsg {
    /// 16 random bytes. Clients must include this in their PoW computation.
    pub challenge: [u8; 16],
    /// Unix timestamp (secs) when this challenge expires.
    pub expires_at: u64,
    /// Current difficulty (leading zero bits required).
    pub difficulty: u32,
}

/// Forwarded payload delivered to the recipient.
///
/// The relay strips `session_token` and `pow_nonce` and wraps the payload in this envelope,
/// preserving blindness (the recipient learns the ciphertext but not the sender's IP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveredMsg {
    pub sender_seq: u16,
    pub ciphertext: Vec<u8>,
}

/// Error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMsg {
    pub code: ErrorCode,
    pub seq: u32,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum ErrorCode {
    InvalidPoW        = 1,
    TokenNotFound     = 2,
    TokenAlreadyExists = 3,
    PayloadTooLarge   = 4,
    RateLimited       = 5,
    InternalError     = 0xFFFF,
}

/// Acknowledgment sent back to the sender after a successful FORWARD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckMsg {
    pub sender_seq: u16,
}

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

/// Maximum UDP datagram payload the relay accepts (64 KiB minus overhead).
pub const MAX_PAYLOAD: usize = 63 * 1024;

/// Serialises a tagged message into a byte vector ready for `send_to`.
pub fn encode<T: Serialize>(tag: Tag, msg: &T) -> Result<Vec<u8>, bincode::Error> {
    let mut body = bincode::serialize(msg)?;
    let mut frame = Vec::with_capacity(1 + body.len());
    frame.push(tag as u8);
    frame.append(&mut body);
    Ok(frame)
}

/// Splits the tag byte from the body and returns `(Tag, body_slice)`.
pub fn split(buf: &[u8]) -> Option<(Tag, &[u8])> {
    let (&tag_byte, rest) = buf.split_first()?;
    Some((Tag::from_byte(tag_byte)?, rest))
}

// ---------------------------------------------------------------------------
// Session token derivation (also used by clients)
// ---------------------------------------------------------------------------

/// Derives the 32-byte session token from a `SessionKey` and a relay ID.
///
/// The relay cannot reverse this without the `SessionKey`.
pub fn derive_token(session_key: &[u8; 32], relay_id: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + relay_id.len());
    input.extend_from_slice(session_key);
    input.extend_from_slice(relay_id);
    blake3::derive_key("TransferDaemon-v1-relay-token", &input)
}
