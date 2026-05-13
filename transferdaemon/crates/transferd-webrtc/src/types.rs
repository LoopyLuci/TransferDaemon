//! Core call types shared across signaling, session management, and the UI.

use serde::{Deserialize, Serialize};

/// Current lifecycle state of a call.
#[derive(Debug, Clone, PartialEq)]
pub enum CallState {
    Idle,
    /// We placed the call; awaiting remote acceptance.
    Outgoing { call_id: String, conv_id: String },
    /// Remote peer is calling us; awaiting our response.
    Incoming { call_id: String, conv_id: String, video: bool, remote_sdp: String },
    /// Media flowing — call is live.
    Active { call_id: String, conv_id: String },
    Ended,
}

impl Default for CallState {
    fn default() -> Self { Self::Idle }
}

impl CallState {
    pub fn call_id(&self) -> Option<&str> {
        match self {
            Self::Outgoing { call_id, .. }
            | Self::Incoming { call_id, .. }
            | Self::Active   { call_id, .. } => Some(call_id),
            _ => None,
        }
    }

    pub fn is_active(&self) -> bool { matches!(self, Self::Active { .. }) }
    pub fn is_idle(&self)   -> bool { matches!(self, Self::Idle) }
    pub fn is_ended(&self)  -> bool { matches!(self, Self::Ended) }
}

/// Raw audio samples (48 kHz, mono, f32 PCM).
pub type AudioSamples = Vec<f32>;

/// Decoded video frame in RGBA8 format.
#[derive(Clone)]
pub struct VideoFrame {
    pub width:  u32,
    pub height: u32,
    pub rgba:   Vec<u8>,
}

/// A serializable ICE candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidateInit {
    pub candidate:        String,
    pub sdp_mid:          Option<String>,
    pub sdp_mline_index:  Option<u16>,
}

impl IceCandidateInit {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }
}
