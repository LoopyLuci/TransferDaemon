use crate::receiver::{Nack, WindowUpdate};
use crate::types::SessionId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    Ack { session_id: SessionId, cumulative_gsn: u64 },
    Nack { session_id: SessionId, missing_gsn: u64, highest_received: u64 },
    WindowUpdate { session_id: SessionId, cumulative_gsn: u64, right_edge: u64 },
    Heartbeat,
    Close,
    Error { code: u16, reason: String },
}

impl ControlMessage {
    pub fn from_nack(nack: Nack) -> Self {
        Self::Nack {
            session_id: nack.session_id,
            missing_gsn: nack.missing_gsn.0,
            highest_received: nack.highest_received.0,
        }
    }

    pub fn from_window_update(u: WindowUpdate) -> Self {
        Self::WindowUpdate {
            session_id: u.session_id,
            cumulative_gsn: u.cumulative_gsn.0,
            right_edge: u.window_right_edge.0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}
