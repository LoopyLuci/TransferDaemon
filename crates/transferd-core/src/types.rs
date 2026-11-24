use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Gsn(pub u64);

impl Gsn {
    pub const ZERO: Self = Gsn(0);

    pub fn next(&self) -> Self { Gsn(self.0 + 1) }
    pub fn distance(&self, other: Gsn) -> u64 { self.0.saturating_sub(other.0) }
    pub fn offset(&self, count: u64) -> Self { Gsn(self.0 + count) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    /// Create a random session ID (for testing).
    #[cfg(test)]
    pub fn random() -> Self {
        use rand::Rng;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill(&mut bytes);
        SessionId(bytes)
    }
}
