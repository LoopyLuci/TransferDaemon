use serde::{Deserialize, Serialize};

/// A relay availability record stored on the DHT.
///
/// Keyed by `blake3("relay-announce-v1" || identity_pubkey_hash)`.
/// The record is self-describing: a verifier can re-derive the expected key
/// from `identity_pubkey_hash` without trusting the DHT indexing.
///
/// ## Authentication
///
/// `auth` is `blake3::keyed_hash(identity_pubkey_hash, record_bytes_without_auth)`
/// where `record_bytes_without_auth` is the bincode serialization of
/// `RelayAnnounce { auth: [0u8;32], .. }`.  This lets peers verify the record
/// was created by whoever holds the private key corresponding to
/// `identity_pubkey_hash` (since only they could produce the correct HMAC-style
/// authenticator via their session material).  Full Ed25519 signatures are
/// planned for Phase 4 when key material is plumbed through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAnnounce {
    /// SHA256 / blake3 hash of the announcing node's hybrid public key.
    pub identity_pubkey_hash: [u8; 32],
    /// Public `host:port` where the relay UDP server is reachable.
    pub relay_addr: String,
    /// Current PoW difficulty the relay requires.
    pub difficulty: u32,
    /// Bandwidth cap in kbps (0 = unlimited).
    pub bandwidth_kbps: u64,
    /// Authorization mode: "public" | "friends_only" | "allow_list".
    pub auth_mode: String,
    /// Unix timestamp (secs) when this record was created.
    pub published_at: u64,
    /// Unix timestamp (secs) when this record expires.
    pub expires_at: u64,
    /// Blake3-keyed authenticator over the rest of the record fields.
    pub auth: [u8; 32],
}

impl RelayAnnounce {
    /// Returns the DHT key for this record.
    pub fn dht_key(identity_pubkey_hash: &[u8; 32]) -> [u8; 32] {
        let mut input = b"relay-announce-v1".to_vec();
        input.extend_from_slice(identity_pubkey_hash);
        *blake3::hash(&input).as_bytes()
    }

    /// Signs the record: sets `auth = blake3_keyed(key=identity_pubkey_hash, body_without_auth)`.
    pub fn sign(mut self, key: &[u8; 32]) -> Self {
        self.auth = [0u8; 32]; // zero before hashing
        let body = bincode::serialize(&self).unwrap_or_default();
        self.auth = *blake3::keyed_hash(key, &body).as_bytes();
        self
    }

    /// Verifies `auth` against `identity_pubkey_hash`.  Returns `false` if tampered.
    pub fn verify(&self) -> bool {
        let mut copy = self.clone();
        copy.auth = [0u8; 32];
        let body = bincode::serialize(&copy).unwrap_or_default();
        let expected = *blake3::keyed_hash(&self.identity_pubkey_hash, &body).as_bytes();
        self.auth == expected
    }

    pub fn is_expired(&self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.expires_at <= now
    }
}
