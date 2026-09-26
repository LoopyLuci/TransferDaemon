//! Peer endpoint discovery via the DHT.
//!
//! A daemon that runs a relay publishes a signed `PeerEndpoint` record under
//! `blake3("transferd-peer-endpoint-v1" || blake3(pk_hex))`. Contacts without an
//! explicit address are resolved by looking up their record and verifying the
//! Ed25519 signature against their public key, yielding a `relay://` address.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Start a DHT node from `TRANSFERD_DHT_BIND` (default ephemeral) and bootstrap
/// from `TRANSFERD_DHT_BOOTSTRAP` (comma-separated `host:port`). Returns `None`
/// when the DHT isn't configured.
pub async fn spawn_dht_node(public_key_hex: Option<String>) -> Option<Arc<transferd_relay::DhtNode>> {
    let bind = std::env::var("TRANSFERD_DHT_BIND").unwrap_or_else(|_| "0.0.0.0:0".to_owned());
    // Deterministic node id derived from the identity public key, so the same
    // identity keeps the same DHT presence across restarts.
    let node_id = match public_key_hex {
        Some(pk) if pk.len() == 64 => {
            let hash = blake3::hash(pk.as_bytes());
            transferd_relay::derive_node_id(hash.as_bytes())
        }
        _ => {
            let mut id = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
            id
        }
    };

    // When binding 0.0.0.0 / an ephemeral port, advertise an externally
    // reachable address (e.g. `TRANSFERD_DHT_ADVERTISE=public-ip:7901`) so
    // remote peers can route to this node.
    let advertised = std::env::var("TRANSFERD_DHT_ADVERTISE")
        .ok()
        .and_then(|s| s.parse().ok());

    let node = match transferd_relay::DhtNode::start_with_advertised(&bind, node_id, advertised).await {
        Ok(n) => Arc::new(n),
        Err(e) => {
            tracing::warn!("[dht] failed to start node: {e}");
            return None;
        }
    };

    if let Ok(bootstrap) = std::env::var("TRANSFERD_DHT_BOOTSTRAP") {
        let peers: Vec<std::net::SocketAddr> = bootstrap
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        node.bootstrap(peers).await;
    }
    Some(node)
}

/// Ensure a DHT node is running (when configured) and publish our endpoint.
pub async fn ensure_dht(state: Arc<parking_lot::Mutex<crate::state::DaemonState>>) {
    let configured = std::env::var("TRANSFERD_DHT_BIND").is_ok()
        || std::env::var("TRANSFERD_DHT_BOOTSTRAP").is_ok();
    if !configured {
        return;
    }
    if state.lock().dht.is_none() {
        let pk = state.lock().identity.as_ref().map(|i| i.public_key.clone());
        if let Some(node) = spawn_dht_node(pk).await {
            state.lock().dht = Some(node);
        }
    }
    publish_endpoint_if_ready(&state).await;
}

/// Derive the Ed25519 signing key from the BIP-39 recovery phrase.
pub fn signing_key_from_phrase(phrase: &str) -> Option<SigningKey> {
    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase).ok()?;
    let seed = mnemonic.to_seed("");
    let seed_arr: [u8; 64] = seed[..64].try_into().ok()?;
    let key_bytes: [u8; 32] = seed_arr[..32].try_into().ok()?;
    Some(SigningKey::from_bytes(&key_bytes))
}

/// Publish the daemon's relay endpoint (called when identity + relay + DHT are ready).
pub async fn publish_endpoint_if_ready(
    state: &std::sync::Arc<parking_lot::Mutex<crate::state::DaemonState>>,
) {
    let (pk, phrase, relay_addr, token) = {
        let s = state.lock();
        let Some(id) = &s.identity else { return };
        let Some(hub) = &s.relay_hub else { return };
        let Some(_dht) = &s.dht else { return };
        (id.public_key.clone(), id.phrase.clone(), hub.relay_addr(), hub.self_token())
    };
    let Some(key) = signing_key_from_phrase(&phrase) else {
        tracing::warn!("[dht] could not derive signing key from phrase");
        return;
    };
    let ep = PeerEndpoint {
        public_key: pk.clone(),
        relay_addr: relay_addr.to_string(),
        token: hex::encode(token),
        published_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        signature: Vec::new(),
    }
    .signed(&key);
    let dht = state.lock().dht.clone();
    if let Some(dht) = dht {
        ep.publish(&dht).await;
        tracing::info!("[dht] published relay endpoint for {pk}");
    }
}

/// Resolve a contact's relay endpoint from the DHT. Returns a `relay://` address.
pub async fn resolve_peer(
    dht: &Arc<transferd_relay::DhtNode>,
    public_key_hex: &str,
) -> Option<String> {
    PeerEndpoint::resolve(dht.as_ref(), public_key_hex).await
}

/// The on-DHT record announcing where a peer can be reached over a relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEndpoint {
    /// 64-hex Ed25519 public key of the peer.
    pub public_key: String,
    /// `host:port` of a relay that will forward to this peer.
    pub relay_addr: String,
    /// Hex-encoded 32-byte relay token the peer registered.
    pub token: String,
    /// Unix timestamp (secs) when the record was created.
    pub published_at: u64,
    /// Ed25519 signature over the record with this field zeroed.
    pub signature: Vec<u8>,
}

impl PeerEndpoint {
    /// The DHT key under which this peer's endpoint is stored.
    pub fn dht_key(public_key_hex: &str) -> [u8; 32] {
        let pk_hash = blake3::hash(public_key_hex.as_bytes());
        let input = [b"transferd-peer-endpoint-v1".as_slice(), pk_hash.as_bytes()].concat();
        *blake3::hash(&input).as_bytes()
    }

    fn canonical_bytes(&self) -> Option<Vec<u8>> {
        let mut copy = self.clone();
        copy.signature = vec![0u8; 64];
        bincode::serialize(&copy).ok()
    }

    /// Sign the record with the peer's Ed25519 signing key.
    pub fn signed(self, key: &SigningKey) -> Self {
        let bytes = self.canonical_bytes().unwrap_or_default();
        let sig = key.sign(&bytes).to_bytes().to_vec();
        Self { signature: sig, ..self }
    }

    /// Verify the Ed25519 signature against `public_key`.
    pub fn verify(&self) -> bool {
        let pk_bytes: [u8; 32] = match hex::decode(&self.public_key) {
            Ok(b) => match b.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            },
            Err(_) => return false,
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else { return false };
        let Some(bytes) = self.canonical_bytes() else { return false };
        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(&bytes, &sig).is_ok()
    }

    /// Publish this endpoint to the DHT (TTL 10 minutes).
    pub async fn publish(&self, dht: &transferd_relay::DhtNode) {
        let key = Self::dht_key(&self.public_key);
        let value = bincode::serialize(self).unwrap_or_default();
        dht.dht_store(key, value, 600).await;
    }

    /// Look up a peer's relay endpoint by their public key.
    ///
    /// Returns a `relay://host:port/<token>` address when a valid, unexpired,
    /// correctly-signed record is found.
    pub async fn resolve(dht: &transferd_relay::DhtNode, public_key_hex: &str) -> Option<String> {
        let key = Self::dht_key(public_key_hex);
        let value = dht.dht_get(key).await?;
        let ep: PeerEndpoint = bincode::deserialize(&value).ok()?;
        if ep.public_key != public_key_hex {
            return None;
        }
        if !ep.verify() {
            return None;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(ep.published_at) > 600 {
            return None; // stale
        }
        Some(format!("relay://{}/{}", ep.relay_addr, ep.token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    fn test_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn test_signed_record_roundtrip() {
        let key = test_key();
        let pk_hex = hex::encode(key.verifying_key().to_bytes());

        let ep = PeerEndpoint {
            public_key: pk_hex.clone(),
            relay_addr: "relay.example:7777".into(),
            token: hex::encode([7u8; 32]),
            published_at: 1_000_000,
            signature: Vec::new(),
        };
        let signed = ep.signed(&key);
        assert!(signed.verify(), "valid signature must verify");
        assert_eq!(signed.public_key, pk_hex);
    }

    #[test]
    fn test_tampered_record_rejected() {
        let key = test_key();
        let pk_hex = hex::encode(key.verifying_key().to_bytes());
        let ep = PeerEndpoint {
            public_key: pk_hex,
            relay_addr: "relay.example:7777".into(),
            token: hex::encode([7u8; 32]),
            published_at: 1_000_000,
            signature: Vec::new(),
        };
        let mut signed = ep.signed(&key);
        signed.relay_addr = "evil.example:9".into();
        assert!(!signed.verify(), "tampered record must fail verification");
    }

    #[test]
    fn test_wrong_key_rejected() {
        let alice = test_key();
        let bob = test_key();
        let ep = PeerEndpoint {
            public_key: hex::encode(alice.verifying_key().to_bytes()),
            relay_addr: "relay.example:7777".into(),
            token: hex::encode([7u8; 32]),
            published_at: 1_000_000,
            signature: Vec::new(),
        };
        // Bob signs a record claiming to be Alice.
        let forged = ep.signed(&bob);
        assert!(!forged.verify(), "signature from the wrong key must fail");
    }
}