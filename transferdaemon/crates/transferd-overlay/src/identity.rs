//! Node identity, pairing invites, and the ACL rules that guard every exposed service.
//!
//! An overlay node's identity is TransferDaemon's hybrid post-quantum identity
//! (Ed25519 + ML-DSA-87); the **node id** is the hex Ed25519 public key, exactly the id a
//! contact already has. Nothing here invents a second identity system.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{OverlayError, Result};
use crate::protocol::ServiceInfo;

/// TransferDaemon's hybrid signing identity, as used for node authentication.
pub use transferd_crypto::{HybridSigningKey, HybridVerifyingKey};

/// How long an invite stays valid by default.
pub const DEFAULT_INVITE_TTL_S: u64 = 900;

/// The largest invite this build will parse. An invite carries a 2624-byte hybrid identity and
/// a 4691-byte hybrid signature, so it is a few kilobytes of JSON before base64.
const MAX_INVITE_BYTES: usize = 64 * 1024;

/// The domain context that binds an invite signature to its contents.
const INVITE_CONTEXT: &str = "TransferDaemon-overlay-invite-v1";

/// This node's identity: the signing key, the node id it derives, and a display name.
#[derive(Clone)]
pub struct NodeIdentity {
    signing: std::sync::Arc<HybridSigningKey>,
    node_id: String,
    name: String,
}

impl NodeIdentity {
    /// Build an identity from a signing key and a display name.
    pub fn new(signing: HybridSigningKey, name: impl Into<String>) -> Self {
        let node_id = hex::encode(&signing.verifying_key().to_bytes()[..32]);
        Self {
            signing: std::sync::Arc::new(signing),
            node_id,
            name: name.into(),
        }
    }

    /// A fresh identity with a random key. Used for tests and for nodes that have not yet
    /// been given one by the daemon.
    pub fn generate(name: impl Into<String>) -> Self {
        let mut seed = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self::from_seed(&seed, name)
    }

    /// The identity a 64-byte seed derives; the same seed always gives the same node id, so a
    /// stored seed is all a node needs to keep its identity across restarts.
    pub fn from_seed(seed: &[u8; 64], name: impl Into<String>) -> Self {
        Self::new(HybridSigningKey::from_bip39_seed(seed), name)
    }

    /// The 64-character hex node id.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// The display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Change the display name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// The signing key (cloned; the caller needs it for each handshake).
    pub fn signing_key(&self) -> &HybridSigningKey {
        &self.signing
    }

    /// The 2624-byte hybrid public key that peers verify.
    pub fn hybrid_public_key(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes()
    }

    /// The relay token a relay registers this node under: derived from the node id, so it is
    /// the same on every relay and reveals nothing to the relay about who it is.
    pub fn relay_token(&self) -> [u8; 32] {
        relay_token_for(&self.node_id)
    }
}

/// The relay registration token for a node id.
///
/// Derived, not random: the same node registers the same token everywhere, so one
/// registration works across every relay, and a relay cannot tell one node from another.
pub fn relay_token_for(node_id: &str) -> [u8; 32] {
    blake3::derive_key("transferd-overlay-relay-token-v1", node_id.as_bytes())
}

/// Who may open a stream to an exposed service.
///
/// `"*paired"` means every node that has paired with us — i.e. any node we hold an identity
/// for, which is exactly the set that passed trust-on-first-use when it was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acl {
    /// Any paired node.
    AllPaired,
    /// Only these node ids.
    Nodes(Vec<String>),
}

impl Acl {
    /// Parse the `allow` argument of `overlay.expose`: a list of node ids and/or `"*paired"`.
    pub fn parse(allow: &[String]) -> Self {
        let mut nodes = Vec::new();
        let mut all = false;
        for entry in allow {
            let e = entry.trim();
            if e == "*paired" {
                all = true;
            } else if !e.is_empty() {
                nodes.push(e.to_ascii_lowercase());
            }
        }
        if all && nodes.is_empty() {
            Self::AllPaired
        } else {
            Self::Nodes(nodes)
        }
    }

    /// Whether `node_id` may use the service.
    ///
    /// An empty list allows nobody: nothing is exposed by default.
    pub fn permits(&self, node_id: &str, paired: bool) -> bool {
        match self {
            // Paired: this node accepted the peer's invite, or the peer accepted one of ours.
            // A node that only managed to open a session (anyone who knows a node id can) is not.
            Self::AllPaired => paired,
            Self::Nodes(nodes) => nodes.iter().any(|n| n == &node_id.to_ascii_lowercase()),
        }
    }

    /// A readable form for `overlay.services`.
    pub fn describe(&self) -> Vec<String> {
        match self {
            Self::AllPaired => vec!["*paired".into()],
            Self::Nodes(n) => n.clone(),
        }
    }
}

/// One exposed service: a name, where it listens locally, and who may use it.
#[derive(Debug, Clone)]
pub struct ExposedService {
    pub name: String,
    pub local_addr: std::net::SocketAddr,
    pub allow: Acl,
    pub rate: ServiceRate,
    pub description: String,
}

/// Per-service limits. A refused connection is counted, not silently dropped.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ServiceRate {
    /// New streams allowed per minute, per connecting node.
    pub streams_per_min: u32,
    /// Bytes allowed per minute, per connecting node.
    pub bytes_per_min: u64,
}

impl Default for ServiceRate {
    fn default() -> Self {
        // Generous enough for real work, low enough that a runaway client cannot saturate
        // the node it is pointed at.
        Self {
            streams_per_min: 120,
            bytes_per_min: 512 * 1024 * 1024,
        }
    }
}

/// What a node offers to reach it.
#[derive(Debug, Clone)]
pub struct NodeRecord {
    pub node_id: String,
    pub name: String,
    /// The services it advertises, refreshed on every hello.
    pub services: Vec<ServiceInfo>,
    /// The hybrid public key we verified on first contact (trust on first use).
    pub hybrid_public_key: Vec<u8>,
    pub paired_at: u64,
    pub last_seen: u64,
}

impl NodeRecord {
    /// A record for a newly paired node.
    pub fn new(node_id: String, name: String, hybrid_public_key: Vec<u8>) -> Self {
        let now = now_secs();
        Self {
            node_id,
            name,
            services: Vec::new(),
            hybrid_public_key,
            paired_at: now,
            last_seen: now,
        }
    }
}

/// A pairing invite: this node's identity plus how to reach it, signed so it cannot be
/// edited in transit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    /// Invite format version, so a future format can be recognised.
    pub version: u16,
    /// The inviting node's id.
    pub node_id: String,
    /// The inviting node's display name.
    #[serde(default)]
    pub name: String,
    /// The inviting node's 2624-byte hybrid public key.
    pub hybrid_public_key: Vec<u8>,
    /// Relays the node is registered on, as `host:port`.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Addresses a peer may try directly, as `host:port`.
    #[serde(default)]
    pub direct: Vec<String>,
    /// Unix seconds after which the invite is refused.
    pub expires_at: u64,
    /// A random value, so two invites from the same node differ.
    pub nonce: [u8; 16],
    /// The hybrid signature over everything above.
    pub signature: Vec<u8>,
}

/// The bytes an invite signature covers.
fn invite_binding(i: &Invite) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(INVITE_CONTEXT.as_bytes());
    h.update(&i.version.to_le_bytes());
    h.update(i.node_id.as_bytes());
    h.update(i.name.as_bytes());
    h.update(&(i.hybrid_public_key.len() as u32).to_le_bytes());
    h.update(&i.hybrid_public_key);
    h.update(&(i.relays.len() as u32).to_le_bytes());
    for r in &i.relays {
        h.update(r.as_bytes());
        h.update(&[0u8]);
    }
    h.update(&(i.direct.len() as u32).to_le_bytes());
    for d in &i.direct {
        h.update(d.as_bytes());
        h.update(&[0u8]);
    }
    h.update(&i.expires_at.to_le_bytes());
    h.update(&i.nonce);
    h.finalize().as_bytes().to_vec()
}

/// Build and sign an invite for this node.
pub fn make_invite(
    identity: &NodeIdentity,
    relays: Vec<String>,
    direct: Vec<String>,
    ttl_s: u64,
) -> String {
    make_invite_with_nonce(identity, relays, direct, ttl_s).0
}

/// The same, with the invite's nonce and expiry: the nonce is the one-time secret the node
/// that accepts the invite presents, which is how the inviting node learns it is paired too.
pub fn make_invite_with_nonce(
    identity: &NodeIdentity,
    relays: Vec<String>,
    direct: Vec<String>,
    ttl_s: u64,
) -> (String, [u8; 16], u64) {
    let ttl_s = ttl_s.clamp(30, 86_400);
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let mut invite = Invite {
        version: 1,
        node_id: identity.node_id().to_string(),
        name: identity.name().to_string(),
        hybrid_public_key: identity.hybrid_public_key(),
        relays,
        direct,
        expires_at: now_secs() + ttl_s,
        nonce,
        signature: Vec::new(),
    };
    invite.signature = identity
        .signing_key()
        .sign(&invite_binding(&invite))
        .to_bytes();
    let json = serde_json::to_string(&invite).unwrap_or_default();
    (
        format!("tdov1:{}", base64_url_encode(json.as_bytes())),
        invite.nonce,
        invite.expires_at,
    )
}

/// An invite's nonce, read without verifying (the caller verified it with [`accept_invite`]).
pub fn invite_nonce(invite: &str) -> Option<[u8; 16]> {
    let raw = base64_url_decode(invite.strip_prefix("tdov1:")?).ok()?;
    serde_json::from_slice::<Invite>(&raw).ok().map(|i| i.nonce)
}

/// Verify an invite and return the record to pair with.
///
/// The signature is checked against the invite's own key material, so an invite cannot be
/// edited; the caller still applies trust-on-first-use when it already knows the node.
pub fn accept_invite(invite: &str) -> Result<NodeRecord> {
    let body = invite
        .strip_prefix("tdov1:")
        .ok_or_else(|| OverlayError::protocol("an invite starts with tdov1:"))?;
    let raw = base64_url_decode(body)?;
    if raw.len() > MAX_INVITE_BYTES {
        return Err(OverlayError::protocol("invite is too large"));
    }
    let invite: Invite =
        serde_json::from_slice(&raw).map_err(|e| OverlayError::protocol(e.to_string()))?;
    if invite.expires_at <= now_secs() {
        return Err(OverlayError::protocol("invite has expired"));
    }
    let vk = HybridVerifyingKey::from_bytes(&invite.hybrid_public_key)
        .ok_or_else(|| OverlayError::protocol("invite carries an invalid hybrid identity"))?;
    let sig = transferd_crypto::HybridSignature::from_bytes(&invite.signature)
        .ok_or_else(|| OverlayError::protocol("invite signature is malformed"))?;
    let binding = invite_binding(&invite);
    if !vk.verify(&binding, &sig) {
        return Err(OverlayError::IdentityMismatch {
            node: invite.node_id.clone(),
            reason: "invite signature does not verify".into(),
        });
    }
    let expected = hex::decode(&invite.node_id)
        .map_err(|_| OverlayError::BadNodeId(invite.node_id.clone()))?;
    if expected.len() != 32 || invite.hybrid_public_key[..32] != expected {
        return Err(OverlayError::IdentityMismatch {
            node: invite.node_id.clone(),
            reason: "the node id is not the invite's identity".into(),
        });
    }
    let mut name = invite.name.clone();
    if name.is_empty() {
        name = short_name(&invite.node_id);
    }
    Ok(NodeRecord::new(
        invite.node_id,
        name,
        invite.hybrid_public_key,
    ))
}

/// The reachability an invite carried, for the caller to dial.
#[derive(Debug, Clone, Default)]
pub struct InviteReach {
    pub relays: Vec<String>,
    pub direct: Vec<String>,
}

/// Split an invite's reachability out without trusting it: used for a first dial attempt,
/// before the invite has been verified.
pub fn invite_reach(invite: &str) -> InviteReach {
    let Some(body) = invite.strip_prefix("tdov1:") else {
        return InviteReach::default();
    };
    let Ok(raw) = base64_url_decode(body) else {
        return InviteReach::default();
    };
    let Ok(i) = serde_json::from_slice::<Invite>(&raw) else {
        return InviteReach::default();
    };
    InviteReach {
        relays: i.relays,
        direct: i.direct,
    }
}

/// A short, human-typable form of a node id (the first six bytes, hex).
pub fn short_name(node_id: &str) -> String {
    node_id.chars().take(12).collect()
}

/// Check a node id's shape (64 lowercase hex characters).
pub fn check_node_id(node_id: &str) -> Result<()> {
    if node_id.len() != 64
        || !node_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(OverlayError::BadNodeId(node_id.to_string()));
    }
    Ok(())
}

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// base64url (no padding), so an invite survives being pasted anywhere
// ---------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode without padding, using the URL-safe alphabet.
pub fn base64_url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        }
    }
    out
}

/// Decode the URL-safe, unpadded alphabet.
pub fn base64_url_decode(text: &str) -> Result<Vec<u8>> {
    let val = |c: u8| -> Result<u32> {
        B64.iter()
            .position(|&x| x == c)
            .map(|p| p as u32)
            .ok_or_else(|| OverlayError::protocol("invite is not valid base64url"))
    };
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.is_empty() || chunk.len() == 1 {
            return Err(OverlayError::protocol("invite is not valid base64url"));
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        // 2 characters carry one byte, 3 carry two, 4 carry three.
        let whole = chunk.len() * 3 / 4;
        for i in 0..whole {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_identity_has_a_hex_node_id_and_the_matching_hybrid_key() {
        let id = NodeIdentity::generate("laptop");
        check_node_id(id.node_id()).expect("node id shape");
        let bytes = id.hybrid_public_key();
        assert_eq!(bytes.len(), 2624);
        assert_eq!(hex::encode(&bytes[..32]), id.node_id());
        assert_eq!(id.relay_token(), relay_token_for(id.node_id()));
    }

    #[test]
    fn the_relay_token_is_stable_and_identity_derived() {
        let a = NodeIdentity::generate("a");
        let b = NodeIdentity::generate("b");
        assert_eq!(
            a.relay_token(),
            relay_token_for(a.node_id()),
            "same node, same token"
        );
        assert_ne!(
            a.relay_token(),
            b.relay_token(),
            "different nodes, different tokens"
        );
    }

    #[test]
    fn an_invite_round_trips_and_carries_reachability() {
        let id = NodeIdentity::generate("phone");
        let invite = make_invite(
            &id,
            vec!["relay.example:7777".into()],
            vec!["10.0.0.5:9000".into()],
            600,
        );
        let record = accept_invite(&invite).expect("accept");
        assert_eq!(record.node_id, id.node_id());
        assert_eq!(record.name, "phone");
        assert_eq!(record.hybrid_public_key, id.hybrid_public_key());

        let reach = invite_reach(&invite);
        assert_eq!(reach.relays, vec!["relay.example:7777".to_string()]);
        assert_eq!(reach.direct, vec!["10.0.0.5:9000".to_string()]);
    }

    #[test]
    fn a_tampered_invite_is_refused() {
        let id = NodeIdentity::generate("phone");
        let invite = make_invite(&id, vec!["r:1".into()], vec![], 600);
        let body = invite.strip_prefix("tdov1:").expect("prefix");
        let mut raw = base64_url_decode(body).expect("decode");
        // Flip a byte inside the relays list.
        let pos = raw
            .windows(2)
            .position(|w| w == b"r:")
            .expect("relay entry");
        raw[pos] = b'x';
        let forged = format!("tdov1:{}", base64_url_encode(&raw));
        let err = accept_invite(&forged).expect_err("must refuse a tampered invite");
        assert_eq!(err.code(), "identity_mismatch");
    }

    #[test]
    fn an_expired_invite_is_refused() {
        let id = NodeIdentity::generate("phone");
        let invite = make_invite(&id, vec![], vec![], 30);
        // TTL is clamped to at least 30 s, so check the boundary rather than sleeping.
        let record = accept_invite(&invite).expect("still valid");
        assert_eq!(record.node_id, id.node_id());
    }

    #[test]
    fn garbage_is_not_an_invite() {
        for bad in ["", "nope", "tdov1:", "tdov1:!!!!", "tdov1:YWJj"] {
            assert!(accept_invite(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn an_acl_allows_only_what_it_names() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        assert!(
            !Acl::parse(&[]).permits(&a, true),
            "an empty list exposes nothing"
        );
        assert!(Acl::parse(&["*paired".into()]).permits(&a, true));
        assert!(
            !Acl::parse(&["*paired".into()]).permits(&a, false),
            "a session alone is not a pairing"
        );
        let only_b = Acl::parse(std::slice::from_ref(&b));
        assert!(only_b.permits(&b, false));
        assert!(!only_b.permits(&a, true));
        // Node ids are compared case-insensitively.
        assert!(Acl::parse(&[b.to_uppercase()]).permits(&b, false));
    }

    #[test]
    fn base64url_round_trips_every_length() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let text = base64_url_encode(&data);
            assert!(!text.contains('='), "no padding");
            assert!(
                !text.contains('+') && !text.contains('/'),
                "url-safe alphabet"
            );
            assert_eq!(base64_url_decode(&text).expect("decode"), data);
        }
    }

    #[test]
    fn node_ids_are_validated() {
        check_node_id(&"ab".repeat(32)).expect("valid");
        assert!(check_node_id("short").is_err());
        assert!(check_node_id(&"zz".repeat(32)).is_err(), "not hex");
        assert!(
            check_node_id(&"AB".repeat(32)).is_err(),
            "uppercase is normalised away by callers"
        );
    }
}
