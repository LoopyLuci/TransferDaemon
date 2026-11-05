//! Pairing methods: the ways two nodes come to trust each other.
//!
//! A method turns an offer, the text one person copies to the other, into a paired node. Every
//! method ends the same way: [`OverlayNode::pair_with`] records the node, the key it presents and
//! the addresses it can be reached on. Two methods ship:
//!
//! - `short-code`, offered as `tdo3:<address>/<code>`. The code is a random secret, shown once and
//!   valid for a short time. The two nodes run SPAKE2 with it over a direct address, so the code is
//!   never sent, and each node proves it knows the code with a MAC over the key it presents. A
//!   wrong guess leaves an attacker nothing to check offline.
//! - `signed`, offered as `tdov2:<invite>`. The inviter signs its identity and reach into the text.
//!   No connection is needed to make the offer, but the text is long.
//!
//! To add a method, implement [`PairingMethod`] with a fixed `id` and a prefix its offers start
//! with, then list it in [`methods`]. Inbound connections are routed by id, so nothing else changes.

use std::time::Duration;

use async_trait::async_trait;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use tokio::net::TcpStream;

use crate::error::{OverlayError, Result};
use crate::identity::{self, now_secs, HybridVerifyingKey, NodeRecord};
use crate::lanes::DIAL_TIMEOUT;
use crate::node::{OverlayNode, PairedPeer};
use crate::wire::{read_blob, write_blob};

/// Opens every pairing connection, so the listener can tell it from a handshake.
const PAIRING_MAGIC: &[u8] = b"TDPAIR1";
/// The longest method id a pairing connection may carry.
const MAX_METHOD_ID: usize = 32;
/// How long the listener waits for enough of an inbound connection's first bytes to route it.
const ROUTE_WAIT: Duration = Duration::from_secs(5);
/// How long either side waits for the other in a short-code exchange. A connection that goes quiet
/// fails within this time and gives its code back, so no connection can hold the code open.
#[cfg(not(test))]
const EXCHANGE_WAIT: Duration = Duration::from_secs(10);
#[cfg(test)]
const EXCHANGE_WAIT: Duration = Duration::from_secs(1);

/// The text prefix of a short-code offer. The version is in it, so an offer from another build is
/// refused by name.
const SHORT_PREFIX: &str = "tdo3:";
const CODE_LEN: usize = 10;
/// Crockford base32: no I, L, O or U, so a code copied by hand is not misread.
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Failed attempts against one code before it is burned.
const MAX_CODE_ATTEMPTS: u8 = 3;
const MAX_OFFER_ADDRS: usize = 4;
const MAX_NAME_CHARS: usize = 64;
const SPAKE_ID: &[u8] = b"transferd-overlay short code v1";
const CONFIRM_CONTEXT: &str = "transferd-overlay short code confirm v1";
const INVITER: &[u8] = b"inviter";
const ACCEPTER: &[u8] = b"accepter";
const REPLY_OK: u8 = 0;
const REPLY_REFUSED: u8 = 1;

/// One way two nodes can come to trust each other.
#[async_trait]
pub trait PairingMethod: Send + Sync {
    /// The method's name. It travels on the wire, and it is what callers ask for.
    fn id(&self) -> &'static str;

    /// Whether `offer` is one this method made, judged by its prefix alone.
    fn claims(&self, offer: &str) -> bool;

    /// Make an offer for the other node to pair with, valid for `ttl_s` seconds.
    fn offer(&self, node: &OverlayNode, ttl_s: u64) -> Result<String>;

    /// Pair with an offer another node made.
    async fn accept(
        &self,
        node: &OverlayNode,
        offer: &str,
        name: Option<String>,
    ) -> Result<NodeRecord>;

    /// Answer a pairing connection that opened with this method's id.
    async fn answer(&self, _node: &OverlayNode, _stream: TcpStream) -> Result<NodeRecord> {
        Err(OverlayError::protocol(format!(
            "the {} method pairs without a connection of its own",
            self.id()
        )))
    }
}

static SHORT_CODE: ShortCode = ShortCode;
static SIGNED: Signed = Signed;

/// Every pairing method this build offers, in the order they are listed.
pub fn methods() -> [&'static dyn PairingMethod; 2] {
    [&SHORT_CODE, &SIGNED]
}

/// The method with this id.
pub(crate) fn by_id(id: &str) -> Option<&'static dyn PairingMethod> {
    methods().into_iter().find(|m| m.id() == id)
}

/// The method that made this offer.
pub(crate) fn by_offer(offer: &str) -> Option<&'static dyn PairingMethod> {
    methods().into_iter().find(|m| m.claims(offer))
}

/// The pairing method an inbound connection asks for, when it is a pairing connection at all.
/// The bytes are only peeked, so a connection that is not a pairing one still reaches the
/// handshake untouched.
pub(crate) async fn inbound_method(stream: &TcpStream) -> Option<&'static dyn PairingMethod> {
    let magic_end = 4 + PAIRING_MAGIC.len();
    let mut head = [0u8; 4 + PAIRING_MAGIC.len() + 1 + MAX_METHOD_ID];
    let method = tokio::time::timeout(ROUTE_WAIT, async {
        loop {
            let n = stream.peek(&mut head).await.ok()?;
            if n == 0 {
                return None;
            }
            if n >= magic_end && &head[4..magic_end] != PAIRING_MAGIC {
                return None;
            }
            if n > magic_end {
                let id_len = head[magic_end] as usize;
                if id_len > MAX_METHOD_ID {
                    return None;
                }
                if n >= magic_end + 1 + id_len {
                    let id =
                        std::str::from_utf8(&head[magic_end + 1..magic_end + 1 + id_len]).ok()?;
                    return by_id(id);
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    method.ok().flatten()
}

/// The signed invite: the inviter's identity and reach, signed into the text.
struct Signed;

#[async_trait]
impl PairingMethod for Signed {
    fn id(&self) -> &'static str {
        "signed"
    }

    fn claims(&self, offer: &str) -> bool {
        offer.starts_with("tdov2:")
    }

    fn offer(&self, node: &OverlayNode, ttl_s: u64) -> Result<String> {
        Ok(node.invite_create(ttl_s))
    }

    async fn accept(
        &self,
        node: &OverlayNode,
        offer: &str,
        name: Option<String>,
    ) -> Result<NodeRecord> {
        node.invite_accept(offer, name)
    }
}

/// The short code: a random code, shown once, that pairs two nodes over a direct address.
struct ShortCode;

/// The one code a node will accept, and how many attempts have failed against it.
pub(crate) struct PendingCode {
    code: String,
    expires_at: u64,
    failures: u8,
}

/// What each side sends once the key is agreed: its hybrid public key and name, and a MAC over
/// them made with the agreed key, which only the holder of the code can make.
#[derive(Serialize, Deserialize)]
struct Confirm {
    pk: Vec<u8>,
    name: String,
    mac: Vec<u8>,
}

#[async_trait]
impl PairingMethod for ShortCode {
    fn id(&self) -> &'static str {
        "short-code"
    }

    fn claims(&self, offer: &str) -> bool {
        offer.starts_with(SHORT_PREFIX)
    }

    fn offer(&self, node: &OverlayNode, ttl_s: u64) -> Result<String> {
        let addrs: Vec<String> = node
            .published_direct()
            .into_iter()
            .filter(|a| valid_addr(a))
            .take(MAX_OFFER_ADDRS)
            .collect();
        if addrs.is_empty() {
            return Err(OverlayError::protocol(
                "a short code needs a direct address to point at: configure one, or start a listener",
            ));
        }
        let code = new_code();
        let expires_at = now_secs() + ttl_s.clamp(30, 86_400);
        // A new code replaces the old one, so there is only ever one code open.
        *node.pending_code().lock() = Some(PendingCode {
            code: code.clone(),
            expires_at,
            failures: 0,
        });
        Ok(format!(
            "{SHORT_PREFIX}{}/{}",
            addrs.join(","),
            display_code(&code)
        ))
    }

    async fn accept(
        &self,
        node: &OverlayNode,
        offer: &str,
        name: Option<String>,
    ) -> Result<NodeRecord> {
        let (addrs, code) = parse_offer(offer)?;
        let mut last_error = String::new();
        for addr in &addrs {
            match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    return bounded(pair_as_accepter(node, stream, &addrs, &code, name)).await;
                }
                Ok(Err(e)) => last_error = format!("{addr}: {e}"),
                Err(_) => last_error = format!("{addr} did not answer"),
            }
        }
        Err(OverlayError::protocol(format!(
            "cannot reach the node to pair with ({last_error})"
        )))
    }

    async fn answer(&self, node: &OverlayNode, mut stream: TcpStream) -> Result<NodeRecord> {
        let _ = stream.set_nodelay(true);
        let hello_bytes = bounded(read_blob(&mut stream)).await?;
        let msg_b = unhello(&hello_bytes, self.id())?;
        // Take the code for this attempt. Until it settles no other attempt can start, so guesses
        // cannot run in parallel.
        let taken = node.pending_code().lock().take();
        let mut pending = match taken {
            Some(pending) if pending.expires_at > now_secs() => pending,
            _ => {
                let _ = write_blob(
                    &mut stream,
                    &reply(REPLY_REFUSED, b"this node has no open code: make a new one"),
                )
                .await;
                return Err(OverlayError::protocol("a pairing asked for no open code"));
            }
        };
        match bounded(respond(node, &mut stream, &pending.code, msg_b)).await {
            Ok(peer) => {
                let direct = Vec::new();
                register_peer(node, peer, direct)
            }
            Err(e) => {
                pending.failures += 1;
                if pending.failures < MAX_CODE_ATTEMPTS && pending.expires_at > now_secs() {
                    *node.pending_code().lock() = Some(pending);
                }
                Err(e)
            }
        }
    }
}

/// The accepting side of a short-code pairing, over a connection already open to the inviter.
async fn pair_as_accepter(
    node: &OverlayNode,
    mut stream: TcpStream,
    addrs: &[String],
    code: &str,
    name: Option<String>,
) -> Result<NodeRecord> {
    let _ = stream.set_nodelay(true);
    let (state, msg_b) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(code.as_bytes()),
        &Identity::new(SPAKE_ID),
    );
    write_blob(&mut stream, &hello("short-code", &msg_b)).await?;

    let reply_bytes = read_blob(&mut stream).await.map_err(|_| wrong_code())?;
    let (status, msg_a) = reply_bytes
        .split_first()
        .ok_or_else(|| OverlayError::protocol("the node sent an empty reply"))?;
    if *status != REPLY_OK {
        return Err(OverlayError::protocol(format!(
            "the node refused: {}",
            String::from_utf8_lossy(msg_a)
        )));
    }
    let key = state
        .finish(msg_a)
        .map_err(|_| OverlayError::protocol("the node's pairing message is malformed"))?;

    let transcript = frame_parts(&[&msg_b, msg_a]);
    let own = node.identity();
    let own_pk = own.hybrid_public_key();
    let own_name = own.name().to_string();
    let mac = confirm_mac(&key, ACCEPTER, &transcript, &own_pk, &own_name);
    write_blob(
        &mut stream,
        &encode_confirm(&Confirm {
            pk: own_pk,
            name: own_name,
            mac: mac.to_vec(),
        })?,
    )
    .await?;

    let peer = decode_confirm(&read_blob(&mut stream).await.map_err(|_| wrong_code())?)?;
    if !confirm_matches(&key, INVITER, &transcript, &peer) {
        return Err(wrong_code());
    }
    let label = match name.map(|n| clean_name(&n)) {
        Some(label) if !label.is_empty() => label,
        _ => clean_name(&peer.name),
    };
    let node_id = peer_node_id(node, &peer)?;
    Ok(node.pair_with(PairedPeer {
        node_id,
        name: label,
        own_name: clean_name(&peer.name),
        hybrid_public_key: peer.pk.clone(),
        key_fingerprint: identity::key_fingerprint(&peer.pk),
        direct: addrs.to_vec(),
        relays: Vec::new(),
        pairing: String::new(),
    }))
}

/// The inviting side of a short-code pairing: answer the accepter, and check its key confirmation.
/// On success this node sends its own confirmation and returns the accepter's.
async fn respond(
    node: &OverlayNode,
    stream: &mut TcpStream,
    code: &str,
    msg_b: &[u8],
) -> Result<Confirm> {
    let (state, msg_a) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(code.as_bytes()),
        &Identity::new(SPAKE_ID),
    );
    let key = state
        .finish(msg_b)
        .map_err(|_| OverlayError::protocol("the pairing message is malformed"))?;
    write_blob(stream, &reply(REPLY_OK, &msg_a)).await?;

    let transcript = frame_parts(&[msg_b, &msg_a]);
    let peer = decode_confirm(&read_blob(stream).await?)?;
    if !confirm_matches(&key, ACCEPTER, &transcript, &peer) {
        return Err(wrong_code());
    }
    let own = node.identity();
    let own_pk = own.hybrid_public_key();
    let own_name = own.name().to_string();
    let mac = confirm_mac(&key, INVITER, &transcript, &own_pk, &own_name);
    write_blob(
        stream,
        &encode_confirm(&Confirm {
            pk: own_pk,
            name: own_name,
            mac: mac.to_vec(),
        })?,
    )
    .await?;
    Ok(peer)
}

/// Record the accepter that answered: its key is the one its confirmation was made with.
fn register_peer(node: &OverlayNode, peer: Confirm, direct: Vec<String>) -> Result<NodeRecord> {
    let node_id = peer_node_id(node, &peer)?;
    let own_name = clean_name(&peer.name);
    Ok(node.pair_with(PairedPeer {
        node_id: node_id.clone(),
        name: own_name.clone(),
        own_name,
        hybrid_public_key: peer.pk.clone(),
        key_fingerprint: identity::key_fingerprint(&peer.pk),
        direct,
        relays: Vec::new(),
        pairing: String::new(),
    }))
}

/// The node id a confirmation's key belongs to, after checking the key parses and is not this node.
fn peer_node_id(node: &OverlayNode, peer: &Confirm) -> Result<String> {
    if HybridVerifyingKey::from_bytes(&peer.pk).is_none() {
        return Err(OverlayError::protocol("the node presented a malformed key"));
    }
    let node_id = hex::encode(&peer.pk[..32]);
    identity::check_node_id(&node_id)?;
    if node_id == node.node_id() {
        return Err(OverlayError::protocol("that offer came from this node"));
    }
    Ok(node_id)
}

fn wrong_code() -> OverlayError {
    OverlayError::protocol(
        "the pairing did not complete: the code may be wrong, or it may have expired",
    )
}

/// Runs one step of a short-code exchange, and fails if the other side goes quiet.
async fn bounded<T>(step: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(EXCHANGE_WAIT, step)
        .await
        .unwrap_or_else(|_| Err(OverlayError::protocol("the other node went quiet")))
}

/// A fresh code: ten characters from the Crockford alphabet. A byte mod 32 is uniform, since 256
/// is a multiple of 32.
fn new_code() -> String {
    let mut bytes = [0u8; CODE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| CODE_ALPHABET[(*b % 32) as usize] as char)
        .collect()
}

/// A code as it is shown: two groups of five, with a dash between.
fn display_code(code: &str) -> String {
    format!("{}-{}", &code[..CODE_LEN / 2], &code[CODE_LEN / 2..])
}

/// A code as typed or pasted, normalised: spaces and dashes dropped, case folded, and the
/// characters Crockford reads as digits mapped to them. `None` if it cannot be a code.
fn normalize_code(text: &str) -> Option<String> {
    let mut out = String::with_capacity(CODE_LEN);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '-') {
        if !c.is_ascii() {
            return None;
        }
        let c = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        if !CODE_ALPHABET.contains(&(c as u8)) {
            return None;
        }
        out.push(c);
    }
    (out.len() == CODE_LEN).then_some(out)
}

/// The addresses and the code in a short-code offer.
fn parse_offer(offer: &str) -> Result<(Vec<String>, String)> {
    let body = offer
        .strip_prefix(SHORT_PREFIX)
        .ok_or_else(|| OverlayError::protocol("not a short code"))?;
    let (addrs, code) = body.rsplit_once('/').ok_or_else(|| {
        OverlayError::protocol("a short code is an address, a slash and the code")
    })?;
    let code = normalize_code(code).ok_or_else(|| {
        OverlayError::protocol("that code is not valid: ten characters, in two groups of five")
    })?;
    let addrs: Vec<String> = addrs
        .split(',')
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(String::from)
        .collect();
    if addrs.is_empty() || addrs.len() > MAX_OFFER_ADDRS || !addrs.iter().all(|a| valid_addr(a)) {
        return Err(OverlayError::protocol(
            "the addresses in that code are not valid",
        ));
    }
    Ok((addrs, code))
}

/// `host:port`, with no separator the offer format uses.
fn valid_addr(addr: &str) -> bool {
    !addr.contains([',', '/', ' '])
        && addr
            .rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
}

/// The name a peer gives itself, trimmed and capped.
fn clean_name(name: &str) -> String {
    name.trim().chars().take(MAX_NAME_CHARS).collect()
}

/// The MAC that proves a node knows the agreed key, bound to its role, the exchange so far, its
/// key and its name.
fn confirm_mac(key: &[u8], role: &[u8], transcript: &[u8], pk: &[u8], name: &str) -> [u8; 32] {
    let mac_key = blake3::derive_key(CONFIRM_CONTEXT, key);
    *blake3::keyed_hash(
        &mac_key,
        &frame_parts(&[role, transcript, pk, name.as_bytes()]),
    )
    .as_bytes()
}

/// Whether the peer's confirmation carries the right MAC for its role. The comparison is
/// constant-time.
fn confirm_matches(key: &[u8], role: &[u8], transcript: &[u8], peer: &Confirm) -> bool {
    let expected = confirm_mac(key, role, transcript, &peer.pk, &peer.name);
    let Ok(got): std::result::Result<[u8; 32], _> = peer.mac.as_slice().try_into() else {
        return false;
    };
    blake3::Hash::from(got) == blake3::Hash::from(expected)
}

/// Length-prefixed concatenation, so no two different lists of parts give the same bytes.
fn frame_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// A pairing connection's first blob: the magic, the method id, and the method's payload.
fn hello(method: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAIRING_MAGIC.len() + 1 + method.len() + payload.len());
    out.extend_from_slice(PAIRING_MAGIC);
    out.push(method.len() as u8);
    out.extend_from_slice(method.as_bytes());
    out.extend_from_slice(payload);
    out
}

/// The payload of a pairing hello, if it is for `method`.
fn unhello<'a>(bytes: &'a [u8], method: &str) -> Result<&'a [u8]> {
    let rest = bytes
        .strip_prefix(PAIRING_MAGIC)
        .ok_or_else(|| OverlayError::protocol("not a pairing connection"))?;
    let (id_len, rest) = rest
        .split_first()
        .ok_or_else(|| OverlayError::protocol("a pairing connection names no method"))?;
    let id_len = *id_len as usize;
    if rest.len() < id_len || &rest[..id_len] != method.as_bytes() {
        return Err(OverlayError::protocol(
            "the connection is for another pairing method",
        ));
    }
    Ok(&rest[id_len..])
}

/// A reply: a status byte, then the body.
fn reply(status: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(status);
    out.extend_from_slice(body);
    out
}

fn encode_confirm(confirm: &Confirm) -> Result<Vec<u8>> {
    bincode::serialize(confirm).map_err(|_| OverlayError::protocol("cannot encode a confirmation"))
}

fn decode_confirm(bytes: &[u8]) -> Result<Confirm> {
    bincode::deserialize(bytes)
        .map_err(|_| OverlayError::protocol("the node's confirmation is malformed"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::identity::NodeIdentity;
    use crate::node::OverlayConfig;

    async fn node(name: &str) -> Arc<OverlayNode> {
        let mut config = OverlayConfig::local(NodeIdentity::generate(name));
        config.listen = Some("127.0.0.1:0".parse().expect("a loopback address"));
        OverlayNode::start(config).await.expect("the node starts")
    }

    /// The same offer with a different code: the first character changed.
    fn with_other_code(offer: &str) -> String {
        let (head, code) = offer.rsplit_once('/').expect("an offer has a code");
        let mut chars: Vec<char> = code.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        format!("{head}/{}", chars.into_iter().collect::<String>())
    }

    /// Poll until `done` holds, for the side of a pairing that settles after the other returns.
    async fn settle(what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..200 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(done(), "{what} did not settle");
    }

    #[test]
    fn a_short_code_has_the_short_form() {
        let code = new_code();
        assert_eq!(code.len(), CODE_LEN);
        assert!(code.bytes().all(|b| CODE_ALPHABET.contains(&b)));
        let shown = display_code(&code);
        assert_eq!(shown.len(), CODE_LEN + 1);
        assert_eq!(normalize_code(&shown).as_deref(), Some(code.as_str()));
    }

    #[test]
    fn a_typed_code_is_normalised() {
        assert_eq!(normalize_code("k7q9m-2xd4w").as_deref(), Some("K7Q9M2XD4W"));
        assert_eq!(normalize_code("O0IL-11111X").as_deref(), Some("001111111X"));
        assert_eq!(normalize_code("TOO-SHORT"), None);
        assert_eq!(normalize_code("K7Q9M2XD4U"), None);
    }

    #[test]
    fn the_method_list_names_every_method_once() {
        let ids: Vec<&str> = methods().iter().map(|m| m.id()).collect();
        assert_eq!(ids, ["short-code", "signed"]);
        assert!(by_offer("tdo3:127.0.0.1:1/ABCDE-FGHJK").is_some());
        assert!(by_offer("tdov2:anything").is_some());
        assert!(by_offer("nope").is_none());
    }

    #[tokio::test]
    async fn a_right_code_pairs_both_nodes() {
        let inviter = node("inviter").await;
        let accepter = node("accepter").await;
        let offer = inviter.pair_offer("short-code", 600).expect("an offer");
        assert!(offer.starts_with("tdo3:"), "got {offer}");
        assert!(offer.len() < 80, "the offer is {} characters", offer.len());

        let record = accepter
            .pair_accept(&offer, Some("the inviter".into()))
            .await
            .expect("the right code pairs");
        assert_eq!(record.node_id, inviter.node_id());
        assert_eq!(record.name, "the inviter");
        assert!(accepter.is_paired(&inviter.node_id()));
        let inviter_side = inviter.clone();
        let accepter_id = accepter.node_id();
        settle("the inviter's pairing", move || {
            inviter_side.is_paired(&accepter_id)
        })
        .await;
    }

    #[tokio::test]
    async fn a_wrong_code_is_refused_and_counts_against_the_code() {
        let inviter = node("inviter").await;
        let accepter = node("accepter").await;
        let offer = inviter.pair_offer("short-code", 600).expect("an offer");

        assert!(accepter
            .pair_accept(&with_other_code(&offer), None)
            .await
            .is_err());
        let inviter_side = inviter.clone();
        settle("the failed attempt", move || {
            inviter_side
                .pending_code()
                .lock()
                .as_ref()
                .map(|p| p.failures)
                == Some(1)
        })
        .await;
        assert!(!inviter.is_paired(&accepter.node_id()));

        accepter
            .pair_accept(&offer, None)
            .await
            .expect("the right code still pairs after one wrong try");
    }

    #[tokio::test]
    async fn three_wrong_codes_burn_the_code() {
        let inviter = node("inviter").await;
        let accepter = node("accepter").await;
        let offer = inviter.pair_offer("short-code", 600).expect("an offer");
        let wrong = with_other_code(&offer);

        for _ in 0..MAX_CODE_ATTEMPTS {
            assert!(accepter.pair_accept(&wrong, None).await.is_err());
        }
        let inviter_side = inviter.clone();
        settle("the code to burn", move || {
            inviter_side.pending_code().lock().is_none()
        })
        .await;

        assert!(accepter.pair_accept(&offer, None).await.is_err());
    }

    #[tokio::test]
    async fn a_code_pairs_once() {
        let inviter = node("inviter").await;
        let first = node("first").await;
        let second = node("second").await;
        let offer = inviter.pair_offer("short-code", 600).expect("an offer");

        first
            .pair_accept(&offer, None)
            .await
            .expect("the first pairs");
        assert!(second.pair_accept(&offer, None).await.is_err());
    }

    /// A connection that starts an exchange and then goes quiet gives its code back once the
    /// exchange times out. It does not hold the code open, so the right code still pairs.
    #[tokio::test]
    async fn a_stalled_attempt_gives_the_code_back() {
        let inviter = node("inviter").await;
        let accepter = node("accepter").await;
        let offer = inviter.pair_offer("short-code", 600).expect("an offer");
        let listener = inviter.listener_addr().expect("the inviter listens");

        // A valid first message for a guessed code, and then silence.
        let (_guess, msg) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(b"a guess"),
            &Identity::new(SPAKE_ID),
        );
        let mut stalled = TcpStream::connect(listener).await.expect("connects");
        write_blob(&mut stalled, &hello("short-code", &msg))
            .await
            .expect("the hello is sent");

        let inviter_side = inviter.clone();
        settle("the stalled attempt to give the code back", move || {
            inviter_side
                .pending_code()
                .lock()
                .as_ref()
                .map(|p| p.failures)
                == Some(1)
        })
        .await;
        accepter
            .pair_accept(&offer, None)
            .await
            .expect("the code still pairs");
        drop(stalled);
    }

    #[tokio::test]
    async fn an_expired_code_is_refused() {
        let inviter = node("inviter").await;
        let accepter = node("accepter").await;
        let offer = inviter.pair_offer("short-code", 600).expect("an offer");
        if let Some(pending) = inviter.pending_code().lock().as_mut() {
            pending.expires_at = 1;
        }

        assert!(accepter.pair_accept(&offer, None).await.is_err());
    }

    #[tokio::test]
    async fn a_new_code_replaces_the_old_one() {
        let inviter = node("inviter").await;
        let accepter = node("accepter").await;
        let old = inviter.pair_offer("short-code", 600).expect("an offer");
        let new = inviter.pair_offer("short-code", 600).expect("an offer");

        assert!(accepter.pair_accept(&old, None).await.is_err());
        accepter
            .pair_accept(&new, None)
            .await
            .expect("the new code pairs");
    }

    #[tokio::test]
    async fn the_signed_method_still_pairs() {
        let inviter = node("inviter").await;
        let accepter = node("accepter").await;
        let offer = inviter.pair_offer("signed", 600).expect("an offer");
        assert!(offer.starts_with("tdov2:"));

        let record = accepter
            .pair_accept(&offer, None)
            .await
            .expect("the invite pairs");
        assert_eq!(record.node_id, inviter.node_id());
    }

    #[tokio::test]
    async fn unknown_methods_and_offers_are_refused() {
        let inviter = node("inviter").await;
        assert!(inviter.pair_offer("no-such-method", 600).is_err());
        assert!(inviter
            .pair_accept("tdxx:127.0.0.1:1/ABCDE-FGHJK", None)
            .await
            .is_err());
    }
}
