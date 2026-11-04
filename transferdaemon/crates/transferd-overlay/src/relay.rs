//! The relay path: one registered point, many peers, one inbound demultiplexer.
//!
//! A relay is the only path that always works: it is reached by an *outbound* datagram, and it
//! delivers to the mapping that datagram created. Nothing here ever listens, so nothing here
//! needs a firewall port — on this node or on any peer.
//!
//! Over one relay the overlay runs two kinds of payload:
//!
//! ```text
//! [0x01][sender_token: 32][initiator flight]    the authenticated hybrid handshake, opening
//! [0x03][sender_token: 32][responder flight]    ... and its answer
//! [0x02][sender_token: 32][sealed tunnel frame] a session's traffic
//! ```
//!
//! both padded to a power of two with a length header, so the relay only ever sees fixed-grid
//! ciphertext sizes and never learns who is talking to whom.
//!
//! The socket the node registered with is also the one its hole punches use (see `punch.rs`): the
//! NAT mapping the relay saw is the only mapping a peer can be sure to find. So the one inbound
//! loop here first offers every datagram to the punch table, and what is not a probe or the
//! traffic of a punched route is a relay datagram as before.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use relayd::protocol::{encode, split, DeliveredMsg, LocateMsg, LocatedMsg, Tag};
use tokio::sync::oneshot;
use transferd_core::lanes::relay_client::RelayClient;

use crate::error::{OverlayError, Result};
use crate::identity::{self, NodeIdentity};
use crate::lanes::FramePipe;
use crate::link::RouteKind;
use crate::protocol::{Candidate, FrameReader};
use crate::punch::{self, PunchTable};
use crate::wire::{LinkKeys, Tunnel};

/// The prefix of a handshake flight inside a relay payload.
pub const PREFIX_HANDSHAKE: u8 = 0x01;
/// The prefix of a session frame inside a relay payload.
pub const PREFIX_DATA: u8 = 0x02;
/// The prefix of a handshake answer. Apart from the opening flight, so two nodes dialling each
/// other at the same moment never take the other's opening for an answer.
pub const PREFIX_HANDSHAKE_REPLY: u8 = 0x03;

/// How long a relay handshake may take. Four datagrams must all get through (there and back,
/// each via the relay), so on a lossy path it takes several tries: at 20% loss one try works
/// about 40% of the time, and ten seconds of tries fail together well under 1% of the time.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often an unanswered handshake flight is sent again (a datagram may be lost).
const FLIGHT_RESEND: Duration = Duration::from_millis(900);
/// Answers kept so a resent flight gets the same answer instead of a second session key.
const ANSWERS_KEPT: usize = 64;

/// How long to wait for a handshake or a locate answer.
const RELAY_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the registration is renewed. Well inside relayd's TTL, and soon enough after a
/// relay restart that the node is reachable again within a minute.
const REREGISTER_EVERY: Duration = Duration::from_secs(30);

/// Session payloads held for a peer whose link is not registered yet, at most this many per
/// peer and for this many peers. The two sides of a handshake finish at slightly different
/// moments, so the first frames can overtake the link they belong to.
const EARLY_PER_PEER: usize = 64;
const EARLY_PEERS: usize = 64;
/// Links kept per peer on one relay. Two are normal (each side dialled once, or a route added
/// while the first was up); the oldest beyond this is closed.
const LINKS_PER_PEER: usize = 4;

/// One peer's link over this relay, plus the state its reader needs.
struct PeerLink {
    link: Arc<FramePipe>,
    tunnel: Tunnel,
    reader: FrameReader,
}

impl PeerLink {
    /// Open one sealed payload (the tunnel checks authenticity and replay) and pass on its
    /// frames. False when it is not this link's: another link to the same peer may own it.
    fn deliver(&mut self, sealed: &[u8]) -> bool {
        let Ok(plain) = self.tunnel.open(sealed) else {
            return false;
        };
        for frame in self.reader.push(&plain) {
            self.link.push_frame(frame);
        }
        true
    }
}

/// Hand a payload to whichever of a peer's links it authenticates for. The payload carries no
/// link id (the relay sees nothing but ciphertext), so the keys are what tell them apart.
fn deliver_to(links: &mut [PeerLink], sealed: &[u8]) -> bool {
    links.iter_mut().any(|l| l.deliver(sealed))
}

/// A registered relay and the sessions multiplexed over it.
pub struct RelayHub {
    pub addr: SocketAddr,
    client: Arc<RelayClient>,
    self_token: [u8; 32],
    peers: Mutex<HashMap<[u8; 32], Vec<PeerLink>>>,
    /// Payloads that arrived before their peer's link was registered.
    early: Mutex<HashMap<[u8; 32], Vec<Vec<u8>>>>,
    /// Flights already answered (by a hash of the flight), with the answer sent.
    answered: Mutex<HashMap<[u8; 32], Vec<u8>>>,
    /// Handshake answers still expected, by the peer's token.
    handshakes: Mutex<HashMap<[u8; 32], oneshot::Sender<Vec<u8>>>>,
    /// Address-location answers still expected, by request id.
    locates: Mutex<HashMap<u32, oneshot::Sender<LocatedMsg>>>,
    next_request: std::sync::atomic::AtomicU32,
    /// Hole punches and punched routes on this same socket.
    punch: Arc<PunchTable>,
    /// This node's own identity, used to answer an inbound handshake.
    identity: NodeIdentity,
    /// The node this hub belongs to, so an inbound handshake becomes a session.
    node: crate::node::OverlayNode,
}

impl RelayHub {
    /// Register on `addr` with `self_token`, then start the one inbound loop that feeds every
    /// session on this relay.
    pub async fn start(
        addr: SocketAddr,
        self_token: [u8; 32],
        identity: NodeIdentity,
        node: crate::node::OverlayNode,
    ) -> Result<Arc<Self>> {
        let client = Arc::new(
            RelayClient::bind(addr)
                .await
                .map_err(|e| OverlayError::Relay {
                    addr: addr.to_string(),
                    reason: e.to_string(),
                })?,
        );
        client
            .register(self_token)
            .await
            .map_err(|e| OverlayError::Relay {
                addr: addr.to_string(),
                reason: e.to_string(),
            })?;
        let punch = PunchTable::new(client.socket(), node.udp_gateway(), addr.ip().is_loopback());
        let hub = Arc::new(Self {
            addr,
            client,
            punch,
            self_token,
            peers: Mutex::new(HashMap::new()),
            early: Mutex::new(HashMap::new()),
            answered: Mutex::new(HashMap::new()),
            handshakes: Mutex::new(HashMap::new()),
            locates: Mutex::new(HashMap::new()),
            next_request: std::sync::atomic::AtomicU32::new(1),
            identity,
            node,
        });
        let reader = hub.clone();
        tokio::spawn(async move { reader.recv_loop().await });
        hub.spawn_registration();
        Ok(hub)
    }

    /// Renew the registration for as long as the hub lives. A fresh registration is also what
    /// a restarted relay needs, so the node never stays unreachable after one.
    fn spawn_registration(self: &Arc<Self>) {
        let hub = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(REREGISTER_EVERY);
            ticker.tick().await; // the first tick is now, and we just registered
            loop {
                ticker.tick().await;
                let Some(hub) = hub.upgrade() else { break };
                if let Err(e) = hub.client.send_register(hub.self_token).await {
                    tracing::debug!("[overlay relay] re-registering on {}: {e}", hub.addr);
                }
            }
        });
    }

    /// The token the relay routes our messages to us under.
    pub fn self_token(&self) -> [u8; 32] {
        self.self_token
    }

    async fn recv_loop(self: Arc<Self>) {
        let socket = self.client.socket();
        let mut buf = vec![0u8; 65_536];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            // A datagram a peer sent through the gateway arrives wrapped with its address; one
            // that came straight (or the relay's own) is looked at as it is.
            let (src, data) = match self.punch.gateway() {
                Some(gateway) if from == gateway => match punch::gateway_unwrap(&buf[..n]) {
                    Some((src, inner)) => {
                        if !self.punch.on_datagram(src, inner) {
                            tracing::trace!(
                                "[overlay relay] a wrapped datagram from {src} is not ours"
                            );
                        }
                        continue;
                    }
                    None => (from, &buf[..n]),
                },
                _ => (from, &buf[..n]),
            };
            if self.punch.on_datagram(src, data) {
                continue;
            }
            let Some((tag, body)) = split(data) else {
                continue;
            };
            match tag {
                Tag::Ack => {
                    let Ok(delivered) = bincode::deserialize::<DeliveredMsg>(body) else {
                        continue;
                    };
                    self.dispatch(&delivered.ciphertext);
                }
                Tag::Locate => {
                    let Ok(answer) = bincode::deserialize::<LocatedMsg>(body) else {
                        continue;
                    };
                    if let Some(tx) = self.locates.lock().remove(&answer.request) {
                        let _ = tx.send(answer);
                    }
                }
                _ => {}
            }
        }
    }

    /// Answer handshakes that peers dial through this relay, so inbound-only nodes are
    /// reachable too.
    ///
    /// A peer that knows our relay token can reach us with **no inbound port**: it sends the
    /// handshake through the relay, and the relay delivers it to the mapping our own
    /// registration created.
    fn answer_inbound_handshake(self: &Arc<Self>, from: [u8; 32], flight: Vec<u8>) {
        let hub = self.clone();
        tokio::spawn(async move {
            // A flight we answered already was resent because our answer was lost: send the same
            // answer again. Answering afresh would make a second key the dialler never sees.
            let id = *blake3::hash(&flight).as_bytes();
            let known = hub.answered.lock().get(&id).cloned();
            if let Some(reply) = known {
                let _ = hub.send_payload(PREFIX_HANDSHAKE_REPLY, from, &reply).await;
                return;
            }
            let Some((keys, peer_id, reply)) = hub.answer_handshake(&flight, &hub.identity) else {
                return;
            };
            {
                let mut answered = hub.answered.lock();
                if answered.len() >= ANSWERS_KEPT {
                    answered.clear();
                }
                answered.insert(id, reply.clone());
            }
            // The token is derived from the node id, so the two are the same key material.
            let peer_token = identity::relay_token_for(&peer_id);
            // The link is registered before the answer goes out, so the dialler's first frames
            // find it.
            let link = hub.link(hub.node.next_link_id(), peer_token, &keys).await;
            let _ = hub.send_payload(PREFIX_HANDSHAKE_REPLY, from, &reply).await;
            hub.node
                .adopt_relay_link(link, peer_id, from, RouteKind::Relay)
                .await;
        });
    }

    /// Hand one payload to the session it belongs to, or to whoever is waiting for it.
    fn dispatch(self: &Arc<Self>, payload: &[u8]) {
        let Some((prefix, from, rest)) = unpad(payload) else {
            tracing::debug!("[overlay relay] a payload arrived that is not one of ours");
            return;
        };
        tracing::trace!(
            "[overlay relay] {} byte payload, prefix {prefix:#04x}",
            rest.len()
        );
        match prefix {
            PREFIX_HANDSHAKE => self.answer_inbound_handshake(from, rest.to_vec()),
            PREFIX_HANDSHAKE_REPLY => {
                // An answer nobody waits for any more (a copy, for a resent flight) is dropped.
                if let Some(tx) = self.handshakes.lock().remove(&from) {
                    let _ = tx.send(rest.to_vec());
                }
            }
            PREFIX_DATA => {
                let mut peers = self.peers.lock();
                match peers.get_mut(&from) {
                    Some(links) => {
                        if !deliver_to(links, rest) {
                            tracing::debug!("[overlay relay] a session payload did not open (replayed or not ours)");
                        }
                    }
                    None => {
                        drop(peers);
                        let mut early = self.early.lock();
                        if early.len() >= EARLY_PEERS && !early.contains_key(&from) {
                            tracing::debug!(
                                "[overlay relay] a session payload for an unknown peer was dropped"
                            );
                            return;
                        }
                        let held = early.entry(from).or_default();
                        if held.len() < EARLY_PER_PEER {
                            held.push(rest.to_vec());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Run the authenticated hybrid handshake with a peer over this relay.
    ///
    /// Returns the link keys: the same derivation as a direct connection, so a relay path and
    /// a direct path are interchangeable and either can be added to a running session. It also
    /// returns the peer's 2624-byte hybrid public key from its verified flight, for the caller to
    /// check against the peer's key fingerprint.
    pub async fn handshake(
        &self,
        peer_node_id: &str,
        peer_token: [u8; 32],
        identity: &NodeIdentity,
    ) -> Result<(LinkKeys, Vec<u8>)> {
        let (tx, rx) = oneshot::channel();
        self.handshakes.lock().insert(peer_token, tx);
        let init = transferd_crypto::handshake::Initiator::new();
        let flight = transferd_crypto::auth_handshake::AuthInitiatorHello::build(
            &init,
            transferd_crypto::auth_handshake::PROTOCOL_VERSION,
            transferd_crypto::auth_handshake::CIPHERSUITE_HYBRID_X25519_MLKEM768,
            identity.signing_key(),
        );
        let body = flight.to_wire();
        tracing::debug!(
            "[overlay relay] handshake flight to {peer_node_id} via {}",
            self.addr
        );
        // The same flight again until it is answered: a datagram may be lost on the way there or
        // back, and the peer answers a repeat with the answer it already gave.
        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        let mut rx = rx;
        let reply = loop {
            self.send_payload(PREFIX_HANDSHAKE, peer_token, &body)
                .await?;
            let wait =
                FLIGHT_RESEND.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
            match tokio::time::timeout(wait, &mut rx).await {
                Ok(Ok(bytes)) => break bytes,
                Ok(Err(_)) => return Err(OverlayError::protocol("the handshake was abandoned")),
                Err(_) if tokio::time::Instant::now() < deadline => continue,
                Err(_) => {
                    self.handshakes.lock().remove(&peer_token);
                    return Err(OverlayError::protocol(format!(
                        "{peer_node_id} did not answer through {}",
                        self.addr
                    )));
                }
            }
        };
        let resp = transferd_crypto::auth_handshake::AuthResponderHello::from_wire(&reply)
            .ok_or_else(|| OverlayError::protocol("the responder flight is malformed"))?;
        if !resp.verify() {
            return Err(OverlayError::protocol(
                "the responder flight signature does not verify",
            ));
        }
        let seen = hex::encode(&resp.identity_pk.to_bytes()[..32]);
        if seen != peer_node_id {
            return Err(OverlayError::IdentityMismatch {
                node: seen,
                reason: format!("we dialled {peer_node_id}"),
            });
        }
        let session = init.finalize(resp.hello);
        Ok((
            LinkKeys::derive(session.as_bytes()),
            resp.identity_pk.to_bytes(),
        ))
    }

    /// Answer an inbound handshake from a peer that dialled us through this relay.
    ///
    /// Returns the link keys, the peer's node id (taken from the signed flight itself) and the
    /// answer to send back.
    pub fn answer_handshake(
        &self,
        flight: &[u8],
        identity: &NodeIdentity,
    ) -> Option<(LinkKeys, String, Vec<u8>)> {
        let hello = transferd_crypto::auth_handshake::AuthInitiatorHello::from_wire(flight)?;
        if !hello.verify() {
            return None;
        }
        let (responder, session) =
            transferd_crypto::handshake::Responder::new().respond(&hello.hello);
        let reply = transferd_crypto::auth_handshake::AuthResponderHello::build(
            &responder,
            transferd_crypto::auth_handshake::PROTOCOL_VERSION,
            transferd_crypto::auth_handshake::CIPHERSUITE_HYBRID_X25519_MLKEM768,
            identity.signing_key(),
        );
        let peer_id = hex::encode(&hello.identity_pk.to_bytes()[..32]);
        Some((
            LinkKeys::derive(session.as_bytes()).swapped(),
            peer_id,
            reply.to_wire(),
        ))
    }

    /// Open a session link to a peer over this relay.
    pub async fn link(&self, id: u32, peer_token: [u8; 32], keys: &LinkKeys) -> Arc<FramePipe> {
        let (link, rx) = FramePipe::new(
            id,
            RouteKind::Relay,
            format!("relay://{}#{}", self.addr, hex::encode(peer_token)),
            keys,
        );
        let mut peer_link = PeerLink {
            link: link.clone(),
            tunnel: Tunnel::receiver(keys),
            reader: FrameReader::new(),
        };
        {
            // Anything that overtook the link is delivered first, then the link takes over —
            // under the peers lock, so nothing can slip in between.
            let mut peers = self.peers.lock();
            for sealed in self.early.lock().remove(&peer_token).unwrap_or_default() {
                peer_link.deliver(&sealed);
            }
            let links = peers.entry(peer_token).or_default();
            links.retain(|l| l.link.is_open());
            links.insert(0, peer_link);
            while links.len() > LINKS_PER_PEER {
                if let Some(old) = links.pop() {
                    old.link.close();
                }
            }
        }
        let client = self.client.clone();
        let self_token = self.self_token;
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(sealed) = rx.recv().await {
                let mut body = Vec::with_capacity(1 + 32 + sealed.len());
                body.push(PREFIX_DATA);
                body.extend_from_slice(&self_token);
                body.extend_from_slice(&sealed);
                // A datagram that could not be sent is a lost datagram, which the session repairs;
                // it is no reason to close the route (that would end a session over one hiccup).
                if let Err(e) = client.send_forward(peer_token, &pad(&body)).await {
                    tracing::debug!("[overlay relay] a datagram was not sent: {e}");
                }
            }
        });
        link
    }

    /// Send one sealed blob to a peer through this relay.
    pub async fn forward(&self, peer_token: [u8; 32], sealed: Vec<u8>) -> Result<()> {
        self.client
            .send_forward(peer_token, &self.encapsulate(sealed))
            .await
            .map_err(|e| OverlayError::Relay {
                addr: self.addr.to_string(),
                reason: e.to_string(),
            })
    }

    fn encapsulate(&self, sealed: Vec<u8>) -> Vec<u8> {
        let mut body = Vec::with_capacity(1 + 32 + sealed.len());
        body.push(PREFIX_DATA);
        body.extend_from_slice(&self.self_token);
        body.extend_from_slice(&sealed);
        pad(&body)
    }

    async fn send_payload(&self, prefix: u8, peer_token: [u8; 32], body: &[u8]) -> Result<()> {
        let mut payload = Vec::with_capacity(1 + 32 + body.len());
        payload.push(prefix);
        payload.extend_from_slice(&self.self_token);
        payload.extend_from_slice(body);
        self.client
            .send_forward(peer_token, &pad(&payload))
            .await
            .map_err(|e| OverlayError::Relay {
                addr: self.addr.to_string(),
                reason: e.to_string(),
            })
    }

    /// Ask the relay which addresses it sees for us and for a peer (STUN-style).
    ///
    /// This is what makes a hole punch possible: the relay is the only party that can observe a
    /// NAT's mapped address, and it hands out nothing but the two addresses the two nodes would
    /// exchange anyway.
    pub async fn locate(&self, peer_token: [u8; 32]) -> Result<LocatedMsg> {
        let request = self
            .next_request
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.locates.lock().insert(request, tx);
        let pow_nonce =
            self.client
                .pow_nonce(self.self_token)
                .await
                .map_err(|e| OverlayError::Relay {
                    addr: self.addr.to_string(),
                    reason: e.to_string(),
                })?;
        let msg = LocateMsg {
            self_token: self.self_token,
            peer_token,
            pow_nonce,
            seq: request,
        };
        let frame = encode(Tag::Locate, &msg).map_err(|e| OverlayError::Relay {
            addr: self.addr.to_string(),
            reason: e.to_string(),
        })?;
        self.client
            .socket()
            .send_to(&frame, self.addr)
            .await
            .map_err(|e| OverlayError::Relay {
                addr: self.addr.to_string(),
                reason: e.to_string(),
            })?;
        match tokio::time::timeout(RELAY_TIMEOUT, rx).await {
            Ok(Ok(answer)) => Ok(answer),
            _ => {
                self.locates.lock().remove(&request);
                Err(OverlayError::protocol(format!(
                    "{} did not answer a locate",
                    self.addr
                )))
            }
        }
    }

    /// The addresses a peer may try for a hole punch to this node: the one the relay sees for the
    /// registration socket (asked on that same socket, so it is the NAT mapping the punch will
    /// use), and this machine's own address towards the relay when it is not loopback (for a
    /// peer on the same network, which a NAT would not loop traffic back to).
    pub async fn punch_candidates(&self, peer_token: [u8; 32]) -> Result<Vec<Candidate>> {
        let located = self.locate(peer_token).await?;
        let mut out = vec![Candidate {
            addr: located.self_addr.to_string(),
            private: false,
        }];
        if let (Some(ip), Some(port)) = (punch::local_ip_toward(self.addr), self.punch.local_port())
        {
            let own = SocketAddr::new(ip, port);
            if own != located.self_addr && punch::acceptable_candidate(own, false) {
                out.push(Candidate {
                    addr: own.to_string(),
                    private: true,
                });
            }
        }
        Ok(out)
    }

    /// Register a hole-punch attempt on the registration socket (see `PunchTable::begin`).
    pub(crate) fn punch_begin(&self, params: punch::PunchParams) -> Result<punch::Running> {
        self.punch.begin(params)
    }

    /// Forget a peer (its session ended).
    pub async fn forget(&self, peer_token: [u8; 32]) {
        self.peers.lock().remove(&peer_token);
        self.early.lock().remove(&peer_token);
    }
}

/// Pad to a power of two with a 4-byte little-endian length header.
pub fn pad(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut power = 64usize;
    while power < data.len() + 4 {
        power *= 2;
    }
    let mut out = Vec::with_capacity(power);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    out.resize(power, 0);
    out
}

/// Strip the padding: returns `(prefix, sender token, body)`.
pub fn unpad(data: &[u8]) -> Option<(u8, [u8; 32], &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
    if 4 + len > data.len() {
        return None;
    }
    let body = &data[4..4 + len];
    let (&prefix, rest) = body.split_first()?;
    let token: [u8; 32] = rest.get(..32)?.try_into().ok()?;
    Some((prefix, token, &rest[32..]))
}
