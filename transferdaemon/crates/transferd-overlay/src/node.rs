//! The overlay node: the always-connected, self-routing network one machine participates in.
//!
//! # Reachability is outbound-only
//!
//! Every node keeps authenticated **outbound** connections. Nothing is ever dialled *into*:
//!
//! 1. It registers its identity-derived token on every configured relay — a self-hostable
//!    `relayd`, and any paired node that is itself reachable can run one for the rest. A relay
//!    delivers to the mapping our outbound datagram created, so a NAT, a firewall or a CGNAT
//!    needs no configuration at all.
//! 2. Direct addresses a peer published (its listener, a LAN or tailnet address) are dialled
//!    first, with a short timeout, and the relay is used when none answers. Once a session is
//!    up, the other kind of path is added beside it, so a stream can fail over.
//! 3. When a session is up over the relay, the two nodes try a coordinated UDP hole punch over
//!    it (`punch.rs`): each sends authenticated probes from its relay socket at the addresses
//!    the other named. If one gets through, the session gains a direct route; if not, nothing
//!    changes.
//! 4. The relay is always the fallback, so "always reachable" never depends on a direct path
//!    existing.
//!
//! # Services
//!
//! `expose` publishes a local service with an access list of node identities — and nothing is
//! reachable until it is called. A peer that is not on the list never reaches the local socket:
//! the ACL is checked before the stream is accepted, and the refusal is audited.
//!
//! `connect` gives a stable local endpoint for a peer's service. The endpoint outlives the
//! session: when a session comes back, the same local address starts forwarding again.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::error::{OverlayError, Result};
use crate::events::{now_secs, Audit, AuditRecord, EventLog, OverlayEvent};
use crate::identity::{self, Acl, ExposedService, NodeIdentity, NodeRecord, ServiceRate};
use crate::lanes::{self, FramePipe};
use crate::link::{Link, RouteKind};
use crate::mux::StreamId;
use crate::protocol::{self, ServiceInfo};
use crate::punch;
use crate::relay::RelayHub;
use crate::session::{self, SessionEvent, SessionHandle};
use crate::state::{StoredConnect, StoredExpose, StoredGroup, StoredNode, StoredState};

/// How often the node saves its state.
pub const NODE_TICK: Duration = Duration::from_secs(30);

/// How a session reads and writes a proxied stream.
const COPY_CHUNK: usize = 32 * 1024;

/// How the overlay node is set up.
#[derive(Clone)]
pub struct OverlayConfig {
    /// This node's identity.
    pub identity: NodeIdentity,
    /// Relays to register on, as `host:port` (a WebSocket relay is registered on too).
    pub relays: Vec<String>,
    /// Addresses to publish for direct dialling.
    pub direct: Vec<String>,
    /// An optional direct listener. `None` (the default) means **no inbound port at all**,
    /// which is the point: the overlay works with nothing open.
    pub listen: Option<SocketAddr>,
    /// Where the paired-node state is kept.
    pub state_path: Option<PathBuf>,
    /// Where the audit trail is written.
    pub audit_path: Option<PathBuf>,
    /// The highest protocol version to offer. Lower it to simulate an older peer.
    pub max_version: u8,
    /// Whether to try hole punching to a peer reached over a relay (on by default).
    pub punch: bool,
    /// A UDP gateway the datagrams that are not for the relay go through, wrapped (see
    /// `punch::gateway_wrap`). `None` (the default) sends them straight. For a node behind a
    /// UDP-aware proxy, and for tests that put a NAT emulator in front of a node.
    pub udp_gateway: Option<SocketAddr>,
}

impl OverlayConfig {
    /// A configuration with no relays, no listener and no files: the smallest useful overlay.
    pub fn local(identity: NodeIdentity) -> Self {
        Self {
            identity,
            relays: Vec::new(),
            direct: Vec::new(),
            listen: None,
            state_path: None,
            audit_path: None,
            max_version: protocol::VERSION_CURRENT as u8,
            punch: true,
            udp_gateway: None,
        }
    }
}

/// What a pairing records about the node it paired with, whichever method made the pairing.
pub(crate) struct PairedPeer {
    pub node_id: String,
    /// The name this node knows the peer by: the operator's choice, or the peer's own name.
    pub name: String,
    /// The name the peer gives itself.
    pub own_name: String,
    pub hybrid_public_key: Vec<u8>,
    pub key_fingerprint: [u8; 32],
    pub direct: Vec<String>,
    pub relays: Vec<String>,
    /// The invite nonce a signed invite carried, in hex. Empty for a short code.
    pub pairing: String,
}

/// A hole punch this node started and has not had an answer to yet.
struct PunchAttempt {
    id: u64,
    nonce: [u8; 32],
    hub: SocketAddr,
}

/// The fewest seconds between two punch requests accepted from one peer.
const PUNCH_REQUEST_GAP: Duration = Duration::from_secs(3);
/// How long a punch request waits for its answer.
const PUNCH_ANSWER_WAIT: Duration = Duration::from_secs(10);

/// One peer's session, plus what we know about it.
struct Peer {
    record: NodeRecord,
    session: SessionHandle,
    /// The route the session came up on, for `overlay.connect`'s reply.
    route: RouteKind,
    /// Addresses we may dial this peer on.
    reachable: Vec<String>,
}

/// Whether a stored pairing nonce (hex) is one.
fn nonce_from_hex(text: &str) -> Option<[u8; 16]> {
    hex::decode(text)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
}

fn fingerprint_from_hex(text: &str) -> Option<[u8; 32]> {
    hex::decode(text)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
}

/// Where the local proxies are listening.
#[derive(Clone, Copy, Default)]
pub struct ProxyAddrs {
    pub socks5: Option<SocketAddr>,
    pub http: Option<SocketAddr>,
}

/// The overlay node.
#[derive(Clone)]
pub struct OverlayNode {
    inner: Arc<Inner>,
}

struct Inner {
    config: OverlayConfig,
    peers: parking_lot::Mutex<HashMap<String, Peer>>,
    exposes: parking_lot::RwLock<BTreeMap<String, ExposedService>>,
    connects: parking_lot::Mutex<BTreeMap<SocketAddr, StoredConnect>>,
    groups: parking_lot::RwLock<BTreeMap<String, Vec<String>>>,
    hubs: parking_lot::Mutex<Vec<Arc<RelayHub>>>,
    events: EventLog,
    audit: Audit,
    listener: parking_lot::Mutex<Option<SocketAddr>>,
    proxies: parking_lot::Mutex<ProxyAddrs>,
    /// Per-(service, node) rate windows.
    rates: parking_lot::Mutex<HashMap<(String, String), RateWindow>>,
    /// Endpoints whose local listener is running, with the task serving each.
    forwarders: parking_lot::Mutex<HashMap<SocketAddr, tokio::task::AbortHandle>>,
    /// Addresses this node publishes for direct dialling.
    direct: parking_lot::Mutex<Vec<String>>,
    next_link: std::sync::atomic::AtomicU32,
    /// Nodes currently being dialled, so two callers do not dial at once.
    dialing: parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Streams currently open to each node, which is what group placement spreads by.
    loads: parking_lot::Mutex<HashMap<String, usize>>,
    /// The nodes this node is paired with: it accepted their invite, or they accepted ours.
    /// `*paired` means these, never merely a node that opened a session.
    paired: parking_lot::Mutex<std::collections::HashSet<String>>,
    /// Nonces of the invites we accepted, by the node that issued them: presented in our hello.
    presented: parking_lot::Mutex<HashMap<String, [u8; 16]>>,
    /// The key fingerprint each accepted invite named, by node id. The key a node presents on
    /// first contact must hash to it (see `check_presented_key`). Kept here as well as in the state
    /// file, so the check holds for a node that has no state file.
    fingerprints: parking_lot::Mutex<HashMap<String, [u8; 32]>>,
    /// Invites issued and not used yet: nonce -> expiry.
    invites: parking_lot::Mutex<HashMap<[u8; 16], u64>>,
    /// The mesh DNS forwarder, when it is on.
    mesh_dns: parking_lot::Mutex<Option<Arc<crate::dns::MeshDns>>>,
    /// Its settings as last asked for, kept in the state file so a restart brings it back.
    mesh_dns_config: parking_lot::Mutex<Option<crate::dns::MeshDnsConfig>>,
    /// Hole punches we asked a peer for, by peer.
    punching: parking_lot::Mutex<HashMap<String, PunchAttempt>>,
    /// When a peer last asked us for one, to hold them to a reasonable rate.
    punch_asked: parking_lot::Mutex<HashMap<String, std::time::Instant>>,
    /// The short code this node will accept, if one is open (see `pairing`).
    pending_code: parking_lot::Mutex<Option<crate::pairing::PendingCode>>,
}

/// A simple per-minute rate window.
#[derive(Default)]
struct RateWindow {
    minute: u64,
    streams: u32,
    bytes: u64,
}

impl RateWindow {
    /// Charge one stream and its bytes; returns why it was refused, if it was.
    fn charge(
        &mut self,
        rate: ServiceRate,
        bytes: u64,
        now: u64,
    ) -> std::result::Result<(), String> {
        if self.minute / 60 != now / 60 {
            *self = RateWindow {
                minute: now,
                ..Default::default()
            };
        }
        if self.streams >= rate.streams_per_min {
            return Err(format!(
                "more than {} streams a minute",
                rate.streams_per_min
            ));
        }
        if self.bytes + bytes > rate.bytes_per_min {
            return Err(format!("more than {} bytes a minute", rate.bytes_per_min));
        }
        self.streams += 1;
        self.bytes += bytes;
        Ok(())
    }
}

impl OverlayNode {
    /// Start a node: load its state, register with its relays, and start listening.
    pub async fn start(config: OverlayConfig) -> Result<Arc<Self>> {
        let state = config
            .state_path
            .as_ref()
            .map(|p| StoredState::load(p))
            .unwrap_or_default();
        let node = Arc::new(Self {
            inner: Arc::new(Inner {
                groups: parking_lot::RwLock::new(
                    state
                        .groups
                        .iter()
                        .map(|g| (g.name.clone(), g.members.clone()))
                        .collect(),
                ),
                audit: Audit::new(config.audit_path.clone()),
                events: EventLog::new(),
                listener: parking_lot::Mutex::new(None),
                proxies: parking_lot::Mutex::new(ProxyAddrs::default()),
                rates: parking_lot::Mutex::new(HashMap::new()),
                forwarders: parking_lot::Mutex::new(HashMap::new()),
                next_link: std::sync::atomic::AtomicU32::new(1),
                dialing: parking_lot::Mutex::new(HashMap::new()),
                loads: parking_lot::Mutex::new(HashMap::new()),
                paired: parking_lot::Mutex::new(state.nodes.keys().cloned().collect()),
                presented: parking_lot::Mutex::new(
                    state
                        .nodes
                        .values()
                        .filter_map(|n| Some((n.node_id.clone(), nonce_from_hex(&n.pairing)?)))
                        .collect(),
                ),
                fingerprints: parking_lot::Mutex::new(
                    state
                        .nodes
                        .values()
                        .filter_map(|n| {
                            Some((n.node_id.clone(), fingerprint_from_hex(&n.key_fingerprint)?))
                        })
                        .collect(),
                ),
                invites: parking_lot::Mutex::new(
                    state
                        .invites
                        .iter()
                        .filter(|i| i.expires_at > now_secs())
                        .filter_map(|i| Some((nonce_from_hex(&i.nonce)?, i.expires_at)))
                        .collect(),
                ),
                mesh_dns: parking_lot::Mutex::new(None),
                punching: parking_lot::Mutex::new(HashMap::new()),
                punch_asked: parking_lot::Mutex::new(HashMap::new()),
                pending_code: parking_lot::Mutex::new(None),
                mesh_dns_config: parking_lot::Mutex::new(state.mesh_dns.clone()),
                direct: parking_lot::Mutex::new(config.direct.clone()),
                hubs: parking_lot::Mutex::new(Vec::new()),
                connects: parking_lot::Mutex::new(
                    state
                        .connects
                        .iter()
                        .filter_map(|c| c.local_addr.parse().ok().map(|a| (a, c.clone())))
                        .collect(),
                ),
                exposes: parking_lot::RwLock::new(
                    state
                        .exposes
                        .iter()
                        .filter_map(|e| {
                            Some((
                                e.service.clone(),
                                ExposedService {
                                    name: e.service.clone(),
                                    local_addr: e.local_addr.parse().ok()?,
                                    allow: Acl::parse(&e.allow),
                                    rate: ServiceRate::default(),
                                    description: e.description.clone(),
                                },
                            ))
                        })
                        .collect(),
                ),
                peers: parking_lot::Mutex::new(HashMap::new()),
                config,
            }),
        });
        node.restore_peers(&state);
        node.register_relays().await;
        node.start_inbound_listener().await;
        node.spawn_tick();
        node.save_state();
        if let Some(config) = state.mesh_dns.clone() {
            if let Err(e) = node.set_mesh_dns(Some(config)).await {
                tracing::warn!("[overlay] mesh DNS did not come back: {e}");
            }
        }
        Ok(node)
    }

    /// This node's identity.
    pub fn identity(&self) -> NodeIdentity {
        self.inner.config.identity.clone()
    }

    /// This node's id.
    pub fn node_id(&self) -> String {
        self.inner.config.identity.node_id().to_string()
    }

    /// The live event log.
    pub fn events(&self) -> &EventLog {
        &self.inner.events
    }

    /// The audit trail.
    pub fn audit_trail(&self) -> &Audit {
        &self.inner.audit
    }

    /// The relay hubs this node is registered on.
    pub fn relay_hubs(&self) -> Vec<Arc<RelayHub>> {
        self.inner.hubs.lock().clone()
    }

    pub(crate) fn next_link_id(&self) -> u32 {
        self.inner
            .next_link
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn emit(&self, event: OverlayEvent) {
        self.inner.events.push(event);
    }

    fn audit(&self, mut record: AuditRecord) {
        record.actor = self.node_id();
        self.inner.audit.record(record);
    }

    // ---- reachability -----------------------------------------------------

    /// Register on every configured relay. One that does not answer now is retried in the
    /// background until it does, so a node that booted before its relay still becomes reachable.
    async fn register_relays(&self) {
        for spec in self.inner.config.relays.clone() {
            let Some(addr) = resolve_udp(&spec) else {
                tracing::warn!("[overlay] relay {spec} is not a host:port; skipping");
                continue;
            };
            if self.try_relay(addr).await {
                continue;
            }
            let node = self.clone();
            tokio::spawn(async move {
                let mut wait = Duration::from_secs(1);
                loop {
                    tokio::time::sleep(wait).await;
                    if node.try_relay(addr).await {
                        break;
                    }
                    wait = (wait * 2).min(Duration::from_secs(30));
                }
            });
        }
    }

    async fn try_relay(&self, addr: SocketAddr) -> bool {
        let token = self.inner.config.identity.relay_token();
        match RelayHub::start(
            addr,
            token,
            self.inner.config.identity.clone(),
            self.clone(),
        )
        .await
        {
            Ok(hub) => {
                self.inner.hubs.lock().push(hub);
                self.emit(OverlayEvent::new(
                    "relay.up",
                    self.node_id(),
                    addr.to_string(),
                ));
                true
            }
            Err(e) => {
                tracing::warn!("[overlay] relay {addr}: {e}");
                false
            }
        }
    }

    /// The relays this node is registered on.
    pub fn relays(&self) -> Vec<SocketAddr> {
        self.inner.hubs.lock().iter().map(|h| h.addr).collect()
    }

    async fn start_inbound_listener(&self) {
        let Some(bind) = self.inner.config.listen else {
            return;
        };
        let identity = self.inner.config.identity.clone();
        let node = self.clone();
        match tokio::net::TcpListener::bind(bind).await {
            Ok(listener) => {
                let local = listener.local_addr().unwrap_or(bind);
                *self.inner.listener.lock() = Some(local);
                tracing::info!(
                    "[overlay] direct listener on {local} (every other path is outbound-only)"
                );
                tokio::spawn(async move {
                    loop {
                        let Ok((stream, from)) = listener.accept().await else {
                            break;
                        };
                        let node = node.clone();
                        let identity = identity.clone();
                        tokio::spawn(async move {
                            if let Some(method) = crate::pairing::inbound_method(&stream).await {
                                match method.answer(&node, stream).await {
                                    Ok(peer) => {
                                        tracing::info!(
                                            "[overlay] paired with {} from {from}",
                                            peer.node_id
                                        )
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            "[overlay] pairing from {from} refused: {e}"
                                        )
                                    }
                                }
                                return;
                            }
                            match lanes::accept_tcp(
                                node.next_link_id(),
                                RouteKind::Direct,
                                stream,
                                &identity,
                            )
                            .await
                            {
                                Ok((link, _keys, peer_id, hybrid)) => {
                                    node.adopt_inbound(link, peer_id, hybrid, from).await;
                                }
                                Err(e) => {
                                    tracing::debug!("[overlay] inbound from {from} refused: {e}")
                                }
                            }
                        });
                    }
                });
            }
            Err(e) => tracing::warn!("[overlay] cannot bind the direct listener on {bind}: {e}"),
        }
    }

    /// The direct listener's address, when one is bound.
    pub fn listener_addr(&self) -> Option<SocketAddr> {
        *self.inner.listener.lock()
    }

    /// Take a connection someone made to our direct listener and turn it into a session.
    async fn adopt_inbound(
        &self,
        link: Arc<FramePipe>,
        peer_id: String,
        hybrid: Vec<u8>,
        from: SocketAddr,
    ) {
        if identity::check_node_id(&peer_id).is_err() {
            link.mark_down();
            return;
        }
        if !self.admit_presented_key(&peer_id, &hybrid) {
            link.mark_down();
            return;
        }
        {
            let mut peers = self.inner.peers.lock();
            peers.entry(peer_id.clone()).or_insert_with(|| Peer {
                record: NodeRecord::new(
                    peer_id.clone(),
                    identity::short_name(&peer_id),
                    hybrid.clone(),
                ),
                session: detached_session(&peer_id),
                route: RouteKind::Direct,
                reachable: vec![from.to_string()],
            });
        }
        self.attach(&peer_id, link as Arc<dyn Link>, RouteKind::Direct)
            .await;
        if let Some(p) = self.inner.peers.lock().get_mut(&peer_id) {
            p.record.hybrid_public_key = hybrid;
        }
        self.emit(OverlayEvent::new("peer.up", &peer_id, "direct"));
        self.save_state();
    }

    /// Put a new link to a peer to use: on the live session when there is one (it becomes
    /// another route of that session, so streams can fail over to it), or as a new session.
    /// One session per peer is what keeps both ends agreeing on where a stream lives.
    async fn attach(&self, node_id: &str, link: Arc<dyn Link>, route: RouteKind) -> SessionHandle {
        let live = self
            .inner
            .peers
            .lock()
            .get(node_id)
            .map(|p| p.session.clone())
            .filter(SessionHandle::is_live);
        if let Some(session) = live {
            session.add_link(link).await;
            return session;
        }
        tracing::debug!(
            "[overlay] new session with {node_id} over {}",
            route.as_str()
        );
        let session = self.start_session(node_id, vec![link], route).await;
        self.set_session(node_id, session.clone(), route);
        session
    }

    /// After a session is up on one kind of path, add the others in the background, so the
    /// session has a second route to fail over to and the best one can carry the traffic.
    fn widen(&self, node_id: &str, have: RouteKind) {
        let node = self.clone();
        let node_id = node_id.to_string();
        tokio::spawn(async move {
            if have == RouteKind::Relay || have == RouteKind::HolePunch {
                for addr in node.known_direct(&node_id) {
                    let kind = classify_addr(&addr);
                    if let Ok((link, _, _, hybrid)) = lanes::dial_tcp(
                        node.next_link_id(),
                        kind,
                        &addr,
                        &node.inner.config.identity,
                        Some(&node_id),
                    )
                    .await
                    {
                        // The address must present the key the invite named, as on every other dial.
                        if !node.admit_presented_key(&node_id, &hybrid) {
                            link.mark_down();
                            continue;
                        }
                        node.attach(&node_id, link as Arc<dyn Link>, kind).await;
                        node.emit(OverlayEvent::new(
                            "route.change",
                            &node_id,
                            format!("{} added", kind.as_str()),
                        ));
                        break;
                    }
                }
                // Still on the relay alone: ask the peer to punch a direct path with us.
                if have == RouteKind::Relay {
                    node.start_punch(&node_id).await;
                }
            } else {
                let token = identity::relay_token_for(&node_id);
                for hub in node.relay_hubs() {
                    if let Ok((keys, hybrid)) = hub
                        .handshake(&node_id, token, &node.inner.config.identity)
                        .await
                    {
                        if node.check_presented_key(&node_id, &hybrid).is_err() {
                            continue;
                        }
                        let link: Arc<dyn Link> = hub.link(node.next_link_id(), token, &keys).await;
                        node.attach(&node_id, link, RouteKind::Relay).await;
                        node.remember_identity(&node_id, hybrid);
                        node.emit(OverlayEvent::new("route.change", &node_id, "relay added"));
                        break;
                    }
                }
            }
        });
    }

    /// Make sure there is a session with `node_id`, dialling if there is not.
    pub async fn ensure_session(&self, node_id: &str) -> Result<SessionHandle> {
        if let Some(peer) = self.inner.peers.lock().get(node_id) {
            if peer.session.is_usable() {
                return Ok(peer.session.clone());
            }
        }
        identity::check_node_id(node_id)?;
        // One dial per peer at a time; dials to different peers do not wait for each other.
        let gate = self
            .inner
            .dialing
            .lock()
            .entry(node_id.to_string())
            .or_default()
            .clone();
        let _guard = gate.lock().await;
        if let Some(peer) = self.inner.peers.lock().get(node_id) {
            if peer.session.is_usable() {
                return Ok(peer.session.clone());
            }
        }
        let (handle, route) = self.dial(node_id).await?;
        self.emit(OverlayEvent::new("peer.up", node_id, route.as_str()));
        self.save_state();
        self.widen(node_id, route);
        Ok(handle)
    }

    /// Try every path to a peer, cheapest first, and take the first that answers.
    async fn dial(&self, node_id: &str) -> Result<(SessionHandle, RouteKind)> {
        let peer_token = identity::relay_token_for(node_id);
        let hubs = self.relay_hubs();
        let mut attempts: Vec<String> = Vec::new();

        // 1. Direct addresses the peer published (LAN, tailnet, or any address it chose): the
        //    shortest path when there is one, and a quick no when there is not.
        for addr in self.known_direct(node_id) {
            let kind = classify_addr(&addr);
            match lanes::dial_tcp(
                self.next_link_id(),
                kind,
                &addr,
                &self.inner.config.identity,
                Some(node_id),
            )
            .await
            {
                Ok((link, _keys, _peer, hybrid)) => {
                    if let Err(e) = self.check_presented_key(node_id, &hybrid) {
                        link.mark_down();
                        attempts.push(format!("tcp {addr}: {e}"));
                        continue;
                    }
                    let handle = self.attach(node_id, link as Arc<dyn Link>, kind).await;
                    self.remember_identity(node_id, hybrid);
                    return Ok((handle, kind));
                }
                Err(e) => attempts.push(format!("tcp {addr}: {e}")),
            }
        }

        // 2. Relays: always available when both nodes are registered on one.
        for hub in &hubs {
            match hub
                .handshake(node_id, peer_token, &self.inner.config.identity)
                .await
            {
                Ok((keys, hybrid)) => {
                    // The key is checked before any link exists, so a refused peer gets none.
                    if let Err(e) = self.check_presented_key(node_id, &hybrid) {
                        attempts.push(format!("relay {}: {e}", hub.addr));
                        continue;
                    }
                    let link: Arc<dyn Link> =
                        hub.link(self.next_link_id(), peer_token, &keys).await;
                    let handle = self.attach(node_id, link, RouteKind::Relay).await;
                    self.remember_identity(node_id, hybrid);
                    return Ok((handle, RouteKind::Relay));
                }
                Err(e) => attempts.push(format!("relay {}: {e}", hub.addr)),
            }
        }

        // A hole punch is no way to a first session: it is coordinated over a session that is
        // already up (see `start_punch`), and a peer the relay cannot reach cannot be punched to.
        tracing::debug!("[overlay] no route to {node_id}: {}", attempts.join("; "));
        Err(OverlayError::Unreachable {
            node: node_id.to_string(),
        })
    }

    /// The UDP gateway this node's non-relay datagrams go through, if it has one.
    pub(crate) fn udp_gateway(&self) -> Option<SocketAddr> {
        self.inner.config.udp_gateway
    }

    /// The live session with a paired peer, when hole punching may be tried over it.
    fn punch_session(&self, peer: &str) -> Option<SessionHandle> {
        if !self.inner.config.punch || !self.inner.paired.lock().contains(peer) {
            return None;
        }
        self.inner
            .peers
            .lock()
            .get(peer)
            .map(|p| p.session.clone())
            .filter(SessionHandle::is_live)
    }

    /// Ask a peer we reached over the relay for a direct path: our candidates go to it over the
    /// session, it answers with its own, and both then probe each other (see `punch.rs`). Only
    /// the node that dialled does this; if the exchange fails, the session is unchanged.
    async fn start_punch(&self, peer: &str) {
        let Some(session) = self.punch_session(peer) else {
            return;
        };
        if !session.ready(Duration::from_secs(5)).await
            || session.version() < protocol::VERSION_PUNCH
        {
            return;
        }
        let direct = |r: &protocol::RouteReport| {
            r.active && r.kind != RouteKind::Relay.as_str() && r.kind != RouteKind::WsRelay.as_str()
        };
        if session.routes().iter().any(direct) {
            return;
        }
        let peer_token = identity::relay_token_for(peer);
        let mut found = None;
        for hub in self.relay_hubs() {
            match hub.punch_candidates(peer_token).await {
                Ok(candidates) => {
                    found = Some((hub.addr, candidates));
                    break;
                }
                Err(e) => tracing::debug!("[overlay punch] {}: {e}", hub.addr),
            }
        }
        let Some((hub, candidates)) = found else {
            return;
        };
        let id = rand::random::<u64>();
        let nonce = rand::random::<[u8; 32]>();
        self.inner
            .punching
            .lock()
            .insert(peer.to_string(), PunchAttempt { id, nonce, hub });
        let msg = protocol::PunchMsg {
            id,
            reply: false,
            nonce,
            candidates,
        };
        if session.send_punch(msg).await.is_err() {
            self.inner.punching.lock().remove(peer);
            return;
        }
        // An answer that never comes is forgotten, so the next try starts clean.
        let node = self.clone();
        let peer = peer.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(PUNCH_ANSWER_WAIT).await;
            let mut punching = node.inner.punching.lock();
            if punching.get(&peer).is_some_and(|a| a.id == id) {
                punching.remove(&peer);
            }
        });
    }

    /// The peer's side of a punch exchange arrived over the session.
    async fn on_punch(&self, peer: String, msg: protocol::PunchMsg) {
        let Some(session) = self.punch_session(&peer) else {
            return;
        };
        let named: Vec<SocketAddr> = msg
            .candidates
            .iter()
            .take(punch::MAX_CANDIDATES)
            .filter_map(|c| c.addr.parse().ok())
            .collect();
        let peer_token = identity::relay_token_for(&peer);
        if msg.reply {
            // The answer to a request of ours: only the one we are waiting for.
            let attempt = {
                let mut punching = self.inner.punching.lock();
                match punching.get(&peer) {
                    Some(a) if a.id == msg.id => punching.remove(&peer),
                    _ => None,
                }
            };
            let Some(attempt) = attempt else { return };
            let Some(hub) = self
                .relay_hubs()
                .into_iter()
                .find(|h| h.addr == attempt.hub)
            else {
                return;
            };
            let params = punch::PunchParams {
                id: msg.id,
                initiator: true,
                keys: punch::PunchKeys::derive(msg.id, &attempt.nonce, &msg.nonce),
                candidates: named,
                link_id: self.next_link_id(),
            };
            match hub.punch_begin(params) {
                Ok(running) => self.finish_punch(&peer, running).await,
                Err(e) => self.punch_failed(&peer, &e.to_string()),
            }
            return;
        }
        // A request. Peers are held to a rate, and when both ends asked at once the lower node
        // id's request is the one that goes ahead.
        {
            let mut asked = self.inner.punch_asked.lock();
            let now = std::time::Instant::now();
            if asked
                .get(&peer)
                .is_some_and(|t| now.duration_since(*t) < PUNCH_REQUEST_GAP)
            {
                return;
            }
            asked.insert(peer.clone(), now);
        }
        {
            let mut punching = self.inner.punching.lock();
            if punching.contains_key(&peer) {
                if self.node_id().as_str() < peer.as_str() {
                    return;
                }
                punching.remove(&peer);
            }
        }
        let mut chosen = None;
        for hub in self.relay_hubs() {
            if let Ok(candidates) = hub.punch_candidates(peer_token).await {
                chosen = Some((hub, candidates));
                break;
            }
        }
        let Some((hub, candidates)) = chosen else {
            return;
        };
        let nonce = rand::random::<[u8; 32]>();
        let params = punch::PunchParams {
            id: msg.id,
            initiator: false,
            keys: punch::PunchKeys::derive(msg.id, &msg.nonce, &nonce),
            candidates: named,
            link_id: self.next_link_id(),
        };
        // Registered before the answer goes out, so the first probes of the peer find the attempt.
        let running = match hub.punch_begin(params) {
            Ok(running) => running,
            Err(e) => {
                self.punch_failed(&peer, &e.to_string());
                return;
            }
        };
        let reply = protocol::PunchMsg {
            id: msg.id,
            reply: true,
            nonce,
            candidates,
        };
        if session.send_punch(reply).await.is_err() {
            return;
        }
        self.finish_punch(&peer, running).await;
    }

    fn punch_failed(&self, peer: &str, why: &str) {
        self.emit(OverlayEvent::new(
            "route.change",
            peer,
            format!("holepunch failed: {why}"),
        ));
    }

    /// Probe until the attempt wins or runs out, and on a win add the route to the session.
    async fn finish_punch(&self, peer: &str, running: punch::Running) {
        match running.finish().await {
            Ok(link) => {
                self.attach(peer, link as Arc<dyn Link>, RouteKind::HolePunch)
                    .await;
                self.emit(OverlayEvent::new("route.change", peer, "holepunch up"));
            }
            Err(e) => self.punch_failed(peer, &e.to_string()),
        }
    }

    /// Record a live session for a peer, keeping what we already know about it (the name it
    /// was paired under, its identity, its addresses).
    fn set_session(&self, node_id: &str, session: SessionHandle, route: RouteKind) {
        let mut peers = self.inner.peers.lock();
        match peers.get_mut(node_id) {
            Some(peer) => {
                peer.session = session;
                peer.route = route;
            }
            None => {
                let record = NodeRecord::new(
                    node_id.to_string(),
                    identity::short_name(node_id),
                    Vec::new(),
                );
                peers.insert(
                    node_id.to_string(),
                    Peer {
                        record,
                        session,
                        route,
                        reachable: Vec::new(),
                    },
                );
            }
        }
    }

    /// Take a link a peer dialled us through a relay and turn it into a session.
    pub(crate) async fn adopt_relay_link(
        &self,
        link: Arc<FramePipe>,
        peer_id: String,
        hybrid: Vec<u8>,
        _from: [u8; 32],
        route: RouteKind,
    ) {
        if identity::check_node_id(&peer_id).is_err() {
            link.mark_down();
            return;
        }
        {
            let mut peers = self.inner.peers.lock();
            peers.entry(peer_id.clone()).or_insert_with(|| Peer {
                record: NodeRecord::new(peer_id.clone(), identity::short_name(&peer_id), hybrid),
                session: detached_session(&peer_id),
                route,
                reachable: Vec::new(),
            });
        }
        self.attach(&peer_id, link as Arc<dyn Link>, route).await;
        self.emit(OverlayEvent::new(
            "peer.up",
            &peer_id,
            "dialled us through the relay",
        ));
    }

    /// Addresses we know for a peer.
    fn known_direct(&self, node_id: &str) -> Vec<String> {
        if let Some(peer) = self.inner.peers.lock().get(node_id) {
            if !peer.reachable.is_empty() {
                return peer.reachable.clone();
            }
        }
        self.load_state()
            .nodes
            .get(node_id)
            .map(|n| n.direct.clone())
            .unwrap_or_default()
    }

    /// Check the hybrid key a peer presented on first contact. A node paired by invite must present
    /// the key its invite fingerprinted, and a node we have met before must present the key it
    /// presented then. Anything else is refused before a link is attached.
    fn check_presented_key(&self, node_id: &str, presented: &[u8]) -> Result<()> {
        let fingerprint = self.inner.fingerprints.lock().get(node_id).copied();
        if let Some(fingerprint) = fingerprint {
            if identity::key_fingerprint(presented) != fingerprint {
                return Err(OverlayError::IdentityMismatch {
                    node: node_id.to_string(),
                    reason: "the key it presents is not the one its invite named".into(),
                });
            }
        }
        let known = self
            .inner
            .peers
            .lock()
            .get(node_id)
            .map(|p| p.record.hybrid_public_key.clone())
            .filter(|k| !k.is_empty());
        if known.is_some_and(|k| k.as_slice() != presented) {
            return Err(OverlayError::IdentityMismatch {
                node: node_id.to_string(),
                reason: "this node id now presents a different identity".into(),
            });
        }
        Ok(())
    }

    /// Whether a first contact may be answered or attached. A refusal goes into the event log, so
    /// a node that is turned away can be seen to be.
    pub(crate) fn admit_presented_key(&self, node_id: &str, presented: &[u8]) -> bool {
        match self.check_presented_key(node_id, presented) {
            Ok(()) => true,
            Err(e) => {
                self.emit(OverlayEvent::new("peer.denied", node_id, e.to_string()));
                false
            }
        }
    }

    fn remember_identity(&self, node_id: &str, hybrid: Vec<u8>) {
        {
            let mut peers = self.inner.peers.lock();
            if let Some(peer) = peers.get_mut(node_id) {
                if peer.record.hybrid_public_key.is_empty()
                    || peer.record.hybrid_public_key == hybrid
                {
                    peer.record.hybrid_public_key = hybrid;
                }
            }
        }
        self.save_state();
    }

    async fn start_session(
        &self,
        node_id: &str,
        links: Vec<Arc<dyn Link>>,
        route: RouteKind,
    ) -> SessionHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = session::spawn(
            session::SessionSetup {
                peer_node_id: node_id.to_string(),
                peer_name: identity::short_name(node_id),
                identity: self.inner.config.identity.clone(),
                services: self.services(),
                max_version: self.inner.config.max_version,
                ext: self.hello_ext(node_id),
            },
            links,
            tx,
        )
        .await;
        self.pump_session(node_id.to_string(), rx);
        let _ = route;
        handle
    }

    /// React to what a session reports. Opens are authorised here, which is where the ACL is.
    fn pump_session(&self, _node_id: String, mut rx: mpsc::UnboundedReceiver<SessionEvent>) {
        let node = self.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    SessionEvent::Hello { peer, name, ext } => node.note_hello(&peer, &name, &ext),
                    SessionEvent::Ready {
                        peer,
                        version,
                        services,
                    } => {
                        node.emit(OverlayEvent::new(
                            "peer.up",
                            &peer,
                            format!("protocol v{version}"),
                        ));
                        node.note_services(&peer, &services);
                    }
                    SessionEvent::Refused { peer, reason } => {
                        node.emit(OverlayEvent::new("peer.down", &peer, reason.clone()));
                        let mut record = AuditRecord::new("refused");
                        record.peer = peer;
                        record.error = reason;
                        node.audit(record);
                    }
                    SessionEvent::RouteChanged { peer, kind, up } => {
                        node.emit(OverlayEvent::new(
                            "route.change",
                            &peer,
                            format!("{} {}", kind.as_str(), if up { "up" } else { "down" }),
                        ));
                    }
                    SessionEvent::OpenRequest {
                        peer,
                        stream,
                        service,
                    } => {
                        node.authorize_open(&peer, stream, &service);
                    }
                    SessionEvent::Punch { peer, msg } => {
                        // Off this loop: a punch takes seconds, and the session keeps talking.
                        let node = node.clone();
                        tokio::spawn(async move { node.on_punch(peer, msg).await });
                    }
                    SessionEvent::Down { peer, reason } => {
                        node.emit(OverlayEvent::new("peer.down", &peer, reason));
                    }
                }
            }
        });
    }

    /// What our hello to `peer` carries: the invite nonce, when we paired by accepting its invite.
    fn hello_ext(&self, peer: &str) -> Vec<u8> {
        let pairing = self.inner.presented.lock().get(peer).copied();
        if pairing.is_none() {
            return Vec::new();
        }
        bincode::serialize(&protocol::HelloExt { pairing }).unwrap_or_default()
    }

    /// A peer's hello: if it presents the nonce of an invite we issued, it accepted that invite,
    /// so it is paired with us too. Each invite pairs once.
    fn note_hello(&self, peer: &str, name: &str, ext: &[u8]) {
        let Some(nonce) = protocol::HelloExt::decode(ext).pairing else {
            return;
        };
        if self.inner.paired.lock().contains(peer) {
            return;
        }
        let valid = {
            let mut invites = self.inner.invites.lock();
            match invites.remove(&nonce) {
                Some(expires) => expires > now_secs(),
                None => false,
            }
        };
        if !valid {
            return;
        }
        self.inner.paired.lock().insert(peer.to_string());
        let label = if name.trim().is_empty() {
            identity::short_name(peer)
        } else {
            name.trim().to_string()
        };
        let mut state = self.load_state();
        state
            .nodes
            .entry(peer.to_string())
            .or_insert_with(|| StoredNode {
                node_id: peer.to_string(),
                name: label.clone(),
                hybrid_public_key: Vec::new(),
                key_fingerprint: String::new(),
                relays: Vec::new(),
                direct: Vec::new(),
                paired_at: now_secs(),
                last_name: label.clone(),
                pairing: String::new(),
            });
        self.save_state_with(&state);
        if let Some(p) = self.inner.peers.lock().get_mut(peer) {
            if p.record.name == identity::short_name(peer) {
                p.record.name = label.clone();
            }
        }
        self.save_state();
        self.emit(OverlayEvent::new(
            "peer.paired",
            peer,
            format!("{label} accepted our invite"),
        ));
        let mut record = AuditRecord::new("pair");
        record.peer = peer.to_string();
        record.service = label;
        self.audit(record);
    }

    fn note_services(&self, peer: &str, services: &[ServiceInfo]) {
        let mut state = self.load_state();
        if let Some(node) = state.nodes.get_mut(peer) {
            node.last_name = services
                .first()
                .map(|_| node.last_name.clone())
                .unwrap_or_else(|| node.last_name.clone());
        }
        drop(state);
    }

    /// Check the ACL and the rate limit, then accept the stream or refuse it out loud.
    fn authorize_open(&self, peer: &str, stream: StreamId, service: &str) {
        let session = self.inner.peers.lock().get(peer).map(|p| p.session.clone());
        let peer_owned = peer.to_string();
        let service_owned = service.to_string();
        let refused_service = service_owned.clone();
        let refuse = |node: OverlayNode, reason: &str| {
            let session = session.clone();
            let reason = reason.to_string();
            let service = refused_service.clone();
            let peer = peer_owned.clone();
            let denied = format!("{refused_service}: {reason}");
            let audit_error = reason.clone();
            tokio::spawn(async move {
                if let Some(session) = session {
                    let _ = session.authorize(stream, service, false, reason).await;
                }
            });
            node.emit(OverlayEvent::new("connect.denied", &peer, denied));
            let mut record = AuditRecord::new("denied");
            record.peer = peer;
            record.service = refused_service;
            record.error = audit_error;
            node.audit(record);
        };

        let exposes = self.inner.exposes.read();
        let Some(expose) = exposes.get(service) else {
            drop(exposes);
            refuse(self.clone(), "no such service");
            return;
        };
        let paired = self.inner.paired.lock().contains(peer);
        if !expose.allow.permits(peer, paired) {
            drop(exposes);
            refuse(self.clone(), "not in the access list");
            return;
        }
        let local = expose.local_addr;
        let rate = expose.rate;
        drop(exposes);

        let mut rates = self.inner.rates.lock();
        let window = rates
            .entry((service.to_string(), peer.to_string()))
            .or_default();
        if let Err(reason) = window.charge(rate, 0, now_secs()) {
            drop(rates);
            refuse(self.clone(), &reason);
            return;
        }
        drop(rates);

        let Some(session) = session else {
            refuse(self.clone(), "no session");
            return;
        };
        let node = self.clone();
        let audit_service = service_owned.clone();
        let wire_service = service_owned.clone();
        tokio::spawn(async move {
            let _ = session
                .authorize(stream, wire_service.clone(), true, String::new())
                .await;
            node.emit(OverlayEvent::new(
                "connect.open",
                &peer_owned,
                wire_service.clone(),
            ));
            let mut record = AuditRecord::new("connect");
            record.peer = peer_owned.clone();
            record.service = audit_service;
            record.local_addr = local.to_string();
            node.audit(record);
            node.pipe_local(session.clone(), stream, local).await;
        });
    }

    /// Copy bytes between a local TCP service and an overlay stream, for as long as either lasts.
    async fn pipe_local(&self, session: SessionHandle, stream: StreamId, local: SocketAddr) {
        let service = match tokio::net::TcpStream::connect(local).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("[overlay] the service at {local} did not take the stream: {e}");
                let _ = session.close(stream).await;
                return;
            }
        };
        let (mut sr, mut sw) = tokio::io::split(service);
        let up = session.clone();
        let down = session;
        let upload = tokio::spawn(async move {
            let mut buf = vec![0u8; COPY_CHUNK];
            while let Ok(n) = sr.read(&mut buf).await {
                if n == 0 || up.send(stream, buf[..n].to_vec(), false).await.is_err() {
                    break;
                }
            }
            let _ = up.send(stream, Vec::new(), true).await;
        });
        tokio::spawn(async move {
            while let Ok(Some(bytes)) = down.recv(stream).await {
                if sw.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            // The peer is done sending: pass the end on to the service, and leave the other
            // direction running, since a service may still answer after reading everything.
            let _ = sw.shutdown().await;
            let _ = upload.await;
        });
    }

    // ---- services ---------------------------------------------------------

    /// Publish a local service. Nothing is reachable until this is called, and only the node
    /// identities in `allow` may open it.
    pub fn expose(
        &self,
        service: &str,
        local_addr: SocketAddr,
        allow: Vec<String>,
        description: &str,
    ) -> Result<()> {
        if service.is_empty() || service.contains(['.', ' ', '\t']) {
            return Err(OverlayError::protocol(
                "a service name has no dots or spaces",
            ));
        }
        self.inner.exposes.write().insert(
            service.to_string(),
            ExposedService {
                name: service.to_string(),
                local_addr,
                allow: Acl::parse(&allow),
                rate: ServiceRate::default(),
                description: description.to_string(),
            },
        );
        self.emit(OverlayEvent::new(
            "service.expose",
            self.node_id(),
            format!("{service} on {local_addr}"),
        ));
        self.advertise();
        let mut record = AuditRecord::new("expose");
        record.service = service.to_string();
        record.local_addr = local_addr.to_string();
        self.audit(record);
        self.save_state();
        Ok(())
    }

    /// Withdraw a service.
    pub fn unexpose(&self, service: &str) -> Result<()> {
        self.inner.exposes.write().remove(service);
        self.emit(OverlayEvent::new(
            "service.unexpose",
            self.node_id(),
            service,
        ));
        self.advertise();
        let mut record = AuditRecord::new("unexpose");
        record.service = service.to_string();
        self.audit(record);
        self.save_state();
        Ok(())
    }

    /// Tell every live session what we expose now, so a peer that connected before a service
    /// appeared (or went away) learns about it without reconnecting.
    fn advertise(&self) {
        let services = self.services();
        let sessions: Vec<SessionHandle> = self
            .inner
            .peers
            .lock()
            .values()
            .filter(|p| p.session.is_usable())
            .map(|p| p.session.clone())
            .collect();
        if sessions.is_empty() {
            return;
        }
        tokio::spawn(async move {
            for session in sessions {
                session.advertise(services.clone()).await;
            }
        });
    }

    /// What this node exposes, as plain `ServiceInfo`s for the session hello.
    pub fn services(&self) -> Vec<ServiceInfo> {
        self.inner
            .exposes
            .read()
            .values()
            .map(|e| ServiceInfo {
                name: e.name.clone(),
                description: e.description.clone(),
            })
            .collect()
    }

    /// Every exposed service with its access list, for `overlay.services`.
    pub fn service_details(&self) -> Vec<serde_json::Value> {
        self.inner
            .exposes
            .read()
            .values()
            .map(|e| {
                serde_json::json!({
                    "service": e.name,
                    "local_addr": e.local_addr.to_string(),
                    "allow": e.allow.describe(),
                    "description": e.description,
                    "streams_per_min": e.rate.streams_per_min,
                    "bytes_per_min": e.rate.bytes_per_min,
                })
            })
            .collect()
    }

    // ---- connections ------------------------------------------------------

    /// Connect to a peer's service, or to a group that offers it, and get a stable local
    /// endpoint. Idempotent: the same target and service always yield the same address.
    pub async fn connect(&self, target: &str, service: &str) -> Result<(SocketAddr, RouteKind)> {
        let key = format!("{target}/{service}");
        let existing = self
            .inner
            .connects
            .lock()
            .iter()
            .find(|(_, c)| format!("{}/{}", c.target, c.service) == key)
            .map(|(a, c)| (*a, c.clone()));
        if let Some((addr, entry)) = existing {
            if self.inner.forwarders.lock().contains_key(&addr) {
                // The endpoint is stable: hand back the address the application already has.
                return Ok((
                    addr,
                    RouteKind::parse(&entry.route).unwrap_or(RouteKind::Relay),
                ));
            }
            self.inner.connects.lock().remove(&addr);
            if let Some(task) = self.inner.forwarders.lock().remove(&addr) {
                task.abort();
            }
        }

        let (node_id, route) = self.place(target, service).await?;
        let session = self.ensure_session(&node_id).await?;
        // Prove the service is reachable before publishing an endpoint, so `overlay.connect`
        // never hands back an address that does not work.
        let probe = session.open(service).await?;
        session.close(probe).await;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| OverlayError::Listen {
                addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
                source: e,
            })?;
        // The listener bound here is the one that serves: closing it and binding the address again
        // would leave a moment in which another socket can take the port.
        let local = listener.local_addr().map_err(OverlayError::Io)?;
        self.inner.connects.lock().insert(
            local,
            StoredConnect {
                target: target.to_string(),
                service: service.to_string(),
                local_addr: local.to_string(),
                route: route.as_str().into(),
            },
        );
        let task = self.serve_endpoint(listener, target.to_string(), service.to_string());
        self.inner.forwarders.lock().insert(local, task);
        self.emit(OverlayEvent::new(
            "connect.open",
            &node_id,
            format!("{service} at {local}"),
        ));
        let mut record = AuditRecord::new("connect");
        record.service = service.to_string();
        record.peer = node_id;
        record.local_addr = local.to_string();
        record.route = route.as_str().into();
        self.audit(record);
        self.save_state();
        Ok((local, route))
    }

    /// Close a local endpoint.
    pub fn disconnect(&self, local_addr: SocketAddr) -> Result<()> {
        if let Some(task) = self.inner.forwarders.lock().remove(&local_addr) {
            task.abort();
        }
        // Taken out first: the guard of an `if let` scrutinee lives through its body, and
        // save_state below locks `connects` again.
        let removed = self.inner.connects.lock().remove(&local_addr);
        if let Some(c) = removed {
            self.emit(OverlayEvent::new(
                "connect.close",
                &c.target,
                format!("{} at {local_addr}", c.service),
            ));
            let mut record = AuditRecord::new("disconnect");
            record.service = c.service;
            record.local_addr = local_addr.to_string();
            self.audit(record);
            self.save_state();
        }
        Ok(())
    }

    /// The endpoints currently forwarded.
    pub fn connect_details(&self) -> Vec<serde_json::Value> {
        self.inner
            .connects
            .lock()
            .values()
            .map(|c| {
                serde_json::json!({
                    "local_addr": c.local_addr,
                    "target": c.target,
                    "service": c.service,
                    "route": c.route,
                    "listening": c.local_addr.parse().map(|a| self.inner.forwarders.lock().contains_key(&a)).unwrap_or(false),
                })
            })
            .collect()
    }

    /// A target named the way a person would: a node id, the name a node was paired under, or
    /// a unique prefix of its id (8 characters or more; a whole id is longer than a DNS label,
    /// so `<service>.<node>.td` needs one of the shorter forms). `None`: not a node (a group).
    pub fn resolve_node(&self, target: &str) -> Option<String> {
        if identity::check_node_id(target).is_ok() {
            return Some(target.to_ascii_lowercase());
        }
        let peers = self.inner.peers.lock();
        if let Some(id) = peers
            .values()
            .find(|p| p.record.name.eq_ignore_ascii_case(target))
            .map(|p| p.record.node_id.clone())
        {
            return Some(id);
        }
        let prefix = target.to_ascii_lowercase();
        if prefix.len() >= 8 && prefix.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut hits = peers.keys().filter(|id| id.starts_with(&prefix));
            if let (Some(id), None) = (hits.next(), hits.next()) {
                return Some(id.clone());
            }
        }
        None
    }

    /// Choose which node serves a request. A group is spread by route quality and current load.
    async fn place(&self, target: &str, service: &str) -> Result<(String, RouteKind)> {
        let resolved = self.resolve_node(target);
        let target = resolved.as_deref().unwrap_or(target);
        if identity::check_node_id(target).is_ok() {
            let node_id = target.to_ascii_lowercase();
            // The peer decides whether it offers the service: what it advertised may be a moment
            // old, and its answer to the open is authoritative (`OPEN_ERR no_such_service`).
            self.ensure_session(&node_id).await?;
            let route = self
                .inner
                .peers
                .lock()
                .get(&node_id)
                .map(|p| p.route)
                .unwrap_or(RouteKind::Relay);
            return Ok((node_id, route));
        }
        let members = self
            .inner
            .groups
            .read()
            .get(target)
            .cloned()
            .ok_or_else(|| OverlayError::GroupEmpty {
                group: target.to_string(),
                service: service.to_string(),
            })?;
        let mut best: Option<(String, RouteKind, f64)> = None;
        for member in members {
            let Ok(session) = self.ensure_session(&member).await else {
                continue;
            };
            // A session that has just come up has not heard what the member offers yet.
            session.ready(Duration::from_secs(5)).await;
            if !session.services.read().iter().any(|s| s.name == service) {
                continue;
            }
            // Placement: how good the best route is, plus what we already have running to it.
            let quality = if session.route_quality().is_finite() {
                session.route_quality()
            } else {
                1000.0
            };
            let load = self.inner.loads.lock().get(&member).copied().unwrap_or(0) as f64;
            let score = quality + load * 50.0;
            if best.as_ref().map(|(_, _, b)| score < *b).unwrap_or(true) {
                let route = self
                    .inner
                    .peers
                    .lock()
                    .get(&member)
                    .map(|p| p.route)
                    .unwrap_or(RouteKind::Relay);
                best = Some((member, route, score));
            }
        }
        best.map(|(n, r, _)| (n, r))
            .ok_or(OverlayError::GroupEmpty {
                group: target.to_string(),
                service: service.to_string(),
            })
    }

    /// Accept local connections on a forwarded endpoint and open a stream for each.
    fn serve_endpoint(
        &self,
        listener: tokio::net::TcpListener,
        target: String,
        service: String,
    ) -> tokio::task::AbortHandle {
        let node = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let node = node.clone();
                let target = target.clone();
                let service = service.clone();
                tokio::spawn(async move {
                    let opened = async {
                        let (node_id, _route) = node.place(&target, &service).await?;
                        let session = node.ensure_session(&node_id).await?;
                        let stream = session.open(&service).await?;
                        Ok::<_, OverlayError>((node_id, session, stream))
                    };
                    let (node_id, session, stream) = match opened.await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!("[overlay] endpoint for {service} at {target}: {e}");
                            return;
                        }
                    };
                    node.inner
                        .loads
                        .lock()
                        .entry(node_id.clone())
                        .and_modify(|n| *n += 1)
                        .or_insert(1);
                    let (mut reader, mut writer) = tokio::io::split(socket);
                    let up = session.clone();
                    let upload = tokio::spawn(async move {
                        let mut buf = vec![0u8; COPY_CHUNK];
                        while let Ok(n) = reader.read(&mut buf).await {
                            if n == 0 || up.send(stream, buf[..n].to_vec(), false).await.is_err() {
                                break;
                            }
                        }
                        let _ = up.send(stream, Vec::new(), true).await;
                    });
                    tokio::spawn(async move {
                        while let Ok(Some(bytes)) = session.recv(stream).await {
                            if writer.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        // The service is done sending: end the application's read side, and leave
                        // the other direction running (half-close), as TCP itself would.
                        let _ = writer.shutdown().await;
                        let _ = upload.await;
                        node.inner
                            .loads
                            .lock()
                            .entry(node_id)
                            .and_modify(|n| *n = n.saturating_sub(1));
                    });
                });
            }
        })
        .abort_handle()
    }

    // ---- mesh DNS ---------------------------------------------------------

    /// Turn the mesh DNS forwarder on with these settings (replacing a running one), or off
    /// with `None`. The settings are kept, so it comes back after a restart.
    pub async fn set_mesh_dns(
        &self,
        config: Option<crate::dns::MeshDnsConfig>,
    ) -> Result<serde_json::Value> {
        // Stop the old one first, and wait until it has let go of its port: the new one usually
        // wants the same port, and so does a caller that turns the resolver off and rebinds it.
        let old = self.inner.mesh_dns.lock().take();
        if let Some(old) = old {
            old.stop().await;
        }
        let Some(config) = config else {
            *self.inner.mesh_dns_config.lock() = None;
            self.emit(OverlayEvent::new("dns.off", self.node_id(), ""));
            self.save_state();
            return Ok(self.mesh_dns_status());
        };
        let node = Arc::new(self.clone());
        let mut tries = 0;
        let dns = loop {
            match crate::dns::MeshDns::start(node.clone(), config.clone()).await {
                Ok(dns) => break dns,
                // A query still in flight on the old forwarder can hold its socket for a moment.
                Err(OverlayError::Listen { .. }) if tries < 20 => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => return Err(e),
            }
        };
        let listen = dns.listen_addr();
        *self.inner.mesh_dns.lock() = Some(dns);
        *self.inner.mesh_dns_config.lock() = Some(config.clone());
        self.emit(OverlayEvent::new(
            "dns.on",
            self.node_id(),
            format!("{listen} via {}", config.upstreams.join(", ")),
        ));
        let mut record = AuditRecord::new("dns");
        record.local_addr = listen.to_string();
        record.service = config.upstreams.join(",");
        self.audit(record);
        self.save_state();
        Ok(self.mesh_dns_status())
    }

    /// The forwarder's state and counters, and whether this node shares a resolver itself.
    pub fn mesh_dns_status(&self) -> serde_json::Value {
        let mut status = match self.inner.mesh_dns.lock().as_ref() {
            Some(dns) => dns.status(),
            None => serde_json::json!({
                "enabled": false,
                "configured": self.inner.mesh_dns_config.lock().clone(),
            }),
        };
        let serving = self.inner.exposes.read().get(crate::dns::SERVICE).map(|e| {
            serde_json::json!({"local_addr": e.local_addr.to_string(), "allow": e.allow.describe()})
        });
        status["serving"] = serving.unwrap_or(serde_json::Value::Null);
        status
    }

    // ---- groups -----------------------------------------------------------

    /// Define a service group: any node in it may serve the service.
    pub fn set_group(&self, name: &str, members: Vec<String>) {
        self.inner.groups.write().insert(name.to_string(), members);
        self.save_state();
    }

    /// The groups and their members.
    pub fn groups(&self) -> Vec<StoredGroup> {
        self.inner
            .groups
            .read()
            .iter()
            .map(|(name, members)| StoredGroup {
                name: name.clone(),
                members: members.clone(),
            })
            .collect()
    }

    // ---- peering ----------------------------------------------------------

    /// Create a pairing invite: identity plus how to reach us, signed so it cannot be edited.
    pub fn invite_create(&self, ttl_s: u64) -> String {
        let reach = identity::InviteReach {
            relays: self.relays().iter().map(|a| a.to_string()).collect(),
            direct: self.published_direct(),
        };
        let (invite, nonce, expires_at) =
            identity::make_invite_with_nonce(&self.identity(), reach.relays, reach.direct, ttl_s);
        {
            let mut invites = self.inner.invites.lock();
            let now = now_secs();
            invites.retain(|_, exp| *exp > now);
            invites.insert(nonce, expires_at);
        }
        self.save_state();
        invite
    }

    /// Verify an invite and pair with it. The invite carries the node's key fingerprint, not its
    /// key: the first contact must present a key that matches (see `check_presented_key`). A node
    /// we already hold a key for must keep it, so an invite that fingerprints another key is refused.
    pub fn invite_accept(&self, invite: &str, name: Option<String>) -> Result<NodeRecord> {
        let verified = identity::accept_invite(invite)?;
        let state = self.load_state();
        let known_key = state
            .nodes
            .get(&verified.node_id)
            .map(|n| n.hybrid_public_key.clone())
            .filter(|k| !k.is_empty());
        if let Some(key) = &known_key {
            if identity::key_fingerprint(key) != verified.key_fingerprint {
                return Err(OverlayError::IdentityMismatch {
                    node: verified.node_id,
                    reason: "this node id now presents a different identity".into(),
                });
            }
        }
        let record = NodeRecord::new(
            verified.node_id.clone(),
            verified.name.clone(),
            known_key.unwrap_or_default(),
        );
        let reach = identity::invite_reach(invite);
        let label = name
            .unwrap_or_else(|| record.name.clone())
            .trim()
            .to_string();
        let nonce = identity::invite_nonce(invite);
        // The name we know this node by is the one the operator gave us, not the one it calls
        // itself: `overlay.connect` and the proxies both key off this.
        let record = self.pair_with(PairedPeer {
            node_id: record.node_id.clone(),
            name: label,
            own_name: record.name.clone(),
            hybrid_public_key: record.hybrid_public_key.clone(),
            key_fingerprint: verified.key_fingerprint,
            direct: reach.direct,
            relays: reach.relays,
            pairing: nonce.map(hex::encode).unwrap_or_default(),
        });
        if let Some(nonce) = nonce {
            self.inner
                .presented
                .lock()
                .insert(record.node_id.clone(), nonce);
        }
        Ok(record)
    }

    /// Record a node we have paired with, however the pairing was made. The key it presents is
    /// kept, so a later first contact must present the same one.
    pub(crate) fn pair_with(&self, peer: PairedPeer) -> NodeRecord {
        let record = NodeRecord::new(
            peer.node_id.clone(),
            peer.own_name.clone(),
            peer.hybrid_public_key.clone(),
        );
        let mut state = self.load_state();
        state.nodes.insert(
            peer.node_id.clone(),
            StoredNode {
                node_id: peer.node_id.clone(),
                name: peer.name.clone(),
                hybrid_public_key: peer.hybrid_public_key.clone(),
                key_fingerprint: hex::encode(peer.key_fingerprint),
                relays: peer.relays.clone(),
                direct: peer.direct.clone(),
                paired_at: record.paired_at,
                last_name: peer.own_name.clone(),
                pairing: peer.pairing.clone(),
            },
        );
        self.save_state_with(&state);
        self.inner.paired.lock().insert(peer.node_id.clone());
        self.inner
            .fingerprints
            .lock()
            .insert(peer.node_id.clone(), peer.key_fingerprint);
        self.inner.peers.lock().insert(
            peer.node_id.clone(),
            Peer {
                record: NodeRecord {
                    name: peer.name.clone(),
                    ..record.clone()
                },
                session: detached_session(&peer.node_id),
                route: RouteKind::Relay,
                reachable: peer.direct.clone(),
            },
        );
        self.emit(OverlayEvent::new(
            "peer.paired",
            &peer.node_id,
            peer.name.clone(),
        ));
        let mut audit = AuditRecord::new("pair");
        audit.peer = peer.node_id.clone();
        audit.service = peer.name.clone();
        self.audit(audit);
        NodeRecord {
            name: peer.name,
            ..record
        }
    }

    /// The short code this node will accept, if one is open.
    pub(crate) fn pending_code(&self) -> &parking_lot::Mutex<Option<crate::pairing::PendingCode>> {
        &self.inner.pending_code
    }

    /// Whether this node is paired with `node_id`.
    #[cfg(test)]
    pub(crate) fn is_paired(&self, node_id: &str) -> bool {
        self.inner.paired.lock().contains(node_id)
    }

    /// The pairing methods this build offers, by name.
    pub fn pairing_methods(&self) -> Vec<&'static str> {
        crate::pairing::methods().iter().map(|m| m.id()).collect()
    }

    /// Make an offer with the named pairing method, valid for `ttl_s` seconds.
    pub fn pair_offer(&self, method: &str, ttl_s: u64) -> Result<String> {
        let method = crate::pairing::by_id(method).ok_or_else(|| {
            OverlayError::protocol(format!("there is no pairing method called {method}"))
        })?;
        method.offer(self, ttl_s)
    }

    /// Pair with an offer, whichever pairing method made it.
    pub async fn pair_accept(&self, offer: &str, name: Option<String>) -> Result<NodeRecord> {
        let method = crate::pairing::by_offer(offer).ok_or_else(|| {
            OverlayError::protocol("this is not an offer from a pairing method this build knows")
        })?;
        method.accept(self, offer, name).await
    }

    /// Publish addresses a peer may try to dial us on directly.
    ///
    /// They travel in this node's invites, so a peer that pairs with us learns them; a node
    /// whose address changes republishes by asking for a fresh invite.
    pub fn set_direct(&self, addr: String) {
        self.inner.direct.lock().push(addr);
    }

    /// The addresses this node publishes for direct dialling: the configured ones, and its
    /// own listener when it has one.
    pub fn published_direct(&self) -> Vec<String> {
        let mut out = self.inner.direct.lock().clone();
        if let Some(listener) = self.listener_addr() {
            let addr = if listener.ip().is_unspecified() {
                SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), listener.port()).to_string()
            } else {
                listener.to_string()
            };
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
        out
    }

    /// Restore peer records from stored state.
    fn restore_peers(&self, state: &StoredState) {
        let mut peers = self.inner.peers.lock();
        for node in state.nodes.values() {
            peers.insert(
                node.node_id.clone(),
                Peer {
                    record: NodeRecord {
                        node_id: node.node_id.clone(),
                        name: node.name.clone(),
                        services: Vec::new(),
                        hybrid_public_key: node.hybrid_public_key.clone(),
                        paired_at: node.paired_at,
                        last_seen: 0,
                    },
                    session: detached_session(&node.node_id),
                    route: RouteKind::Relay,
                    reachable: node.direct.clone(),
                },
            );
        }
    }

    fn load_state(&self) -> StoredState {
        self.inner
            .config
            .state_path
            .as_ref()
            .map(|p| StoredState::load(p))
            .unwrap_or_default()
    }

    fn save_state(&self) {
        let mut state = self.load_state();
        {
            let exposes = self.inner.exposes.read();
            state.exposes = exposes
                .values()
                .map(|e| StoredExpose {
                    service: e.name.clone(),
                    local_addr: e.local_addr.to_string(),
                    allow: e.allow.describe(),
                    description: e.description.clone(),
                })
                .collect();
            state.groups = self.groups();
            state.connects = self.inner.connects.lock().values().cloned().collect();
            state.mesh_dns = self.inner.mesh_dns_config.lock().clone();
            state.invites = self
                .inner
                .invites
                .lock()
                .iter()
                .map(|(nonce, expires_at)| crate::state::StoredInvite {
                    nonce: hex::encode(nonce),
                    expires_at: *expires_at,
                })
                .collect();
        }
        self.save_state_with(&state);
    }

    fn save_state_with(&self, state: &StoredState) {
        if let Some(path) = self.inner.config.state_path.clone() {
            if let Err(e) = state.save(&path) {
                tracing::warn!("[overlay] could not write {}: {e}", path.display());
            }
        }
    }

    // ---- proxies ----------------------------------------------------------

    /// Start the local SOCKS5 and HTTP-CONNECT proxies.
    pub async fn start_proxies(&self) -> Result<(SocketAddr, SocketAddr)> {
        let socks = crate::proxy::serve_socks(self.clone()).await?;
        let http = crate::proxy::serve_http(self.clone()).await?;
        *self.inner.proxies.lock() = ProxyAddrs {
            socks5: Some(socks),
            http: Some(http),
        };
        self.emit(OverlayEvent::new(
            "proxy.start",
            self.node_id(),
            format!("{socks} {http}"),
        ));
        Ok((socks, http))
    }

    /// Where the proxies are listening, if they are running.
    pub fn proxy_status(&self) -> ProxyAddrs {
        *self.inner.proxies.lock()
    }

    // ---- reporting --------------------------------------------------------

    /// The node's own view of itself, for `overlay.status`.
    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "node_id": self.node_id(),
            "name": self.identity().name(),
            "version": crate::VERSION,
            "protocol_versions": {
                "min": protocol::VERSION_MIN,
                "max": self.inner.config.max_version,
                "current": protocol::VERSION_CURRENT,
            },
            "lanes": self.lanes(),
            "relays": self
                .relays()
                .iter()
                .map(|a| serde_json::json!({
                    "addr": a.to_string(),
                    "registered": true,
                    "token": hex::encode(identity::relay_token_for(&self.node_id())),
                }))
                .collect::<Vec<_>>(),
            "nat": self.nat(),
            "listener": self.listener_addr().map(|a| a.to_string()),
            "proxies": {
                "socks5_addr": self.proxy_status().socks5.map(|a| a.to_string()),
                "http_proxy_addr": self.proxy_status().http.map(|a| a.to_string()),
            },
            "exposes": self.inner.exposes.read().keys().cloned().collect::<Vec<_>>(),
            "connects": self.connect_details(),
        })
    }

    /// What we know about our own reachability.
    fn nat(&self) -> serde_json::Value {
        if self.relays().is_empty() {
            return serde_json::json!({"type": "unknown", "mapped": serde_json::Value::Null});
        }
        match self.listener_addr() {
            // We publish a direct listener, so a peer may reach us without a relay.
            Some(a) => serde_json::json!({"type": "reachable", "mapped": a.to_string()}),
            // No listener: every inbound path is an outbound one, through a relay or a punch.
            None => serde_json::json!({
                "type": "outbound",
                "mapped": self.relays().first().map(|a| a.to_string()),
                "note": "no inbound port is needed: every path is dialled outbound",
            }),
        }
    }

    /// Every session on this node, for `overlay.status.lanes`.
    fn lanes(&self) -> Vec<serde_json::Value> {
        let peers = self.inner.peers.lock();
        peers
            .values()
            .map(|peer| {
                serde_json::json!({
                    "peer": peer.record.node_id,
                    "name": peer.record.name,
                    "state": if peer.session.is_usable() { "up" } else { "down" },
                    "routes": peer.session.routes(),
                })
            })
            .collect()
    }

    /// Every peer, with its routes and services, for `overlay.peers`.
    pub fn peer_list(&self) -> Vec<serde_json::Value> {
        let peers = self.inner.peers.lock();
        peers
            .values()
            .map(|peer| {
                let live = peer.session.is_usable();
                serde_json::json!({
                    "node_id": peer.record.node_id,
                    "name": peer.record.name,
                    "state": if live { "up" } else { "degraded" },
                    "routes": peer.session.routes(),
                    "services": peer.session.services.read().clone(),
                    "protocol_version": peer.session.version(),
                })
            })
            .collect()
    }

    fn spawn_tick(&self) {
        let node = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(NODE_TICK);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                node.save_state();
            }
        });
    }
}

fn classify_addr(addr: &str) -> RouteKind {
    let ip = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) if v4.is_loopback() || v4.is_private() => RouteKind::Lan,
        Ok(std::net::IpAddr::V4(v4))
            if v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]) =>
        {
            RouteKind::Tailscale
        }
        _ => RouteKind::Direct,
    }
}

fn resolve_udp(spec: &str) -> Option<SocketAddr> {
    let bare = spec
        .strip_prefix("udp://")
        .or_else(|| spec.strip_prefix("relay://"))
        .unwrap_or(spec);
    bare.parse().ok()
}

/// A handle that is never live, used for peers we know but have not dialled yet.
fn detached_session(node_id: &str) -> SessionHandle {
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    SessionHandle::detached(node_id.to_string(), tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_is_usable_while_a_route_is_up_and_not_once_every_route_is_down() {
        let route = |active| crate::protocol::RouteReport {
            kind: "tcp".into(),
            rtt_ms: 1.0,
            loss: 0.0,
            mbps: 1.0,
            active,
            cwnd: 0,
            in_flight: 0,
            srtt_ms: 0.0,
            rto_ms: 0.0,
            sent_bytes: 0,
            retx_bytes: 0,
        };
        assert!(crate::session::routes_usable(&[]), "nothing measured yet");
        assert!(
            crate::session::routes_usable(&[route(false), route(true)]),
            "one route up"
        );
        assert!(
            !crate::session::routes_usable(&[route(false), route(false)]),
            "every route down"
        );
    }

    #[test]
    fn an_address_is_classified_by_where_it_points() {
        assert_eq!(classify_addr("127.0.0.1:5000"), RouteKind::Lan);
        assert_eq!(classify_addr("192.168.1.10:5000"), RouteKind::Lan);
        assert_eq!(classify_addr("100.64.0.10:5000"), RouteKind::Tailscale);
        assert_eq!(classify_addr("203.0.113.9:5000"), RouteKind::Direct);
    }

    #[test]
    fn a_rate_window_refuses_past_its_budget_and_resets_each_minute() {
        let rate = ServiceRate {
            streams_per_min: 2,
            bytes_per_min: 100,
        };
        let mut w = RateWindow::default();
        assert!(w.charge(rate, 10, 1_000).is_ok());
        assert!(w.charge(rate, 10, 1_001).is_ok());
        assert!(
            w.charge(rate, 10, 1_002).is_err(),
            "the third stream in the minute is refused"
        );
        assert!(
            w.charge(rate, 1_000_000, 1_003).is_err(),
            "and so is a byte budget that is past"
        );
        assert!(
            w.charge(rate, 10, 1_060).is_ok(),
            "the next minute starts a fresh window"
        );
    }
}
