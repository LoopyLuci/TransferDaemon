//! RelayHub — the daemon's inbound relay endpoint.
//!
//! Owns the UDP socket registered with the relay under our `self_token`, runs the
//! X25519 responder side of relay session establishment, decrypts inbound chunks,
//! and applies `WireMsg`s to daemon state. Also lets the daemon initiate sessions
//! to peers (`initiate`) and derive the per-direction keys for outbound lanes.
//!
//! Session model: one shared secret per peer, established by the first handshake
//! (either we initiate or a peer initiates to us). We send with role-0 keys when
//! we initiated, role-1 keys when we responded — matching the TCP lane scheme.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex as PkMutex;
use tokio::sync::{Mutex, oneshot};

use transferd_core::lanes::relay_client::{PREFIX_CHUNK, PREFIX_HANDSHAKE, RelayClient};
use transferd_core::lanes::relay_ws_client::RelayForward;
use transferd_core::transport::Chunk;
use transferd_core::types::{Gsn, SessionId};
use transferd_crypto::auth_handshake::{
    AuthInitiatorHello, AuthResponderHello, CIPHERSUITE_HYBRID_X25519_MLKEM768, PROTOCOL_VERSION,
};
use transferd_crypto::handshake::{Initiator, Responder};
use transferd_crypto::identity::HybridSigningKey;
use transferd_crypto::{DmiDecryptor, DmiEncryptor};

use crate::peer_manager::directional_keys;
use crate::state::DaemonState;
use crate::wire::WireMsg;

/// Derive a stable relay self-token from the identity public key hex.
pub fn relay_token_for(public_key_hex: &str) -> [u8; 32] {
    blake3::derive_key("transferd-relay-token-v1", public_key_hex.as_bytes())
}

/// A session with one peer: the KDF'd shared secret and which role we played.
#[derive(Clone)]
struct RelaySession {
    shared: [u8; 32],
    /// True when we initiated the handshake (we send with role-0 keys).
    we_initiated: bool,
    /// Per-message ratchet for this peer. `we_initiated` decides the role.
    ratchet: std::sync::Arc<parking_lot::Mutex<transferd_crypto::ratchet::DoubleRatchet>>,
    /// The peer's verified 2624-byte hybrid public key.
    peer_hybrid_pk: Vec<u8>,
}

/// Relay transport: UDP (`relayd`) or WebSocket (`relayd-ws` / Cloudflare).
/// `Ws(true)` = `wss://` (TLS), `Ws(false)` = `ws://` (plaintext).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayKind {
    Udp,
    Ws(bool),
}

/// One configured relay: its kind, address, and a forwarder the hub uses to
/// route handshakes + acks through it.
pub struct HubRelay {
    pub kind: RelayKind,
    pub addr: std::net::SocketAddr,
    /// The DNS authority (`host:port`, hostname preserved) for WS relays —
    /// used as the TLS connect target (SNI) and the published endpoint. `None`
    /// for UDP relays.
    pub authority: Option<String>,
    pub forward: Arc<dyn RelayForward + Send + Sync>,
    /// The concrete WS client (Some for WS relays) — lanes need it to send.
    pub ws_client: Option<Arc<transferd_core::lanes::relay_ws_client::RelayWsClient>>,
}

pub struct RelayHub {
    /// One entry per configured relay. The same `self_token` is registered on
    /// every relay (the token is derived from the identity, not the relay), so
    /// a session is reachable via ANY of them — UDP or WebSocket.
    relays: Vec<HubRelay>,
    self_token: [u8; 32],
    /// Sessions keyed by `(peer_token, we_initiated)`. A peer can hold BOTH
    /// roles simultaneously (it initiated to us AND we initiated to it), so a
    /// single per-token slot would let the second handshake overwrite the
    /// first. Chunks are matched to the role whose recv-key verifies.
    sessions: Mutex<HashMap<([u8; 32], bool), RelaySession>>,
    /// Pending initiator handshakes: peer_token → responder's auth flight.
    pending: Mutex<HashMap<[u8; 32], oneshot::Sender<AuthResponderHello>>>,
}

/// Whether the relay inbound endpoint is enabled via `TRANSFERD_RELAY_ADDR`
/// (comma-separated list of relays).
pub fn relay_enabled() -> bool {
    std::env::var("TRANSFERD_RELAY_ADDR")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

/// Parse a `host:port` into a `SocketAddr`, resolving DNS names (e.g. a
/// Cloudflare Worker's `*.workers.dev` host). Prefers IPv4.
pub(crate) fn resolve_addr(s: &str) -> Option<std::net::SocketAddr> {
    if let Ok(a) = s.parse() {
        return Some(a);
    }
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .ok()?
        .find(|a| a.is_ipv4())
}

/// Parse the comma-separated `TRANSFERD_RELAY_ADDR` into `(addr, kind)` pairs.
/// Plain `host:port` entries are UDP relays; `ws://host:port` are WebSocket,
/// `wss://host:port` are WebSocket over TLS (Cloudflare Worker, relayd-ws
/// behind an HTTPS reverse proxy). DNS hostnames are resolved eagerly; the
/// original authority (hostname:port) is returned alongside for TLS connect +
/// publishing.
pub fn configured_relays() -> Vec<((std::net::SocketAddr, RelayKind), Option<String>)> {
    std::env::var("TRANSFERD_RELAY_ADDR")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            let (rest, tls) = if let Some(rest) = s.strip_prefix("wss://") {
                (rest, Some(true))
            } else if let Some(rest) = s.strip_prefix("ws://") {
                (rest, Some(false))
            } else {
                (s, None)
            };
            let addr = resolve_addr(rest)?;
            let kind = match tls {
                Some(t) => RelayKind::Ws(t),
                None => RelayKind::Udp,
            };
            Some(((addr, kind), tls.map(|_| rest.to_string())))
        })
        .collect()
}

/// Start (or restart) the inbound relay listeners using the current identity's
/// public key to derive a stable token. No-op when no relay is configured or
/// the daemon has no identity yet.
pub async fn spawn_inbound_relay_listener(state: Arc<PkMutex<DaemonState>>) {
    let configured = configured_relays();
    if configured.is_empty() {
        tracing::debug!(
            "[relay] no relays configured (TRANSFERD_RELAY_ADDR unset/unresolvable); inbound relay off"
        );
        return;
    }
    let relay_specs: Vec<(std::net::SocketAddr, RelayKind)> = configured.iter().map(|(s, _)| *s).collect();
    let authorities: Vec<Option<String>> = configured.into_iter().map(|(_, a)| a).collect();

    let token = {
        let s = state.lock();
        match &s.identity {
            Some(id) => relay_token_for(&id.public_key),
            None => {
                tracing::debug!("[relay] no identity yet; deferred");
                return;
            }
        }
    };

    // Skip if a hub is already running on the same relays and token.
    {
        let s = state.lock();
        if let Some(h) = &s.relay_hub {
            if h.relay_specs() == relay_specs && h.self_token() == token {
                return;
            }
        }
    }

    match RelayHub::start(state.clone(), relay_specs.clone(), authorities, token).await {
        Ok(hub) => {
            state.lock().relay_hub = Some(hub);
            tracing::info!("[relay] inbound listeners registered on {} relays", relay_specs.len());
            // If a DHT node is available, publish our endpoint so contacts can
            // discover us by public key.
            crate::peer_discovery::publish_endpoint_if_ready(&state).await;
        }
        Err(e) => {
            tracing::error!("[relay] failed to start inbound listeners: {e}");
        }
    }
}

impl RelayHub {

/// Connect every relay (UDP or WS), register `self_token`, and spawn a receive
/// loop per relay. `state` is used to apply inbound messages.
    pub async fn start(
        state: Arc<PkMutex<DaemonState>>,
        relay_specs: Vec<(std::net::SocketAddr, RelayKind)>,
        authorities: Vec<Option<String>>,
        self_token: [u8; 32],
    ) -> Result<Arc<Self>, String> {
        let mut relays: Vec<HubRelay> = Vec::with_capacity(relay_specs.len());
        enum Loop {
            Udp(Arc<RelayClient>),
            Ws(tokio::sync::mpsc::Receiver<Vec<u8>>, Arc<dyn RelayForward + Send + Sync>),
        }
        let mut loops: Vec<Loop> = Vec::with_capacity(relay_specs.len());
        for ((addr, kind), authority) in relay_specs.into_iter().zip(authorities) {
            match kind {
                RelayKind::Udp => {
                    let client = Arc::new(
                        RelayClient::bind(addr).await.map_err(|e| e.to_string())?,
                    );
                    client.register(self_token).await.map_err(|e| e.to_string())?;
                    client.spawn_keepalive_loop(self_token);
                    relays.push(HubRelay { kind, addr, authority: None, forward: client.clone(), ws_client: None });
                    loops.push(Loop::Udp(client));
                }
                RelayKind::Ws(tls) => {
                    let scheme = if tls { "wss" } else { "ws" };
                    // TLS connects by the ORIGINAL authority (hostname) so SNI
                    // matches the relay's certificate; fall back to the addr.
                    let connect_to = authority.clone().unwrap_or_else(|| addr.to_string());
                    let (client, rx) =
                        transferd_core::lanes::relay_ws_client::RelayWsClient::connect(
                            &format!("{scheme}://{connect_to}"),
                            self_token,
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    let client = Arc::new(client);
                    client.spawn_keepalive_loop(self_token);
                    relays.push(HubRelay { kind, addr, authority, forward: client.clone(), ws_client: Some(client.clone()) });
                    loops.push(Loop::Ws(rx, client));
                }
            }
        }

        let hub = Arc::new(Self {
            relays,
            self_token,
            sessions: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        });

        for l in loops {
            match l {
                Loop::Udp(client) => {
                    let hub2 = hub.clone();
                    let state2 = state.clone();
                    tokio::spawn(async move {
                        hub2.recv_loop_udp(client, state2).await;
                    });
                }
                Loop::Ws(rx, forward) => {
                    let hub2 = hub.clone();
                    let state2 = state.clone();
                    tokio::spawn(async move {
                        hub2.recv_loop_ws(rx, forward, state2).await;
                    });
                }
            }
        }

        tracing::info!("[relay] inbound listeners registered token on {} relays", hub.relays.len());
        Ok(hub)
    }

    pub fn self_token(&self) -> [u8; 32] {
        self.self_token
    }

    /// All relays this hub is registered on, as `(socket_addr, kind)`.
    pub fn relay_specs(&self) -> Vec<(std::net::SocketAddr, RelayKind)> {
        self.relays.iter().map(|r| (r.addr, r.kind)).collect()
    }

    /// Relay endpoint strings for DHT publishing — `ws://host:port` /
    /// `wss://host:port` for WS relays (hostname preserved for TLS), `host:port`
    /// for UDP.
    pub fn relay_endpoint_strs(&self) -> Vec<String> {
        self.relays
            .iter()
            .map(|r| match r.kind {
                RelayKind::Udp => r.addr.to_string(),
                RelayKind::Ws(tls) => {
                    let scheme = if tls { "wss" } else { "ws" };
                    let authority = r.authority.clone().unwrap_or_else(|| r.addr.to_string());
                    format!("{scheme}://{authority}")
                }
            })
            .collect()
    }

    /// Whether the hub is registered on `addr`.
    pub fn has_relay(&self, addr: std::net::SocketAddr) -> bool {
        self.relays.iter().any(|r| r.addr == addr)
    }

    /// Whether the hub is registered on a relay with this AUTHORITY
    /// (`host:port`, hostname preserved — DNS round-robin may resolve the same
    /// hostname to different IPs, so the hostname is the stable identity).
    pub fn has_relay_authority(&self, authority: &str) -> bool {
        self.relays.iter().any(|r| {
            r.authority.as_deref().map(|a| a == authority).unwrap_or(false)
                || r.addr.to_string() == authority
        })
    }

    /// The kind of the relay at `addr`, if registered.
    pub fn relay_kind(&self, addr: std::net::SocketAddr) -> Option<RelayKind> {
        self.relays.iter().find(|r| r.addr == addr).map(|r| r.kind)
    }

    fn client_for(&self, addr: std::net::SocketAddr) -> Option<&Arc<dyn RelayForward + Send + Sync>> {
        self.relays.iter().find(|r| r.addr == addr).map(|r| &r.forward)
    }

    /// The concrete WebSocket relay client for `addr` (None for UDP relays).
    pub fn ws_client_for(
        &self,
        addr: std::net::SocketAddr,
    ) -> Option<Arc<transferd_core::lanes::relay_ws_client::RelayWsClient>> {
        self.relays.iter().find(|r| r.addr == addr).and_then(|r| r.ws_client.clone())
    }

    /// Initiate a relay session with `peer_token`, performing the authenticated
    /// hybrid handshake over the relay if not already established. Idempotent.
    /// Returns the peer's verified 2624-byte hybrid public key.
    ///
    /// `via` selects which relay to route the handshake through; only relays
    /// the hub is registered on are valid.
    pub async fn initiate(
        &self,
        peer_token: [u8; 32],
        identity: &HybridSigningKey,
        via: std::net::SocketAddr,
    ) -> Result<Vec<u8>, String> {
        if let Some(s) = self.sessions.lock().await.get(&(peer_token, true)).cloned() {
            return Ok(s.peer_hybrid_pk);
        }
        let client = self
            .client_for(via)
            .cloned()
            .ok_or_else(|| format!("relay not registered on {via}"))?;

        let init = Initiator::new();
        let flight = AuthInitiatorHello::build(
            &init,
            PROTOCOL_VERSION,
            CIPHERSUITE_HYBRID_X25519_MLKEM768,
            identity,
        );

        // Register the pending handshake BEFORE sending, so a fast reply
        // (loopback / same-host relays) can't race past it.
        let (tx, rx) = oneshot::channel::<AuthResponderHello>();
        self.pending.lock().await.insert(peer_token, tx);

        let mut payload = Vec::with_capacity(1 + 32 + flight.to_wire().len());
        payload.push(PREFIX_HANDSHAKE);
        payload.extend_from_slice(&self.self_token);
        payload.extend_from_slice(&flight.to_wire());
        client
            .relay_send_forward(peer_token, &payload)
            .await
            .map_err(|e| e.to_string())?;

        let auth_resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rx,
        )
        .await
        .map_err(|_| "relay handshake timed out".to_string())?
        .map_err(|_| "relay handshake channel closed".to_string())?;

        if !auth_resp.verify() {
            return Err("relay responder identity signature failed to verify".to_string());
        }
        let peer_hybrid_pk = auth_resp.identity_pk.to_bytes();
        let key = init.finalize(auth_resp.hello);
        let key_bytes: [u8; 32] = *key.as_bytes();
        self.sessions.lock().await.insert(
            (peer_token, true),
            RelaySession {
                shared: key_bytes,
                we_initiated: true,
                ratchet: std::sync::Arc::new(parking_lot::Mutex::new(
                    transferd_crypto::ratchet::DoubleRatchet::new(&key_bytes, true),
                )),
                peer_hybrid_pk: peer_hybrid_pk.clone(),
            },
        );
        tracing::debug!(
            "[relay] initiator session token={}.. root={}..",
            peer_token[..2].iter().map(|b| format!("{b:02x}")).collect::<String>(),
            key_bytes[..2].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        );
        Ok(peer_hybrid_pk)
    }

    /// The per-peer shared secret (used as the ratchet root by the caller).
    pub async fn session_root(&self, peer_token: [u8; 32]) -> Option<[u8; 32]> {
        self.sessions.lock().await.get(&(peer_token, true)).map(|s| s.shared)
    }

    /// Per-direction (send, recv) keys for an established peer session.
    pub async fn send_keys(&self, peer_token: [u8; 32]) -> Option<([u8; 32], [u8; 32])> {
        let s = self.sessions.lock().await.get(&(peer_token, true)).cloned()?;
        let (role0, role1) = directional_keys(&s.shared);
        Some(if s.we_initiated { (role0, role1) } else { (role1, role0) })
    }

    /// Whether an initiator session with `peer_token` has been established.
    pub async fn has_session(&self, peer_token: [u8; 32]) -> bool {
        self.sessions.lock().await.contains_key(&(peer_token, true))
    }

    // -----------------------------------------------------------------------
    // Receive loops
    // -----------------------------------------------------------------------

    async fn recv_loop_udp(&self, client: Arc<RelayClient>, state: Arc<PkMutex<DaemonState>>) {
        let socket = client.socket();
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((len, _)) = socket.recv_from(&mut buf).await else { break };
            let frame = &buf[..len];
            let Some((&tag, body)) = frame.split_first() else { continue };
            if tag != relayd::protocol::Tag::Ack as u8 {
                continue;
            }
            let Ok(delivered) = bincode::deserialize::<relayd::protocol::DeliveredMsg>(body)
            else {
                continue;
            };
            let raw = &delivered.ciphertext;
            if raw.is_empty() {
                continue;
            }
            let forward: Arc<dyn RelayForward + Send + Sync> = client.clone();
            match raw[0] {
                PREFIX_HANDSHAKE => self.handle_handshake(&forward, &raw[1..], &state).await,
                PREFIX_CHUNK => self.handle_chunk(&forward, &raw[1..], &state).await,
                _ => {}
            }
        }
    }

    async fn recv_loop_ws(
        &self,
        mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        forward: Arc<dyn RelayForward + Send + Sync>,
        state: Arc<PkMutex<DaemonState>>,
    ) {
        while let Some(raw) = rx.recv().await {
            if raw.is_empty() {
                continue;
            }
            match raw[0] {
                PREFIX_HANDSHAKE => self.handle_handshake(&forward, &raw[1..], &state).await,
                PREFIX_CHUNK => self.handle_chunk(&forward, &raw[1..], &state).await,
                _ => {}
            }
        }
    }

    /// Handle a handshake payload: `[sender_token: 32][Auth flight]`.
    async fn handle_handshake(&self, forward: &Arc<dyn RelayForward + Send + Sync>, payload: &[u8], state: &Arc<PkMutex<DaemonState>>) {
        if payload.len() < 32 {
            return;
        }
        let sender_token: [u8; 32] = match payload[..32].try_into() {
            Ok(t) => t,
            Err(_) => return,
        };
        let body = &payload[32..];

        // A responder reply to OUR outgoing handshake.
        if body.first() == Some(&0x12) {
            if let Some(resp) = AuthResponderHello::from_wire(body) {
                if let Some(tx) = self.pending.lock().await.remove(&sender_token) {
                    let _ = tx.send(resp);
                }
            }
            return;
        }

        // Otherwise we are the responder: verify and reply.
        let Some(auth_hello) = AuthInitiatorHello::from_wire(body) else { return };
        if auth_hello.version != PROTOCOL_VERSION {
            return;
        }
        if auth_hello.ciphersuite != CIPHERSUITE_HYBRID_X25519_MLKEM768 {
            return;
        }
        if !auth_hello.verify() {
            tracing::debug!("[relay] rejecting unauthenticated handshake from {sender_token:02x?}");
            return;
        }

        let identity = match state.lock().hybrid_signing_key() {
            Some(id) => id,
            None => return, // no identity: cannot authenticate a reply
        };

        let (resp_hello, key) = Responder::new().respond(&auth_hello.hello);
        let key_bytes: [u8; 32] = *key.as_bytes();
        self.sessions.lock().await.insert(
            (sender_token, false),
            RelaySession {
                shared: key_bytes,
                we_initiated: false,
                ratchet: std::sync::Arc::new(parking_lot::Mutex::new(
                    transferd_crypto::ratchet::DoubleRatchet::new(&key_bytes, false),
                )),
                peer_hybrid_pk: auth_hello.identity_pk.to_bytes(),
            },
        );
        tracing::debug!(
            "[relay] responder session token={}.. root={}..",
            sender_token[..2].iter().map(|b| format!("{b:02x}")).collect::<String>(),
            key_bytes[..2].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        );

        let flight = AuthResponderHello::build(
            &resp_hello,
            PROTOCOL_VERSION,
            CIPHERSUITE_HYBRID_X25519_MLKEM768,
            &identity,
        );
        let mut payload = Vec::with_capacity(1 + 32 + flight.to_wire().len());
        payload.push(PREFIX_HANDSHAKE);
        payload.extend_from_slice(&self.self_token);
        payload.extend_from_slice(&flight.to_wire());
        let _ = forward.relay_send_forward(sender_token, &payload).await;
    }

    /// Handle an encrypted chunk: `[sender_token: 32][nonce][tag][ciphertext]`.
    async fn handle_chunk(&self, forward: &Arc<dyn RelayForward + Send + Sync>, payload: &[u8], state: &Arc<PkMutex<DaemonState>>) {
        tracing::debug!("[relay] inbound chunk ({} bytes)", payload.len());
        if payload.len() < 32 + 28 {
            tracing::warn!("[relay] chunk too short: {} bytes", payload.len());
            return;
        }
let sender_token: [u8; 32] = match payload[..32].try_into() {
            Ok(t) => t,
            Err(_) => {
                tracing::warn!("[relay] chunk token parse failed");
                return;
            }
        };

        let raw = &payload[32..];
        let Ok(nonce) = <[u8; 12]>::try_from(&raw[..12]) else {
            tracing::warn!("[relay] chunk nonce parse failed");
            return;
        };
        let Ok(gcm_tag) = <[u8; 16]>::try_from(&raw[12..28]) else {
            tracing::warn!("[relay] chunk tag parse failed");
            return;
        };
        let ct = &raw[28..];

        // A peer may hold BOTH roles (it initiated to us and we initiated to
        // it). Try each role's session; only the one whose recv-key matches the
        // peer's send-role will pass the GCM tag check.
        let mut chosen: Option<RelaySession> = None;
        let mut decrypted: Vec<u8> = Vec::new();
        for we_initiated in [true, false] {
            let Some(session) = self.sessions.lock().await.get(&(sender_token, we_initiated)).cloned() else {
                continue;
            };
            let recv_key = if session.we_initiated {
                directional_keys(&session.shared).1 // send=role0, recv=role1
            } else {
                directional_keys(&session.shared).0 // send=role1, recv=role0
            };
            let aad = (ct.len() as u64).to_le_bytes();
            let mut try_ct = ct.to_vec();
            let ok = DmiDecryptor::new(&recv_key)
                .decrypt_verify(&mut try_ct, &nonce, &gcm_tag, &aad)
                .is_ok();
            if ok {
                chosen = Some(session);
                decrypted = try_ct;
                break;
            }
        }
        let Some(session) = chosen else {
            tracing::warn!("[relay] chunk decrypt failed for {sender_token:02x?}");
            return;
        };
        let send_key = if session.we_initiated {
            directional_keys(&session.shared).0
        } else {
            directional_keys(&session.shared).1
        };
        let ct = decrypted;

        // Un-pad and decode the chunk, then the wire message (via the ratchet).
        let Some(plaintext) = unpad_plaintext(&ct) else {
            tracing::warn!("[relay] chunk unpad failed");
            return;
        };
        let Ok(wire) = bincode::deserialize::<transferd_core::transport::WireChunk>(&plaintext)
        else {
            tracing::warn!("[relay] WireChunk decode failed");
            return;
        };
        let chunk = Chunk::from(wire);
        let rm: transferd_crypto::ratchet::RatchetMessage =
            match bincode::deserialize(&chunk.payload) {
                Ok(rm) => rm,
                Err(_) => {
                    tracing::warn!("[relay] RatchetMessage decode failed");
                    return;
                }
            };
        let pre_state = session.ratchet.lock().debug_state();
        let plain = match session.ratchet.lock().decrypt(&rm) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    "[relay] ratchet decrypt failed: {e}; local=[{pre_state}] msg_pk={} idx={} we_initiated={}",
                    rm.ratchet_pk
                        .map(|p| format!("{}..", p[..2].iter().map(|b| format!("{b:02x}")).collect::<String>()))
                        .unwrap_or_else(|| "none".into()),
                    rm.chain_index,
                    session.we_initiated,
                );
                return;
            }
        };
        let Ok(msg) = WireMsg::decode(&plain) else {
            tracing::warn!("[relay] WireMsg decode failed");
            return;
        };

        // Drop messages from blocked contacts.
        let blocked = {
            let s = state.lock();
            match &msg {
                WireMsg::Text { sender, .. } | WireMsg::File { sender, .. } => {
                    s.contacts.iter().any(|c| c.id == *sender && c.blocked)
                }
                _ => false,
            }
        };
        if blocked {
            return;
        }

        // Apply to state; ack when the message expects one.
        let reply = { let mut s = state.lock(); s.apply_inbound(&msg) };
        if let Some(ack) = reply {
            if let Ok(ack_bytes) = ack.encode() {
                // Ratchet the ack with our per-message key.
                let ack_payload = session.ratchet.lock().encrypt(&ack_bytes).ok();
                let ack_chunk = Chunk {
                    gsn: Gsn(0),
                    session_id: SessionId(chunk.session_id.0),
                    payload: Bytes::from(
                        ack_payload
                            .and_then(|rm| bincode::serialize(&rm).ok())
                            .unwrap_or(ack_bytes),
                    ),
                    key_epoch: 0,
                    qos_critical: false,
                };
                if let Ok(enc) = encrypt_chunk(&send_key, &ack_chunk, &self.self_token) {
                    let _ = forward.relay_send_forward(sender_token, &enc).await;
                }
            }
        }
    }
}

/// Encrypt a chunk into the relay frame layout `[PREFIX_CHUNK][token][nonce][tag][ct]`.
fn encrypt_chunk(
    send_key: &[u8; 32],
    chunk: &Chunk,
    self_token: &[u8; 32],
) -> Result<Vec<u8>, ()> {
    let wire = transferd_core::transport::WireChunk::from(chunk);
    let raw = bincode::serialize(&wire).map_err(|_| ())?;
    let plaintext = pad_plaintext(&raw);
    let nonce = DmiEncryptor::nonce_for(chunk.gsn.0, chunk.key_epoch);
    let aad = (plaintext.len() as u64).to_le_bytes();

    let encryptor = DmiEncryptor::new(send_key);
    let mut buf = plaintext;
    let tag = encryptor.encrypt_detached(&mut buf, &nonce, &aad).map_err(|_| ())?;

    let mut payload = Vec::with_capacity(1 + 32 + 12 + 16 + buf.len());
    payload.push(PREFIX_CHUNK);
    payload.extend_from_slice(self_token);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&tag);
    payload.extend_from_slice(&buf);
    Ok(payload)
}

/// Power-of-two padding with a 4-byte LE length header (matches RelayLane).
fn pad_plaintext(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut power = 32usize;
    while power < data.len() + 4 {
        power *= 2;
    }
    let mut out = Vec::with_capacity(power);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    out.resize(power, 0);
    out
}

/// Strip the length header + padding added by `pad_plaintext`.
fn unpad_plaintext(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
    if 4 + len > data.len() {
        return None;
    }
    Some(data[4..4 + len].to_vec())
}