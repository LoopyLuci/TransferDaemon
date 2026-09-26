//! PeerConnectionManager — orchestration layer connecting gRPC services to transport.
//!
//! This module manages connections to other peers, including:
//! - Session establishment via a real X25519 handshake
//! - Lane pool management
//! - Message transmission and reception
//! - Delivery-status correlation (message id ↔ GSN)

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use bytes::Bytes;

use transferd_core::session::Session;
use transferd_core::transport::TransportLane;
use transferd_core::types::{Gsn, SessionId};
use transferd_core::ate::Ate;

use crate::handshake_manager::HandshakeManager;
use crate::wire::WireMsg;

// ---------------------------------------------------------------------------
// PeerSession
// ---------------------------------------------------------------------------

/// A session with a specific peer.
pub struct PeerSession {
    /// The session identifier.
    pub session_id: SessionId,
    /// The session for sending chunks.
    pub session: Session,
    /// Transport lanes to this peer.
    pub lanes: Vec<Box<dyn TransportLane>>,
    /// Last time this session was active.
    pub last_activity: Instant,
    /// Whether this session is currently connected.
    pub connected: bool,
    /// Per-message double ratchet (forward + future secrecy).
    ratchet: parking_lot::Mutex<transferd_crypto::ratchet::DoubleRatchet>,
    /// Outbound chunks awaiting a delivery-status transition: `(gsn, msg_id)`.
    outbound_gsns: VecDeque<(u64, String)>,
    /// Last seen byte counters per lane (bandwidth estimation).
    last_bytes: Vec<u64>,
    /// Last health-tick instant.
    last_health: Instant,
}

impl PeerSession {
    /// Create a new peer session.
    pub fn new(session_id: SessionId, lanes: Vec<Box<dyn TransportLane>>) -> Self {
        Self::with_window(session_id, lanes, 8192)
    }

    /// Create a new peer session with an explicit in-flight window/gap limit.
    ///
    /// The window is generous because control-plane Acks (which advance the
    /// sender's base GSN) are not wired yet; raising it keeps multi-chunk
    /// transfers (e.g. files) flowing.
    pub fn with_window(session_id: SessionId, lanes: Vec<Box<dyn TransportLane>>, window: u64) -> Self {
        let ate = Ate::new(lanes.len(), window); // lane_count, reorder-gap limit
        let session = Session::new(session_id, ate, window);
        Self {
            session_id,
            session,
            lanes,
            last_activity: Instant::now(),
            connected: true,
            ratchet: parking_lot::Mutex::new(transferd_crypto::ratchet::DoubleRatchet::new(
                &[0u8; 32], true,
            )),
            outbound_gsns: VecDeque::new(),
            last_bytes: Vec::new(),
            last_health: Instant::now(),
        }
    }

    /// Create a ratcheted peer session from the handshake session key.
    /// `is_initiator` aligns the send/recv chains with the peer.
    pub fn with_ratchet(
        session_id: SessionId,
        lanes: Vec<Box<dyn TransportLane>>,
        root_key: &[u8; 32],
        is_initiator: bool,
    ) -> Self {
        let ate = Ate::new(lanes.len(), 8192);
        let session = Session::new(session_id, ate, 8192);
        Self {
            session_id,
            session,
            lanes,
            last_activity: Instant::now(),
            connected: true,
            ratchet: parking_lot::Mutex::new(
                transferd_crypto::ratchet::DoubleRatchet::new(root_key, is_initiator),
            ),
            outbound_gsns: VecDeque::new(),
            last_bytes: Vec::new(),
            last_health: Instant::now(),
        }
    }

    /// Enqueue a message for transmission. `msg_id` is remembered so that once
    /// the chunk is dispatched to a lane the caller can mark it "sent".
    pub fn send_message(&mut self, msg_id: String, payload: Bytes, key_epoch: u8) {
        let gsn = self.session.next_gsn();
        let payload = self.ratchet_payload(payload);
        self.session.enqueue(payload, key_epoch);
        self.outbound_gsns.push_back((gsn.0, msg_id));
        self.last_activity = Instant::now();
    }

    /// Wrap a WireMsg payload in the ratchet envelope (per-message key).
    fn ratchet_payload(&self, payload: Bytes) -> Bytes {
        match self.ratchet.lock().encrypt(&payload) {
            Ok(rm) => bincode::serialize(&rm)
                .map(Bytes::from)
                .unwrap_or(payload),
            Err(e) => {
                tracing::error!("[peer] ratchet encrypt failed: {e}");
                payload
            }
        }
    }

    /// Return the message ids of chunks that were actually dispatched this tick,
    /// dropping their GSN↔id records.
    pub fn take_sent_ids(&mut self, sent: &[(usize, Gsn)]) -> Vec<String> {
        let sent_gsns: std::collections::HashSet<u64> =
            sent.iter().map(|(_, g)| g.0).collect();
        let mut dispatched = Vec::new();
        self.outbound_gsns.retain(|(gsn, id)| {
            if sent_gsns.contains(gsn) {
                dispatched.push(id.clone());
                false
            } else {
                true
            }
        });
        dispatched
    }

    /// Drain any inbound messages from the lanes (acks, read receipts, or
    /// unsolicited messages received on a full-duplex lane). Non-blocking:
    /// returns whatever is already buffered.
    pub async fn drain_inbound(&mut self) -> Vec<WireMsg> {
        let mut out = Vec::new();
        for lane in self.lanes.iter_mut() {
            while let Some(res) = lane.try_recv().await {
                match res {
                    Ok(chunk) => {
                        if let Some(msg) = unwrap_ratcheted(&self.ratchet, &chunk.payload) {
                            out.push(msg);
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        out
    }

    /// Process pending chunks (called periodically).
    pub async fn process_tick(&mut self) -> Vec<(usize, Gsn)> {
        if self.lanes.is_empty() {
            return vec![];
        }
        self.last_activity = Instant::now();
        self.session.process_tick(&mut self.lanes).await
    }

    /// The underlying transport lanes.
    pub fn lanes(&self) -> &[Box<dyn TransportLane>] {
        &self.lanes
    }

    /// Check if the session has timed out.
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Measure per-lane bandwidth from byte deltas and issue RTT pings.
    pub async fn tick_health(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_health).as_secs_f64().max(0.01);
        self.last_health = now;
        while self.last_bytes.len() < self.lanes.len() {
            self.last_bytes.push(self.lanes[self.last_bytes.len()].metrics().bytes_sent());
        }
        for (i, lane) in self.lanes.iter_mut().enumerate() {
            let m = lane.metrics();
            let bytes = m.bytes_sent();
            let delta = bytes.saturating_sub(self.last_bytes[i]);
            m.update_bandwidth(delta as f64 / dt * 8.0);
            self.last_bytes[i] = bytes;
            if lane.ping_interval().is_some() {
                lane.ping().await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PeerConnectionManager
// ---------------------------------------------------------------------------

/// Events produced by a transport tick, to be applied to daemon state.
#[derive(Debug, Default)]
pub struct SessionEvents {
    /// Message ids that were dispatched to a lane this tick (→ "sent").
    pub sent_msg_ids: Vec<String>,
    /// Inbound messages from peers: `(contact_id, msg)`.
    pub inbound: Vec<(String, WireMsg)>,
}

/// Manages connections to all peers.
pub struct PeerConnectionManager {
    /// Sessions indexed by contact ID (public key hex).
    sessions: HashMap<String, PeerSession>,
    /// Session timeout duration.
    session_timeout: Duration,
}

impl Default for PeerConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerConnectionManager {
    /// Create a new peer connection manager.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            session_timeout: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Get or create a session for a contact.
    pub fn get_or_create_session(
        &mut self,
        contact_id: &str,
        lanes: Vec<Box<dyn TransportLane>>,
    ) -> &mut PeerSession {
        self.sessions
            .entry(contact_id.to_string())
            .or_insert_with(|| {
                let session_id = SessionId(hex_to_bytes(contact_id));
                PeerSession::new(session_id, lanes)
            })
    }

    /// Get a session for a contact.
    pub fn get_session(&self, contact_id: &str) -> Option<&PeerSession> {
        self.sessions.get(contact_id)
    }

    /// Get a mutable session for a contact.
    pub fn get_session_mut(&mut self, contact_id: &str) -> Option<&mut PeerSession> {
        self.sessions.get_mut(contact_id)
    }

    /// Iterate sessions as `(contact_id, &PeerSession)`.
    pub fn sessions(&self) -> impl Iterator<Item = (&String, &PeerSession)> {
        self.sessions.iter()
    }

    /// Iterate sessions mutably as `(contact_id, &mut PeerSession)`.
    pub fn sessions_mut(&mut self) -> impl Iterator<Item = (&String, &mut PeerSession)> {
        self.sessions.iter_mut()
    }

    /// Remove a timed-out session.
    pub fn remove_timed_out_sessions(&mut self) {
        self.sessions.retain(|_, session| !session.is_timed_out(self.session_timeout));
    }

    /// Process all sessions (called periodically): flush pending chunks, drain
    /// inbound messages, apply transport acks, and retransmit stale chunks.
    pub async fn process_all_sessions(&mut self) -> SessionEvents {
        let mut events = SessionEvents::default();
        for (contact_id, session) in self.sessions.iter_mut() {
            if !session.connected || session.lanes.is_empty() {
                continue;
            }
            // Apply transport-level acks/pongs from the lanes.
            for lane in session.lanes.iter_mut() {
                while let Some(ctrl) = lane.try_recv_control().await {
                    match ctrl {
                        transferd_core::transport::ControlMsg::Ack { gsn, .. } => {
                            // Cumulative ack: everything up to and including
                            // `gsn` is delivered.
                            let msg = transferd_core::control_channel::ControlMessage::Ack {
                                session_id: session.session_id,
                                cumulative_gsn: gsn + 1,
                            };
                            session.session.handle_control(msg);
                        }
                        transferd_core::transport::ControlMsg::Pong { nonce: _, sent_ts } => {
                            let now_us = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_micros() as u64;
                            let rtt_ms = now_us.saturating_sub(sent_ts) as f64 / 1000.0;
                            lane.metrics().update_rtt(rtt_ms);
                            // A successful RTT round-trip proves liveness.
                            lane.metrics().mark_alive();
                        }
                    }
                }
            }

            // Health tick: bandwidth from byte deltas + RTT pings.
            session.tick_health().await;

            // Retransmit stale chunks, then flush pending.
            let _ = session.session.maybe_retransmit(&mut session.lanes).await;
            let sent = session.process_tick().await;
            events.sent_msg_ids.extend(session.take_sent_ids(&sent));

            // In-flight accounting: outstanding = sent-but-unacked.
            let outstanding = session.session.outstanding() as u64;
            for lane in session.lanes.iter() {
                lane.metrics().set_active(outstanding);
            }

            for msg in session.drain_inbound().await {
                events.inbound.push((contact_id.clone(), msg));
            }
        }
        events
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Check if a contact has an active session.
    pub fn has_session(&self, contact_id: &str) -> bool {
        self.sessions.contains_key(contact_id)
    }

    /// Send a message to a contact. The message is queued in the peer session
    /// and flushed by the next `process_all_sessions` tick.
    pub fn send_message(
        &mut self,
        contact_id: &str,
        msg_id: String,
        payload: Bytes,
    ) -> Result<(), String> {
        let session = self
            .get_session_mut(contact_id)
            .ok_or_else(|| format!("no active session for {contact_id}"))?;
        session.send_message(msg_id, payload, 0);
        Ok(())
    }

    /// Create a session for a contact with a direct TCP lane.
    ///
    /// Performs the authenticated hybrid handshake over the new connection and
    /// derives per-direction AES-256-GCM keys so the two directions never share
    /// a (key, nonce) pair. The initiator uses role-0 keys for sending.
    pub async fn create_tcp_session(
        &mut self,
        contact_id: &str,
        address: &str,
        identity: &transferd_crypto::identity::HybridSigningKey,
    ) -> Result<(), String> {
        let (session, _peer_identity) = establish_tcp_session(contact_id, address, identity).await?;
        self.insert_session(contact_id, session);
        Ok(())
    }

    /// Insert a fully-established peer session (used after the async connect +
    /// handshake ran without holding any manager lock).
    pub fn insert_session(&mut self, contact_id: &str, session: PeerSession) {
        self.sessions.insert(contact_id.to_string(), session);
    }
}

/// Decrypt and decode an inbound chunk payload through the per-message ratchet.
fn unwrap_ratcheted(
    ratchet: &parking_lot::Mutex<transferd_crypto::ratchet::DoubleRatchet>,
    payload: &[u8],
) -> Option<WireMsg> {
    let rm: transferd_crypto::ratchet::RatchetMessage = bincode::deserialize(payload).ok()?;
    let plain = ratchet.lock().decrypt(&rm).ok()?;
    WireMsg::decode(&plain).ok()
}

/// Establish a direct TCP session to a peer without touching the manager.
///
/// Async: connects, runs the authenticated hybrid handshake, verifies the
/// peer's authenticated identity against the contact's public key, and builds
/// a `TcpLane` with per-direction keys. Returns the session together with the
/// peer's verified 2624-byte hybrid public key. The caller then inserts the
/// session (recording the fingerprint under trust-on-first-use).
pub async fn establish_tcp_session(
    contact_id: &str,
    address: &str,
    identity: &transferd_crypto::identity::HybridSigningKey,
) -> Result<(PeerSession, Vec<u8>), String> {
    let session_id = SessionId(hex_to_bytes(contact_id));
    let addr: std::net::SocketAddr = address.parse()
        .map_err(|e| format!("Invalid address: {e}"))?;

    // Connect and run the authenticated hybrid handshake.
    let mut stream = tokio::net::TcpStream::connect(addr).await
        .map_err(|e| format!("Failed to connect to {address}: {e}"))?;
    let handshake = HandshakeManager::new();
    let (session_key, peer_identity) = handshake
        .run_initiator_on(&mut stream, identity)
        .await
        .map_err(|e| format!("Handshake failed: {e}"))?;
    let peer_hybrid_pk = verify_peer_identity(contact_id, &peer_identity)?;

    let (send_key, recv_key) = directional_keys(&session_key.key);

    // Create a TCP lane to the peer (initiator: send=role0, recv=role1).
    let lane = transferd_core::lanes::tcp_lane::TcpLane::from_stream(
        0x54435020, // "TCP " lane ID
        stream,
        &send_key,
        &recv_key,
    )
    .map_err(|e| format!("Failed to create TCP lane: {e}"))?;

    tracing::info!("[PeerManager] session established for {contact_id} at {address}");
    Ok((
        PeerSession::with_ratchet(session_id, vec![Box::new(lane)], &session_key.key, true),
        peer_hybrid_pk,
    ))
}

/// Establish a relay session to a peer via the daemon's `RelayHub`.
///
/// Runs the authenticated hybrid handshake over the relay (or reuses an
/// existing session), verifies the peer's authenticated identity against the
/// contact's public key, then builds a send-only `RelayLane`. Returns the
/// session together with the peer's verified 2624-byte hybrid public key.
pub async fn establish_relay_session(
    contact_id: &str,
    relay_addr: &str,
    peer_token_hex: &str,
    state: &std::sync::Arc<parking_lot::Mutex<crate::state::DaemonState>>,
) -> Result<(PeerSession, Vec<u8>), String> {
    let peer_token: [u8; 32] = hex_decode(peer_token_hex)
        .ok_or_else(|| format!("invalid relay peer token: {peer_token_hex}"))?;
    let relay_addr: std::net::SocketAddr = relay_addr
        .parse()
        .map_err(|e| format!("invalid relay address {relay_addr}: {e}"))?;

    let identity = state
        .lock()
        .hybrid_signing_key()
        .ok_or_else(|| "no identity: cannot authenticate over relay".to_string())?;

    let hub = state
        .lock()
        .relay_hub
        .clone()
        .ok_or_else(|| "relay not enabled on this daemon".to_string())?;
    if hub.relay_addr() != relay_addr {
        return Err(format!(
            "relay mismatch: daemon is on {}, contact wants {relay_addr}",
            hub.relay_addr()
        ));
    }

    let peer_hybrid_pk = hub.initiate(peer_token, &identity).await?;
    let peer_vk = transferd_crypto::identity::HybridVerifyingKey::from_bytes(&peer_hybrid_pk)
        .ok_or_else(|| "invalid peer hybrid identity from relay".to_string())?;
    let peer_hybrid_pk = verify_peer_identity(contact_id, &peer_vk)?;
    let (send_key, recv_key) = hub
        .send_keys(peer_token)
        .await
        .ok_or_else(|| "relay session not established".to_string())?;
    let self_token = hub.self_token();

    let lane = transferd_core::lanes::relay_lane::RelayLane::new(
        0x52454C59, // "RELY" lane ID
        relay_addr,
        self_token,
        peer_token,
        &send_key,
        &recv_key,
        false, // registration is owned by the hub
    )
    .await
    .map_err(|e| format!("Failed to create relay lane: {e}"))?;

    tracing::info!("[PeerManager] relay session established for {contact_id} via {relay_addr}");
    let root = hub
        .session_root(peer_token)
        .await
        .ok_or_else(|| "relay session root unavailable".to_string())?;
    Ok((
        PeerSession::with_ratchet(
            SessionId(hex_to_bytes(contact_id)),
            vec![Box::new(lane)],
            &root,
            true,
        ),
        peer_hybrid_pk,
    ))
}

/// Verify the peer's authenticated hybrid identity against the expected
/// contact public key. Returns the peer's 2624-byte hybrid public key bytes,
/// or an error when the classical Ed25519 component does not match.
pub fn verify_peer_identity(
    contact_id: &str,
    peer_vk: &transferd_crypto::identity::HybridVerifyingKey,
) -> Result<Vec<u8>, String> {
    let expected = hex_decode(contact_id)
        .ok_or_else(|| format!("invalid contact public key: {contact_id}"))?;
    let pk = peer_vk.to_bytes();
    if pk[..32] != expected {
        return Err(format!(
            "peer identity mismatch for {contact_id}: authenticated Ed25519 key does not match the contact"
        ));
    }
    Ok(pk)
}

/// Decode a 64-char hex string into a 32-byte token.
fn hex_decode(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let bytes = hex::decode(hex).ok()?;
    bytes.try_into().ok()
}

// ---------------------------------------------------------------------------
// Directional key derivation
// ---------------------------------------------------------------------------

/// Derive the initiator's send/recv keys from the handshake shared secret.
///
/// The initiator sends with `send` and receives with `recv`; the responder
/// uses the same pair but swapped (`recv` for sending, `send` for receiving).
/// Because the two directions use different keys, an identical GSN can never
/// produce a (key, nonce) collision across directions.
pub fn directional_keys(shared: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let initiator_send = blake3::derive_key("TransferDaemon-v2-lane-role-0", shared);
    let initiator_recv = blake3::derive_key("TransferDaemon-v2-lane-role-1", shared);
    (initiator_send, initiator_recv)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Convert a hex string to bytes.
fn hex_to_bytes(hex: &str) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    let hex_bytes = hex.as_bytes();
    for i in 0..16 {
        if i * 2 < hex_bytes.len() {
            let high = hex_to_nibble(hex_bytes[i * 2]);
            let low = if i * 2 + 1 < hex_bytes.len() {
                hex_to_nibble(hex_bytes[i * 2 + 1])
            } else {
                0
            };
            bytes[i] = (high << 4) | low;
        }
    }
    bytes
}

/// Convert a hex character to a nibble.
fn hex_to_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_bytes() {
        let hex = "00000000000000000000000000000001";
        let bytes = hex_to_bytes(hex);
        assert_eq!(bytes[15], 1);
        assert_eq!(bytes[0], 0);
    }

#[test]
    fn test_peer_session_creation() {
        let session_id = SessionId([1u8; 16]);
        let session = PeerSession::new(session_id, vec![]);
        assert_eq!(session.session_id, session_id);
    }

    #[test]
    fn test_verify_peer_identity_matches() {
        let sk = transferd_crypto::identity::HybridSigningKey::from_bip39_seed(&[1u8; 64]);
        let vk = sk.verifying_key();
        let pk_hex = hex::encode(&vk.to_bytes()[..32]);
        let pk = verify_peer_identity(&pk_hex, &vk).expect("must match");
        assert_eq!(pk.len(), 2624);
    }

    #[test]
    fn test_verify_peer_identity_rejects_mismatch() {
        let sk = transferd_crypto::identity::HybridSigningKey::from_bip39_seed(&[1u8; 64]);
        let other = transferd_crypto::identity::HybridSigningKey::from_bip39_seed(&[2u8; 64]);
        let vk = sk.verifying_key();
        let other_vk = other.verifying_key();
        let wrong_pk_hex = hex::encode(&other_vk.to_bytes()[..32]);
        let err = verify_peer_identity(&wrong_pk_hex, &vk).expect_err("must reject mismatch");
        assert!(err.contains("identity mismatch"), "error explains the cause: {err}");
    }

    #[test]
    fn test_peer_connection_manager() {
        let manager = PeerConnectionManager::new();
        assert_eq!(manager.session_count(), 0);
        assert!(!manager.has_session("test"));
    }

    #[test]
    fn test_directional_keys_differ() {
        let shared = [7u8; 32];
        let (role0, role1) = directional_keys(&shared);
        // The two directions must never share a key, otherwise identical GSNs
        // would collide on (key, nonce) across directions.
        assert_ne!(role0, role1, "role-0 and role-1 keys must differ");
        // Deterministic: the same shared secret yields the same pair.
        let (role0b, role1b) = directional_keys(&shared);
        assert_eq!(role0, role0b);
        assert_eq!(role1, role1b);
        // Different shared secrets yield different keys.
        let (c0, c1) = directional_keys(&[8u8; 32]);
        assert_ne!(role0, c0);
        assert_ne!(role1, c1);
    }
}