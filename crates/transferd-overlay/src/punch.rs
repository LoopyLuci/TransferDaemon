//! UDP hole punching: authenticated probes sent from the relay socket, and the direct route a
//! successful exchange leaves behind.
//!
//! A NAT lets a datagram in only through a mapping an outbound datagram created, and the mapping
//! worth using is the one the relay already saw: the node's relay socket. So the probes are sent
//! from that very socket (see [`PunchTable`]), at every address the peer named, at the same
//! moment the peer does the same. Each side's outbound probe opens its own NAT for the other's.
//!
//! The two nodes agree on the attempt over their existing session (`PunchMsg`, which is
//! encrypted end to end), and each contributes a random nonce. Both nonces and the attempt id
//! derive two secrets that nobody else holds:
//!
//! * a probe key, which authenticates every probe and reply;
//! * a link secret, from which the punched route's own tunnel keys come.
//!
//! ```text
//! probe := "TDPB" | kind u8 | id u64 BE | seq u32 BE | mac [16]      (33 bytes)
//! kind  := 1 probe from the initiator   2 probe from the responder
//!          3 reply from the initiator   4 reply from the responder
//! mac   := BLAKE3-keyed(probe key, every byte before it)[..16]
//! ```
//!
//! What keeps this from being a reflector or an oracle:
//!
//! * a datagram that is not exactly a probe of an attempt in progress, with a valid MAC and from
//!   the *other* role, is dropped without an answer;
//! * a probe is answered only when it comes from an address the peer named, and at most a few
//!   times per address per second and per attempt;
//! * probes are sent only to addresses the peer named (loopback, unspecified, multicast and
//!   link-local ones are not accepted as names, loopback excepted when the relay itself is
//!   loopback), at most a handful of times each;
//! * an attempt is forgotten two seconds after it ends.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use crate::error::{OverlayError, Result};
use crate::lanes::FramePipe;
use crate::link::{Link, RouteKind};
use crate::protocol::FrameReader;
use crate::wire::{LinkKeys, Tunnel};

/// The first bytes of a probe.
pub const PROBE_MAGIC: [u8; 4] = *b"TDPB";
/// Bytes of a probe: magic, kind, id, seq, MAC. Shorter than any sealed tunnel frame, so the two
/// can never be mistaken for each other.
pub const PROBE_LEN: usize = 4 + 1 + 8 + 4 + MAC_LEN;
const MAC_LEN: usize = 16;

/// Candidates considered per attempt.
pub const MAX_CANDIDATES: usize = 8;
/// Rounds of probes sent, one every [`ROUND_EVERY`]: about two seconds.
pub const ROUNDS: u32 = 10;
pub const ROUND_EVERY: Duration = Duration::from_millis(200);
/// How long after the last round a late reply is still waited for.
const LATE_REPLY: Duration = Duration::from_millis(400);
/// How long an attempt keeps answering the peer's probes after it ended.
const LINGER: Duration = Duration::from_secs(2);
/// Replies one attempt gives in total, and the least time between two to one address.
const MAX_REPLIES: u32 = 64;
const REPLY_GAP: Duration = Duration::from_millis(40);
/// Punched routes kept at once; the oldest is closed beyond this.
const MAX_ESTABLISHED: usize = 8;

/// The first bytes of a datagram wrapped for a UDP gateway.
pub const GATEWAY_MAGIC: [u8; 4] = *b"TDGW";

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

/// A probe or the reply to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    Probe,
    Reply,
}

/// What a probe says (its MAC is checked on the way in and made on the way out).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub kind: ProbeKind,
    /// Whether the sender is the node that started the attempt.
    pub from_initiator: bool,
    pub id: u64,
    pub seq: u32,
}

/// The secrets of one attempt.
#[derive(Clone)]
pub struct PunchKeys {
    probe: [u8; 32],
    link: [u8; 32],
}

impl PunchKeys {
    /// Derive both secrets from the attempt id and the two nodes' nonces.
    pub fn derive(id: u64, initiator_nonce: &[u8; 32], responder_nonce: &[u8; 32]) -> Self {
        let mut material = Vec::with_capacity(8 + 64);
        material.extend_from_slice(&id.to_be_bytes());
        material.extend_from_slice(initiator_nonce);
        material.extend_from_slice(responder_nonce);
        Self {
            probe: blake3::derive_key("transferd-overlay-punch-probe-v1", &material),
            link: blake3::derive_key("transferd-overlay-punch-link-v1", &material),
        }
    }
}

fn kind_byte(p: &Probe) -> u8 {
    1 + 2 * (p.kind == ProbeKind::Reply) as u8 + (!p.from_initiator) as u8
}

fn mac_of(key: &[u8; 32], head: &[u8]) -> [u8; MAC_LEN] {
    let full = blake3::keyed_hash(key, head);
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&full.as_bytes()[..MAC_LEN]);
    mac
}

/// Build the datagram for a probe.
pub fn encode_probe(key: &PunchKeys, probe: &Probe) -> [u8; PROBE_LEN] {
    let mut out = [0u8; PROBE_LEN];
    out[..4].copy_from_slice(&PROBE_MAGIC);
    out[4] = kind_byte(probe);
    out[5..13].copy_from_slice(&probe.id.to_be_bytes());
    out[13..17].copy_from_slice(&probe.seq.to_be_bytes());
    let mac = mac_of(&key.probe, &out[..17]);
    out[17..].copy_from_slice(&mac);
    out
}

/// Whether a datagram has the shape of a probe (before any key is tried).
pub fn probe_shaped(data: &[u8]) -> bool {
    data.len() == PROBE_LEN && data[..4] == PROBE_MAGIC
}

/// The attempt id a probe-shaped datagram names, to find the key to check it with.
pub fn probe_id(data: &[u8]) -> Option<u64> {
    if !probe_shaped(data) {
        return None;
    }
    Some(u64::from_be_bytes(data[5..13].try_into().ok()?))
}

/// Read a probe, if its MAC is valid under `key`.
pub fn decode_probe(key: &PunchKeys, data: &[u8]) -> Option<Probe> {
    if !probe_shaped(data) {
        return None;
    }
    let expected = mac_of(&key.probe, &data[..17]);
    // Constant time: no early exit on the first differing byte.
    let diff = expected
        .iter()
        .zip(&data[17..])
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return None;
    }
    let (kind, from_initiator) = match data[4] {
        1 => (ProbeKind::Probe, true),
        2 => (ProbeKind::Probe, false),
        3 => (ProbeKind::Reply, true),
        4 => (ProbeKind::Reply, false),
        _ => return None,
    };
    Some(Probe {
        kind,
        from_initiator,
        id: u64::from_be_bytes(data[5..13].try_into().ok()?),
        seq: u32::from_be_bytes(data[13..17].try_into().ok()?),
    })
}

// ---------------------------------------------------------------------------
// Candidates
// ---------------------------------------------------------------------------

/// Whether a peer may name `addr` as a place to send probes.
///
/// Never an address that cannot be a peer (port 0, unspecified, multicast, broadcast, link-local).
/// Loopback only when the relay is on loopback too, which is a node and its relay on one machine
/// (a test, or a lab): otherwise a peer could aim our probes at our own services.
pub fn acceptable_candidate(addr: SocketAddr, relay_is_loopback: bool) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(ip) => {
            !(ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_link_local()
                || (ip.is_loopback() && !relay_is_loopback))
        }
        IpAddr::V6(ip) => {
            !(ip.is_unspecified()
                || ip.is_multicast()
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || (ip.is_loopback() && !relay_is_loopback))
        }
    }
}

/// The address this machine would use towards `relay`: its address on the network the relay is
/// reached over, which is the one a peer on the same network can reach it on. Nothing is sent.
pub fn local_ip_toward(relay: SocketAddr) -> Option<IpAddr> {
    let bind = if relay.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let probe = std::net::UdpSocket::bind(bind).ok()?;
    probe.connect(relay).ok()?;
    probe.local_addr().ok().map(|a| a.ip())
}

// ---------------------------------------------------------------------------
// The UDP gateway envelope
// ---------------------------------------------------------------------------

/// Wrap a datagram for a UDP gateway: a proxy that sends it on to `dest` from its own socket and
/// hands back what arrives, wrapped the same way with the sender's address. A NAT emulator in a
/// test is one; so is any UDP-aware proxy a node has to go through.
///
/// ```text
/// wrapped := "TDGW" | family u8 (4 or 6) | ip octets | port u16 BE | datagram
/// ```
pub fn gateway_wrap(addr: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 16 + 2 + data.len());
    out.extend_from_slice(&GATEWAY_MAGIC);
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Undo [`gateway_wrap`]: the address and the datagram inside.
pub fn gateway_unwrap(data: &[u8]) -> Option<(SocketAddr, &[u8])> {
    let rest = data.strip_prefix(&GATEWAY_MAGIC)?;
    let (&family, rest) = rest.split_first()?;
    let (ip, rest) = match family {
        4 => {
            let (octets, rest) = rest.split_at_checked(4)?;
            let octets: [u8; 4] = octets.try_into().ok()?;
            (IpAddr::V4(Ipv4Addr::from(octets)), rest)
        }
        6 => {
            let (octets, rest) = rest.split_at_checked(16)?;
            let octets: [u8; 16] = octets.try_into().ok()?;
            (IpAddr::V6(Ipv6Addr::from(octets)), rest)
        }
        _ => return None,
    };
    let (port, rest) = rest.split_at_checked(2)?;
    let port = u16::from_be_bytes([port[0], port[1]]);
    Some((SocketAddr::new(ip, port), rest))
}

// ---------------------------------------------------------------------------
// The table of attempts and punched routes on one relay socket
// ---------------------------------------------------------------------------

/// One attempt in progress (or lingering to answer the peer's last probes).
struct Active {
    keys: PunchKeys,
    initiator: bool,
    /// The addresses the peer named: the only ones probed and the only ones answered.
    allowed: HashSet<SocketAddr>,
    /// Rounds of probes sent so far; a reply must echo one of them.
    rounds_sent: u32,
    won: Option<oneshot::Sender<SocketAddr>>,
    replies: u32,
    last_reply: HashMap<SocketAddr, Instant>,
}

/// A punched route: its link and the receiving half of its tunnel.
struct Established {
    link: Arc<FramePipe>,
    tunnel: Tunnel,
    reader: FrameReader,
}

/// What one attempt needs.
pub struct PunchParams {
    pub id: u64,
    pub initiator: bool,
    pub keys: PunchKeys,
    /// The peer's candidates, as it named them (filtered here).
    pub candidates: Vec<SocketAddr>,
    /// The id the new route gets in its session.
    pub link_id: u32,
}

/// The hole-punching state of one relay socket.
pub struct PunchTable {
    socket: Arc<UdpSocket>,
    gateway: Option<SocketAddr>,
    relay_is_loopback: bool,
    attempts: Mutex<HashMap<u64, Active>>,
    routes: Mutex<HashMap<SocketAddr, Established>>,
}

impl PunchTable {
    /// The table for the socket a node is registered on a relay with. With a `gateway`, every
    /// datagram that is not for the relay goes through it, wrapped (see [`gateway_wrap`]).
    pub fn new(
        socket: Arc<UdpSocket>,
        gateway: Option<SocketAddr>,
        relay_is_loopback: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket,
            gateway,
            relay_is_loopback,
            attempts: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
        })
    }

    /// The gateway datagrams go through, if any.
    pub fn gateway(&self) -> Option<SocketAddr> {
        self.gateway
    }

    /// Whether the relay is on loopback (what [`acceptable_candidate`] is told).
    pub fn relay_is_loopback(&self) -> bool {
        self.relay_is_loopback
    }

    /// The port of the relay socket: the one every candidate of this node is on.
    pub fn local_port(&self) -> Option<u16> {
        self.socket.local_addr().ok().map(|a| a.port())
    }

    /// Send one datagram to a peer address, from the relay socket.
    fn send_to(&self, dest: SocketAddr, data: &[u8]) {
        let result = match self.gateway {
            Some(gateway) => self.socket.try_send_to(&gateway_wrap(dest, data), gateway),
            None => self.socket.try_send_to(data, dest),
        };
        if let Err(e) = result {
            // A datagram that did not go is a lost one; the next round sends again.
            tracing::debug!("[overlay punch] a datagram to {dest} was not sent: {e}");
        }
    }

    /// Take a datagram that arrived on the relay socket from `src` (already unwrapped when it
    /// came through the gateway). True when it was ours: a probe, or traffic of a punched route.
    /// Everything else is for the relay path.
    pub fn on_datagram(&self, src: SocketAddr, data: &[u8]) -> bool {
        if probe_shaped(data) {
            self.on_probe(src, data);
            return true;
        }
        let mut routes = self.routes.lock();
        let Some(est) = routes.get_mut(&src) else {
            return false;
        };
        if !est.link.is_open() {
            routes.remove(&src);
            return true;
        }
        // Only a datagram that opens under this route's keys counts; anything else from that
        // address is dropped without a word.
        if let Ok(plain) = est.tunnel.open(data) {
            for frame in est.reader.push(&plain) {
                est.link.push_frame(frame);
            }
        }
        true
    }

    fn on_probe(&self, src: SocketAddr, data: &[u8]) {
        let Some(id) = probe_id(data) else { return };
        let mut attempts = self.attempts.lock();
        let Some(active) = attempts.get_mut(&id) else {
            return;
        };
        // Only from an address the peer named, and only with a valid MAC from the other role.
        if !active.allowed.contains(&src) {
            return;
        }
        let Some(probe) = decode_probe(&active.keys, data) else {
            return;
        };
        if probe.id != id || probe.from_initiator == active.initiator {
            return;
        }
        match probe.kind {
            ProbeKind::Probe => {
                let now = Instant::now();
                let recent = active
                    .last_reply
                    .get(&src)
                    .is_some_and(|t| now.duration_since(*t) < REPLY_GAP);
                if recent || active.replies >= MAX_REPLIES {
                    return;
                }
                active.replies += 1;
                active.last_reply.insert(src, now);
                let reply = encode_probe(
                    &active.keys,
                    &Probe {
                        kind: ProbeKind::Reply,
                        from_initiator: active.initiator,
                        id,
                        seq: probe.seq,
                    },
                );
                self.send_to(src, &reply);
            }
            ProbeKind::Reply => {
                // It must answer a round we sent, and the first one to do so wins.
                if probe.seq < active.rounds_sent {
                    if let Some(won) = active.won.take() {
                        let _ = won.send(src);
                    }
                }
            }
        }
    }

    /// Register an attempt, so the peer's probes are answered from now on. Call it before the
    /// answer that tells the peer to start goes out; then [`Running::finish`] does the probing.
    pub fn begin(self: &Arc<Self>, params: PunchParams) -> Result<Running> {
        let allowed: HashSet<SocketAddr> = params
            .candidates
            .iter()
            .copied()
            .filter(|a| acceptable_candidate(*a, self.relay_is_loopback))
            .take(MAX_CANDIDATES)
            .collect();
        if allowed.is_empty() {
            return Err(OverlayError::protocol("the peer named no usable address"));
        }
        let (won_tx, won) = oneshot::channel();
        self.attempts.lock().insert(
            params.id,
            Active {
                keys: params.keys.clone(),
                initiator: params.initiator,
                allowed: allowed.clone(),
                rounds_sent: 0,
                won: Some(won_tx),
                replies: 0,
                last_reply: HashMap::new(),
            },
        );
        Ok(Running {
            table: self.clone(),
            params,
            allowed,
            won,
        })
    }

    /// The route over a punched address, registered so its datagrams reach it.
    fn establish(self: &Arc<Self>, addr: SocketAddr, params: &PunchParams) -> Arc<FramePipe> {
        let keys = LinkKeys::derive(&params.keys.link);
        let keys = if params.initiator {
            keys
        } else {
            keys.swapped()
        };
        let (link, mut outbound) = FramePipe::new(
            params.link_id,
            RouteKind::HolePunch,
            format!("udp://{addr}"),
            &keys,
        );
        link.mark_down();
        {
            let mut routes = self.routes.lock();
            routes.retain(|_, est| est.link.is_open());
            if routes.len() >= MAX_ESTABLISHED {
                let oldest = routes
                    .iter()
                    .min_by_key(|(_, est)| est.link.id())
                    .map(|(a, _)| *a);
                if let Some(old) = oldest.and_then(|a| routes.remove(&a)) {
                    old.link.close();
                }
            }
            if let Some(replaced) = routes.insert(
                addr,
                Established {
                    link: link.clone(),
                    tunnel: Tunnel::receiver(&keys),
                    reader: FrameReader::new(),
                },
            ) {
                replaced.link.close();
            }
        }
        let table = self.clone();
        let writer = link.clone();
        tokio::spawn(async move {
            while let Some(sealed) = outbound.recv().await {
                if !writer.is_open() {
                    break;
                }
                table.send_to(addr, &sealed);
            }
        });
        link
    }
}

impl Running {
    /// Probe every named address for about two seconds, and on the first authenticated reply
    /// return a link over it. The link starts marked down, so the session sends nothing on it
    /// before its own first ping has been answered.
    pub async fn finish(self) -> Result<Arc<FramePipe>> {
        let Running {
            table,
            params,
            allowed,
            mut won,
        } = self;
        let mut winner = None;
        for seq in 0..ROUNDS {
            if let Some(active) = table.attempts.lock().get_mut(&params.id) {
                active.rounds_sent = seq + 1;
            }
            let probe = encode_probe(
                &params.keys,
                &Probe {
                    kind: ProbeKind::Probe,
                    from_initiator: params.initiator,
                    id: params.id,
                    seq,
                },
            );
            for addr in &allowed {
                table.send_to(*addr, &probe);
            }
            if let Ok(answer) = tokio::time::timeout(ROUND_EVERY, &mut won).await {
                winner = answer.ok();
                break;
            }
        }
        if winner.is_none() {
            winner = match tokio::time::timeout(LATE_REPLY, &mut won).await {
                Ok(answer) => answer.ok(),
                Err(_) => None,
            };
        }
        // The attempt keeps answering the peer's probes a little longer: it may not have heard
        // our reply to the last one yet.
        let lingering = table.clone();
        let id = params.id;
        tokio::spawn(async move {
            tokio::time::sleep(LINGER).await;
            lingering.attempts.lock().remove(&id);
        });
        let Some(addr) = winner else {
            return Err(OverlayError::protocol(
                "no authenticated reply came back from any address the peer named",
            ));
        };
        Ok(table.establish(addr, &params))
    }
}

/// An attempt that is registered and about to probe (see [`PunchTable::begin`]).
pub struct Running {
    table: Arc<PunchTable>,
    params: PunchParams,
    allowed: HashSet<SocketAddr>,
    won: oneshot::Receiver<SocketAddr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> PunchKeys {
        PunchKeys::derive(7, &[1; 32], &[2; 32])
    }

    #[test]
    fn a_probe_round_trips_under_its_key_and_under_no_other() {
        let p = Probe {
            kind: ProbeKind::Probe,
            from_initiator: true,
            id: 7,
            seq: 3,
        };
        let wire = encode_probe(&keys(), &p);
        assert_eq!(wire.len(), PROBE_LEN);
        assert_eq!(decode_probe(&keys(), &wire), Some(p));
        // Another attempt's nonces, or a changed byte, do not authenticate.
        let other = PunchKeys::derive(7, &[1; 32], &[3; 32]);
        assert_eq!(decode_probe(&other, &wire), None);
        for i in 0..PROBE_LEN {
            let mut bad = wire;
            bad[i] ^= 1;
            assert_eq!(decode_probe(&keys(), &bad), None, "byte {i} is covered");
        }
    }

    #[test]
    fn a_probe_cannot_be_turned_into_a_reply_or_into_the_other_role() {
        let p = Probe {
            kind: ProbeKind::Probe,
            from_initiator: true,
            id: 7,
            seq: 0,
        };
        let mut wire = encode_probe(&keys(), &p);
        wire[4] = 3; // claim to be the initiator's reply
        assert_eq!(decode_probe(&keys(), &wire), None);
        wire[4] = 2; // claim to be the responder's probe
        assert_eq!(decode_probe(&keys(), &wire), None);
    }

    #[test]
    fn a_probe_is_shorter_than_any_sealed_frame() {
        // header(20) + tag(16) + counter(8) + length(4)
        const { assert!(PROBE_LEN < 20 + 16 + 8 + 4) };
    }

    #[test]
    fn only_plausible_addresses_are_accepted_as_candidates() {
        let ok = |s: &str, lo: bool| acceptable_candidate(s.parse().expect("an address"), lo);
        assert!(ok("203.0.113.5:4000", false));
        assert!(ok("192.168.1.20:4000", false));
        assert!(!ok("203.0.113.5:0", false));
        assert!(!ok("0.0.0.0:4000", false));
        assert!(!ok("224.0.0.1:4000", false));
        assert!(!ok("169.254.1.1:4000", false));
        assert!(
            !ok("127.0.0.1:4000", false),
            "our own services are not a peer"
        );
        assert!(
            ok("127.0.0.1:4000", true),
            "unless the relay is on this machine too"
        );
        assert!(!ok("[fe80::1]:4000", false));
        assert!(ok("[2001:db8::1]:4000", false));
    }

    #[test]
    fn the_gateway_envelope_round_trips() {
        for addr in ["10.1.2.3:99", "[2001:db8::5]:4242"] {
            let addr: SocketAddr = addr.parse().expect("an address");
            let wrapped = gateway_wrap(addr, b"payload");
            assert_eq!(gateway_unwrap(&wrapped), Some((addr, &b"payload"[..])));
        }
        assert_eq!(gateway_unwrap(b"TDGW"), None);
        assert_eq!(gateway_unwrap(b"not wrapped at all"), None);
    }
}
