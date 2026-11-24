//! A userspace NAT on loopback, and the helpers the hole-punching tests share.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use transferd_overlay::punch::{gateway_unwrap, gateway_wrap, probe_shaped};
use transferd_overlay::OverlayNode;

use super::{base, TestNode};

/// How a [`Nat`] maps and filters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NatKind {
    /// Port-restricted cone: one outside port per inside socket, whoever it talks to; a datagram
    /// is let in only from an address:port the inside socket has already sent to.
    PortRestrictedCone,
    /// Symmetric: a new outside port for every destination, and only that destination may answer.
    Symmetric,
}

/// A NAT on loopback, in front of one node.
///
/// A real NAT is a router and a node's datagrams simply cross it; on loopback there is no router,
/// so the node is told to send everything that is not for the relay through this NAT's inside
/// port, wrapped with its real destination (`OverlayConfig::udp_gateway`). Datagrams for the
/// relay need no wrapping: the NAT forwards them to the relay it was started with.
///
/// Outbound datagrams create the mapping; inbound ones are filtered as the kind says, and a
/// datagram that does not pass is dropped without a word.
pub struct Nat {
    /// The address the node uses as its relay and as its gateway.
    pub inside: SocketAddr,
    front: Arc<UdpSocket>,
    state: Arc<Mutex<NatState>>,
}

#[derive(Default)]
struct NatState {
    host: Option<SocketAddr>,
    stranger: Option<SocketAddr>,
    replayed: usize,
    /// The outside addresses handed out so far.
    outside: Vec<SocketAddr>,
}

type Allowed = Arc<Mutex<HashSet<SocketAddr>>>;

impl Nat {
    /// Start a NAT of `kind` in front of a node whose relay is `relay`.
    pub async fn start(relay: SocketAddr, kind: NatKind) -> Nat {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("nat binds"));
        let inside = front.local_addr().expect("nat address");
        let state: Arc<Mutex<NatState>> = Arc::default();
        let (loop_front, loop_state) = (front.clone(), state.clone());
        tokio::spawn(async move {
            let mut maps: HashMap<(SocketAddr, Option<SocketAddr>), (Arc<UdpSocket>, Allowed)> =
                HashMap::new();
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, host)) = loop_front.recv_from(&mut buf).await else {
                    continue;
                };
                loop_state.lock().unwrap().host = Some(host);
                let (dest, payload) = match gateway_unwrap(&buf[..n]) {
                    Some((dest, inner)) => (dest, inner.to_vec()),
                    None => (relay, buf[..n].to_vec()),
                };
                let key = match kind {
                    NatKind::PortRestrictedCone => (host, None),
                    NatKind::Symmetric => (host, Some(dest)),
                };
                #[allow(clippy::map_entry)] // the socket is bound with an await in between
                if !maps.contains_key(&key) {
                    let out = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("nat binds"));
                    loop_state
                        .lock()
                        .unwrap()
                        .outside
                        .push(out.local_addr().expect("outside address"));
                    let allowed: Allowed = Arc::default();
                    tokio::spawn(inbound(
                        out.clone(),
                        loop_front.clone(),
                        allowed.clone(),
                        loop_state.clone(),
                        relay,
                        host,
                    ));
                    maps.insert(key, (out, allowed));
                }
                let (out, allowed) = &maps[&key];
                allowed.lock().unwrap().insert(dest);
                let _ = out.send_to(&payload, dest).await;
            }
        });
        Nat {
            inside,
            front,
            state,
        }
    }

    /// Replay every probe that reaches the node, also from `stranger`.
    pub fn replay_probes_from(&self, stranger: SocketAddr) {
        self.state.lock().unwrap().stranger = Some(stranger);
    }

    /// How many probes have been replayed so far.
    pub fn replayed(&self) -> usize {
        self.state.lock().unwrap().replayed
    }

    /// Hand the node a datagram as if `from` had sent it, past the filter (an attacker on the
    /// path, or on the inside, who is not stopped by the NAT).
    pub async fn inject(&self, from: SocketAddr, data: &[u8]) {
        let host = self.state.lock().unwrap().host.expect("the node has sent");
        let wrapped = gateway_wrap(from, data);
        self.front.send_to(&wrapped, host).await.expect("injects");
    }

    /// The outside addresses this NAT has handed out.
    pub fn outside(&self) -> Vec<SocketAddr> {
        self.state.lock().unwrap().outside.clone()
    }
}

/// One mapping's outside socket: let in what the filter allows, hand it to the inside host.
async fn inbound(
    outside: Arc<UdpSocket>,
    front: Arc<UdpSocket>,
    allowed: Allowed,
    state: Arc<Mutex<NatState>>,
    relay: SocketAddr,
    host: SocketAddr,
) {
    let mut buf = vec![0u8; 65_536];
    loop {
        // An ICMP "port unreachable" for an earlier datagram (the relay went away) surfaces as an
        // error on this socket on Windows; it is no reason to stop listening.
        let Ok((n, from)) = outside.recv_from(&mut buf).await else {
            continue;
        };
        // The filter: only an address:port the inside already sent to.
        if !allowed.lock().unwrap().contains(&from) {
            continue;
        }
        let data = &buf[..n];
        let delivered = if from == relay {
            data.to_vec()
        } else {
            gateway_wrap(from, data)
        };
        let _ = front.send_to(&delivered, host).await;
        // A stranger who copies a probe off the wire and replays it at the node, from an address
        // the node was never told about.
        let stranger = state.lock().unwrap().stranger;
        if let (Some(stranger), true) = (stranger, probe_shaped(data)) {
            state.lock().unwrap().replayed += 1;
            let _ = front.send_to(&gateway_wrap(stranger, data), host).await;
        }
    }
}

impl TestNode {
    /// Like [`TestNode::behind`], but speaking at most protocol version `max_version`.
    pub async fn behind_speaking(name: &str, nat: &Nat, max_version: u8) -> TestNode {
        let mut config = base(name, &[nat.inside]);
        config.udp_gateway = Some(nat.inside);
        config.max_version = max_version;
        TestNode {
            node: OverlayNode::start(config).await.expect("the node starts"),
        }
    }

    /// Start a node behind `nat`: its relay is reached through the NAT, and so is every
    /// datagram it sends to a peer.
    pub async fn behind(name: &str, nat: &Nat) -> TestNode {
        let mut config = base(name, &[nat.inside]);
        config.udp_gateway = Some(nat.inside);
        TestNode {
            node: OverlayNode::start(config).await.expect("the node starts"),
        }
    }
}

/// The kinds of a node's first peer's routes, and whether each is up.
pub fn route_states(node: &OverlayNode) -> Vec<(String, bool)> {
    node.peer_list()
        .first()
        .and_then(|p| p["routes"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .map(|r| {
            (
                r["kind"].as_str().unwrap_or_default().to_string(),
                r["active"] == true,
            )
        })
        .collect()
}

/// An echo that sends back exactly what it reads.
pub async fn plain_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}
