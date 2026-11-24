//! The harness every overlay integration test builds on: real sockets, real relay, real nodes.
//!
//! Nothing here is a stand-in for the thing under test. The relay is `relayd`'s own state
//! machine served on a real UDP socket; the nodes are real `OverlayNode`s that register with
//! it, dial each other through it, and serve real TCP endpoints on loopback.
//!
//! The one thing the tests *do* control is reachability: a node with `listen: None` binds no
//! inbound overlay listener at all, which is exactly the situation behind a NAT.

// Shared by every test target; each uses only part of it.
#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use relayd::relay::Relay;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use transferd_overlay::{NodeIdentity, OverlayConfig, OverlayNode};

mod nat;
mod shaper;
#[allow(unused_imports)]
pub use nat::{plain_echo, route_states, Nat, NatKind};
#[allow(unused_imports)]
pub use shaper::{Shaped, ShaperStats};

/// How long an integration test waits for something that should already have happened.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// A relay running `relayd`'s own logic on a real UDP socket.
///
/// Difficulty 0 keeps the tests fast; everything else about the relay is the production path
/// (proof of work, registration TTL, blind forwarding, bandwidth accounting).
pub struct TestRelay {
    pub addr: SocketAddr,
    core: Arc<Mutex<Relay>>,
    serving: tokio::task::JoinHandle<()>,
}

impl TestRelay {
    /// Start a relay on an ephemeral loopback port.
    pub async fn start() -> TestRelay {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("relay binds");
        // As relayd does: room for a window's burst.
        transferd_core::lanes::relay_client::widen_buffers(&socket);
        let addr = socket.local_addr().expect("relay address");
        let mut relay = Relay::new(0, 300, 64 * 1024);
        // Every test node is 127.0.0.1, so relayd's per-IP budget (300 datagrams per 30 s, sized for
        // messaging) would be shared by all of them; a relay carrying overlay traffic raises it.
        relay.set_rate_limit(30, 1_000_000);
        let core = Arc::new(Mutex::new(relay));
        let table = core.clone();
        let reader = Arc::new(socket);
        let serving = tokio::spawn(async move {
            relayd::server::serve(reader, table).await;
        });
        TestRelay {
            addr,
            core,
            serving,
        }
    }

    /// How many tokens are registered here right now.
    pub async fn registered(&self) -> usize {
        self.core.lock().await.active_count()
    }

    /// Stop serving, the way a relay that crashed or lost its network does: the socket closes
    /// and every route through it dies at once.
    pub fn stop(&self) {
        self.serving.abort();
    }
}

/// A node in the test overlay.
pub struct TestNode {
    pub node: Arc<OverlayNode>,
}

impl TestNode {
    /// Start a node with no listener at all: it can only be reached the way a node behind a
    /// NAT can — through a relay it registered with.
    pub async fn inbound_only(name: &str, relays: &[SocketAddr]) -> TestNode {
        TestNode::build(name, relays, None).await
    }

    /// Start a node that also publishes a direct listener (the LAN / tailnet case).
    pub async fn with_listener(name: &str, relays: &[SocketAddr]) -> TestNode {
        TestNode::build(name, relays, Some("127.0.0.1:0")).await
    }

    /// Start a node that publishes `direct` addresses (a routable peer).
    pub async fn publishing(name: &str, relays: &[SocketAddr], direct: Vec<String>) -> TestNode {
        let mut config = base(name, relays);
        config.direct = direct;
        TestNode {
            node: OverlayNode::start(config).await.expect("the node starts"),
        }
    }

    async fn build(name: &str, relays: &[SocketAddr], listen: Option<&str>) -> TestNode {
        let mut config = base(name, relays);
        config.listen = listen.and_then(|l| l.parse().ok());
        TestNode {
            node: OverlayNode::start(config).await.expect("the node starts"),
        }
    }

    /// This node's id.
    pub fn id(&self) -> String {
        self.node.node_id()
    }

    /// Pair with `other` using its signed invite.
    pub fn pair_with(&self, other: &TestNode, name: &str) {
        let invite = other.node.invite_create(600);
        self.node
            .invite_accept(&invite, Some(name.to_string()))
            .unwrap_or_else(|e| panic!("{name} pairs with {}: {e}", other.id()));
    }

    /// Publish the addresses this node can be dialled on directly.
    pub fn publish_direct(&self, addrs: Vec<String>) {
        for addr in addrs {
            self.node.set_direct(addr);
        }
    }
}

/// Start a real TCP echo service on loopback, for something to expose.
pub async fn echo_service(tag: u8) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo binds");
    let addr = listener.local_addr().expect("echo address");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let mut out = vec![tag];
                    out.extend_from_slice(&buf[..n]);
                    if tokio::io::AsyncWriteExt::write_all(&mut socket, &out)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Read exactly `n` bytes from a TCP endpoint, or fail the test.
pub async fn read_exact(stream: &mut tokio::net::TcpStream, n: usize) -> Vec<u8> {
    use tokio::io::AsyncReadExt as _;
    let mut buf = vec![0u8; n];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut buf))
        .await
        .expect("the endpoint answers in time")
        .expect("the endpoint answers");
    buf
}

/// Wait until an async `check` is true, or fail with `what`.
pub async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

fn base(name: &str, relays: &[SocketAddr]) -> OverlayConfig {
    OverlayConfig {
        relays: relays.iter().map(|a| a.to_string()).collect(),
        ..OverlayConfig::local(NodeIdentity::generate(name))
    }
}

/// Turn on the overlay's log output, so a failing test says why.
pub fn trace() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("TD_OVERLAY_TRACE")
                .unwrap_or_else(|_| "transferd_overlay=trace".to_string()),
        )
        .with_test_writer()
        .try_init();
}
/// A UDP forwarder in front of a relay that drops a share of the datagrams both ways: what a
/// congested Wi-Fi link or an overflowing socket buffer does to the relayed path.
pub struct Lossy {
    pub addr: SocketAddr,
}

impl Lossy {
    /// Forward to `relay`, dropping `percent` of the datagrams in each direction.
    pub async fn start(relay: SocketAddr, percent: u32) -> Lossy {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("binds"));
        let addr = front.local_addr().expect("addr");
        tokio::spawn(async move {
            // One socket towards the relay per client, so the relay still sees each client apart.
            let mut backs: std::collections::HashMap<SocketAddr, Arc<UdpSocket>> =
                std::collections::HashMap::new();
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, client)) = front.recv_from(&mut buf).await else {
                    continue;
                };
                let back = match backs.get(&client) {
                    Some(b) => b.clone(),
                    None => {
                        let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("binds"));
                        let (to_client, from_relay) = (front.clone(), b.clone());
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65_536];
                            while let Ok((n, _)) = from_relay.recv_from(&mut buf).await {
                                if rand::random::<u32>() % 100 >= percent {
                                    let _ = to_client.send_to(&buf[..n], client).await;
                                }
                            }
                        });
                        backs.insert(client, b.clone());
                        b
                    }
                };
                if rand::random::<u32>() % 100 >= percent {
                    let _ = back.send_to(&buf[..n], relay).await;
                }
            }
        });
        Lossy { addr }
    }
}
