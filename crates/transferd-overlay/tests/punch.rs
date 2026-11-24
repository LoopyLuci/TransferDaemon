//! UDP hole punching, through userspace NATs on loopback.
//!
//! Each node sits behind a NAT emulator (`common::Nat`) that creates a mapping for an outbound
//! datagram and lets an inbound one in only as its kind allows. Two port-restricted cone NATs can
//! be punched; a symmetric NAT cannot, and the relay has to keep working when it is not.

// Test code: a failed expectation is a panic, and that is the point.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{eventually, plain_echo, route_states, Nat, NatKind, TestNode, TestRelay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use transferd_overlay::{OverlayNode, RouteKind};

/// Two nodes behind NATs of the given kinds, paired, with `b` offering an echo service.
async fn pair_behind(
    relay: &TestRelay,
    kind_a: NatKind,
    kind_b: NatKind,
) -> (TestNode, TestNode, Nat, Nat, SocketAddr) {
    common::trace();
    let nat_a = Nat::start(relay.addr, kind_a).await;
    let nat_b = Nat::start(relay.addr, kind_b).await;
    let a = TestNode::behind("a", &nat_a).await;
    let b = TestNode::behind("b", &nat_b).await;
    a.pair_with(&b, "b");
    b.pair_with(&a, "a");
    let echo = plain_echo().await;
    b.node
        .expose("echo", echo, vec!["*paired".into()], "")
        .expect("expose");
    (a, b, nat_a, nat_b, echo)
}

fn has_route(node: &OverlayNode, kind: &str, up: bool) -> bool {
    route_states(node)
        .iter()
        .any(|(k, u)| k == kind && *u == up)
}

fn failed(node: &OverlayNode) -> bool {
    node.events()
        .recent(200)
        .iter()
        .any(|e| e.kind == "route.change" && e.detail.starts_with("holepunch failed"))
}

/// Send `data` through the endpoint and read the same number of bytes back.
async fn round_trip(local: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut app = tokio::net::TcpStream::connect(local)
        .await
        .expect("endpoint");
    let (mut read, mut write) = app.split();
    let send = async {
        write.write_all(data).await.expect("write");
        write.flush().await.expect("flush");
    };
    let mut back = vec![0u8; data.len()];
    let receive = async {
        tokio::time::timeout(common::PATIENCE, read.read_exact(&mut back))
            .await
            .expect("the echo comes back in time")
            .expect("the echo comes back");
    };
    tokio::join!(send, receive);
    back
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + i / 251) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_cone_nats_get_a_punched_route_beside_the_relay_and_a_stream_crosses_it() {
    let relay = TestRelay::start().await;
    let (a, b, _nat_a, _nat_b, _echo) = pair_behind(
        &relay,
        NatKind::PortRestrictedCone,
        NatKind::PortRestrictedCone,
    )
    .await;

    let (local, route) = a.node.connect(&b.id(), "echo").await.expect("connect");
    assert_eq!(
        route,
        RouteKind::Relay,
        "neither node has a listener: the relay it is"
    );

    // Both ends gain the route, and the relay stays beside it.
    eventually("a punched route on both nodes", || async {
        has_route(&a.node, "holepunch", true) && has_route(&b.node, "holepunch", true)
    })
    .await;
    assert!(
        has_route(&a.node, "relay", true),
        "the relay route is still there"
    );
    assert!(has_route(&b.node, "relay", true));
    assert!(!failed(&a.node) && !failed(&b.node));

    // A megabyte and a half crosses, byte for byte.
    let data = pattern(1_500_000);
    assert_eq!(round_trip(local, &data).await, data, "the stream is intact");

    // The punched route carries traffic on its own: with the relay gone, a stream still works
    // (the nodes need no relay once they hold a direct path).
    relay.stop();
    let data = pattern(600_000);
    assert_eq!(
        round_trip(local, &data).await,
        data,
        "the stream crosses the punched route alone"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_symmetric_nat_cannot_be_punched_and_the_relay_keeps_working() {
    let relay = TestRelay::start().await;
    let (a, b, _nat_a, _nat_b, _echo) =
        pair_behind(&relay, NatKind::Symmetric, NatKind::PortRestrictedCone).await;

    let (local, _) = a.node.connect(&b.id(), "echo").await.expect("connect");
    // The attempt runs to its end on both sides and says so.
    eventually("both sides to give up", || async {
        failed(&a.node) && failed(&b.node)
    })
    .await;
    assert!(
        !route_states(&a.node).iter().any(|(k, _)| k == "holepunch"),
        "no punched route on a: {:?}",
        route_states(&a.node)
    );
    assert!(!route_states(&b.node).iter().any(|(k, _)| k == "holepunch"));
    assert!(
        has_route(&a.node, "relay", true),
        "the relay route is untouched"
    );

    let data = pattern(300_000);
    assert_eq!(
        round_trip(local, &data).await,
        data,
        "the stream still works over the relay"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_strangers_probe_is_ignored_and_never_answered() {
    let relay = TestRelay::start().await;
    let (a, b, nat_a, _nat_b, _echo) = pair_behind(
        &relay,
        NatKind::PortRestrictedCone,
        NatKind::PortRestrictedCone,
    )
    .await;
    // The stranger listens where a node's reply would arrive; every probe that reaches `a` is
    // also delivered to it as if the stranger had sent it (valid MAC and all).
    let stranger = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("stranger binds");
    let stranger_addr = stranger.local_addr().expect("addr");
    nat_a.replay_probes_from(stranger_addr);

    a.node.connect(&b.id(), "echo").await.expect("connect");
    eventually("the punch to succeed in spite of the stranger", || async {
        has_route(&a.node, "holepunch", true) && has_route(&b.node, "holepunch", true)
    })
    .await;
    assert!(nat_a.replayed() > 0, "the stranger did replay probes");

    // Noise that merely looks like a probe is not answered either.
    let mut noise = b"TDPB".to_vec();
    noise.extend_from_slice(&[7u8; 29]);
    nat_a.inject(stranger_addr, &noise).await;
    nat_a.inject(stranger_addr, b"TDPB").await;

    // Nothing was ever sent back to the stranger's address, and the punched route is unharmed.
    let mut buf = [0u8; 2048];
    let heard =
        tokio::time::timeout(Duration::from_millis(800), stranger.recv_from(&mut buf)).await;
    assert!(heard.is_err(), "the node answered a stranger: {heard:?}");
    assert!(has_route(&a.node, "holepunch", true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_agreed_on_an_older_version_is_never_sent_a_punch_frame() {
    common::trace();
    let relay = TestRelay::start().await;
    let nat_a = Nat::start(relay.addr, NatKind::PortRestrictedCone).await;
    let nat_b = Nat::start(relay.addr, NatKind::PortRestrictedCone).await;
    let a = TestNode::behind("a", &nat_a).await;
    // b stops at version 2, before hole punching existed: it would not acknowledge CANDIDATE.
    let b = TestNode::behind_speaking("b", &nat_b, 2).await;
    a.pair_with(&b, "b");
    b.pair_with(&a, "a");
    b.node
        .expose("echo", plain_echo().await, vec!["*paired".into()], "")
        .expect("expose");

    let (local, _) = a.node.connect(&b.id(), "echo").await.expect("connect");
    assert_eq!(a.node.peer_list()[0]["protocol_version"], 2);
    // Long enough for a whole attempt to have run, had one been started.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!route_states(&a.node).iter().any(|(k, _)| k == "holepunch"));
    assert!(!failed(&a.node) && !failed(&b.node), "no attempt was made");
    let data = pattern(100_000);
    assert_eq!(round_trip(local, &data).await, data);
}
