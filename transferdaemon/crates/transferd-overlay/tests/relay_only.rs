//! Three nodes, none of which can be dialled, still reach each other.
//!
//! This is the case the whole overlay exists for: every node binds **no listener at all**, so
//! there is nothing for a firewall, a router or a NAT to allow. Each one registers with the
//! relay it can reach — and the relay forwards their traffic between the mappings those
//! outbound registrations created.

mod common;

use common::{TestNode, TestRelay, echo_service, eventually, read_exact};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Two nodes with no listener reach each other and move real bytes through a real service.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn two_nodes_with_no_inbound_listener_reach_each_other_through_a_relay() {
    common::trace();
    let relay = TestRelay::start().await;
    let server = echo_service(0xA1).await;

    let alice = TestNode::inbound_only("alice", &[relay.addr]).await;
    let bob = TestNode::inbound_only("bob", &[relay.addr]).await;
    alice.pair_with(&bob, "bob");
    bob.pair_with(&alice, "alice");

    // Neither of them is listening: the only path is the relay.
    assert!(alice.node.listener_addr().is_none());
    assert!(bob.node.listener_addr().is_none());

    bob.node
        .expose("echo", server, vec!["*paired".into()], "a real TCP service")
        .expect("bob publishes a service");

    let (local, route) = alice.node.connect(&bob.id(), "echo").await.expect("alice reaches bob");
    assert_eq!(route, transferd_overlay::RouteKind::Relay, "the relay is the route");

    let mut stream = tokio::net::TcpStream::connect(local).await.expect("the endpoint listens");
    stream.write_all(b"through the relay").await.expect("write");
    let echo = read_exact(&mut stream, 18).await;
    assert_eq!(&echo, b"\xA1through the relay");

    // The relay really did the work: both tokens are registered there.
    assert!(relay.registered().await >= 2, "both nodes registered their token");

    // Disconnecting closes the endpoint for real: nothing listens there any more.
    drop(stream);
    alice.node.disconnect(local).expect("disconnect");
    eventually("the endpoint to stop listening", || async { tokio::net::TcpStream::connect(local).await.is_err() }).await;
}

/// Three nodes where the middle one also serves as the relay for the other two.
///
/// The requirement is that "any paired node that is reachable may serve as a relay for the
/// rest", so here the relay process is not a separate binary: `relayd`'s own relay logic runs
/// alongside the node that the other two pair with.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn three_nodes_reach_each_other_with_a_paired_node_serving_as_the_relay() {
    let hub = TestNode::with_listener("hub", &[]).await;
    // The hub node runs the relay: the same relayd logic, on its own socket.
    let relay = TestRelay::start().await;
    let edge_one = TestNode::inbound_only("edge-1", &[relay.addr]).await;
    let edge_two = TestNode::inbound_only("edge-2", &[relay.addr]).await;

    // Each edge pairs with the hub, and through the hub's relay with the other edge.
    edge_one.pair_with(&hub, "hub");
    edge_two.pair_with(&hub, "hub");
    let invite = edge_one.node.invite_create(600);
    edge_two.node.invite_accept(&invite, Some("edge-1".into())).expect("the edges pair through the hub");
    hub.node.expose("hello", echo_service(0xB2).await, vec!["*paired".into()], "").expect("hub exposes");

    // Edge two reaches the hub's service with no listener of its own anywhere in the path.
    let (local, _route) = edge_two.node.connect(&hub.id(), "hello").await.expect("edge two reaches the hub");
    let mut stream = tokio::net::TcpStream::connect(local).await.expect("listening");
    stream.write_all(b"hi").await.expect("write");
    let echo = read_exact(&mut stream, 3).await;
    assert_eq!(&echo, b"\xB2hi", "the service answered through the overlay");

    // And the edge that serves nothing can still be reached by the other edge.
    edge_one.node.expose("log", echo_service(0xC3).await, vec!["*paired".into()], "").expect("edge one exposes");
    let (log_local, _) = edge_two.node.connect(&edge_one.id(), "log").await.expect("edge two reaches edge one");
    let mut stream = tokio::net::TcpStream::connect(log_local).await.expect("listening");
    stream.write_all(b"entry").await.expect("write");
    let echo = read_exact(&mut stream, 6).await;
    assert_eq!(&echo, b"\xC3entry");
}

/// A node with no inbound listener is still reachable *inbound* by a peer that dials it
/// through the relay — the session is dialled by the peer, answered by the mapping the
/// victim's own registration created.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn a_node_with_no_listener_accepts_a_session_dialed_through_the_relay() {
    let relay = TestRelay::start().await;
    let server = echo_service(0xD4).await;

    let server_node = TestNode::inbound_only("server", &[relay.addr]).await;
    let client_node = TestNode::inbound_only("client", &[relay.addr]).await;
    client_node.pair_with(&server_node, "server");
    server_node.pair_with(&client_node, "client");
    server_node.node.expose("api", server, vec!["*paired".into()], "").expect("expose");

    let (local, _) = client_node.node.connect(&server_node.id(), "api").await.expect("the client dials");
    let mut stream = tokio::net::TcpStream::connect(local).await.expect("listening");
    stream.write_all(b"inbound").await.expect("write");
    let echo = read_exact(&mut stream, 8).await;
    assert_eq!(&echo, b"\xD4inbound");

    // The server never listened: its own session came in over the relay.
    assert!(server_node.node.listener_addr().is_none());
}

/// A relay that dies takes the relayed path down, and the nodes report it rather than hanging.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn a_relay_that_stops_being_reachable_is_reported_not_hung() {
    let relay = TestRelay::start().await;
    let a = TestNode::inbound_only("a", &[relay.addr]).await;
    let b = TestNode::inbound_only("b", &[relay.addr]).await;
    a.pair_with(&b, "b");
    b.pair_with(&a, "a");
    b.node.expose("svc", echo_service(0xE5).await, vec!["*paired".into()], "").expect("expose");
    let (local, _) = a.node.connect(&b.id(), "svc").await.expect("the route comes up");

    // The path works.
    let mut stream = tokio::net::TcpStream::connect(local).await.expect("listening");
    stream.write_all(b"alive").await.expect("write");
    assert_eq!(&read_exact(&mut stream, 6).await, b"\xE5alive");

    // When the relay is gone the session stops carrying traffic, and `overlay.peers` says so
    // instead of the node pretending it is fine.
    relay.stop();
    eventually("the relayed route to be reported down", || async {
        let peers = a.node.peer_list();
        peers.len() == 1
            && peers[0]["routes"]
                .as_array()
                .map(|routes| !routes.is_empty() && routes.iter().all(|r| r["active"] == false))
                .unwrap_or(false)
    })
    .await;
}

/// A session started with a stale invite still works, because the transport is what decides.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn a_pairing_survives_nodes_with_no_stored_state() {
    // Two nodes with no state file at all (the default): pairing and routing still work,
    // because reachability never came from stored state in the first place.
    let relay = TestRelay::start().await;
    let a = TestNode::inbound_only("a", &[relay.addr]).await;
    let b = TestNode::inbound_only("b", &[relay.addr]).await;
    a.pair_with(&b, "b");
    b.node.expose("x", echo_service(1).await, vec![a.id()], "").expect("expose to a only");
    let (local, _) = a.node.connect(&b.id(), "x").await.expect("reachable");
    let mut s = tokio::net::TcpStream::connect(local).await.expect("listening");
    s.write_all(b"ok").await.expect("write");
    let mut buf = [0u8; 3];
    tokio::time::timeout(common::PATIENCE, s.read_exact(&mut buf)).await.expect("in time").expect("read");
    assert_eq!(&buf, b"\x01ok");
}
/// A service exposed after the session is up is reachable at once, and one withdrawn is
/// refused by name: the peer re-announces what it offers, and its answer to an open decides.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn a_service_exposed_after_the_session_came_up_is_reachable() {
    let relay = TestRelay::start().await;
    let a = TestNode::inbound_only("a", &[relay.addr]).await;
    let b = TestNode::inbound_only("b", &[relay.addr]).await;
    a.pair_with(&b, "b");
    b.pair_with(&a, "a");
    b.node.expose("first", echo_service(1).await, vec!["*paired".into()], "").expect("expose");
    a.node.connect(&b.id(), "first").await.expect("the session comes up");

    b.node.expose("later", echo_service(2).await, vec!["*paired".into()], "").expect("expose later");
    let (local, _) = a.node.connect(&b.id(), "later").await.expect("reachable without a new session");
    let mut s = tokio::net::TcpStream::connect(local).await.expect("listening");
    s.write_all(b"hi").await.expect("write");
    assert_eq!(&read_exact(&mut s, 3).await, b"\x02hi");

    b.node.unexpose("later").expect("withdrawn");
    let err = a.node.connect(&b.id(), "gone").await.expect_err("nothing by that name");
    assert_eq!(err.code(), "no_such_service", "{err}");
    eventually("a to learn what b offers now", || async {
        a.node.peer_list()[0]["services"].as_array().is_some_and(|s| s.len() == 1)
    })
    .await;
}
