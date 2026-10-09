//! Paths, failover, access control, the proxies, groups and versions, over real sockets.
//!
//! * a direct path is preferred when a peer publishes one, and the relay is added beside it;
//! * a stream survives its route dying in the middle: the application's TCP connection carries
//!   on over the other route;
//! * a node outside a service's access list is refused (and the refusal is audited);
//! * SOCKS5 and HTTP CONNECT reach `<service>.<node>.td`;
//! * a service group spreads connections over the nodes that offer it;
//! * an older and a newer peer each agree on the highest version both speak.

// Test code: a failed expectation is a panic, and that is the point.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::{echo_service, eventually, read_exact, TestNode, TestRelay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use transferd_overlay::{NodeIdentity, OverlayConfig, OverlayNode, RouteKind};

/// A TCP forwarder in front of an address, which can be cut: every connection through it dies
/// at once, the way a LAN path does when a cable is pulled or a laptop changes network.
struct Cuttable {
    addr: SocketAddr,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Cuttable {
    async fn start(target: SocketAddr) -> Cuttable {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let addr = listener.local_addr().expect("addr");
        let tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::default();
        let held = tasks.clone();
        let accept = tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    break;
                };
                let Ok(server) = tokio::net::TcpStream::connect(target).await else {
                    continue;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                let up = tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut cr, &mut sw).await;
                });
                let down = tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut sr, &mut cw).await;
                });
                held.lock().await.extend([up, down]);
            }
        });
        tasks.lock().await.push(accept);
        Cuttable { addr, tasks }
    }

    async fn cut(&self) {
        for task in self.tasks.lock().await.drain(..) {
            task.abort();
        }
    }
}

fn routes(node: &OverlayNode) -> Vec<(String, bool)> {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_path_is_preferred_and_a_stream_survives_it_dying() {
    common::trace();
    let relay = TestRelay::start().await;
    let a = TestNode::inbound_only("a", &[relay.addr]).await;
    let b = TestNode::with_listener("b", &[relay.addr]).await;
    // b's direct path goes through a forwarder the test can cut.
    let lan = Cuttable::start(b.node.listener_addr().expect("b listens")).await;
    b.node.set_direct(lan.addr.to_string());
    a.pair_with(&b, "b");
    b.pair_with(&a, "a");
    b.node
        .expose("echo", echo_service(0x5a).await, vec!["*paired".into()], "")
        .expect("expose");

    let (local, route) = a.node.connect(&b.id(), "echo").await.expect("connect");
    assert_eq!(
        route,
        RouteKind::Lan,
        "the published direct (LAN) address is tried first"
    );
    eventually("the relay to be added as a second route", || async {
        let r = routes(&a.node);
        r.len() == 2 && r.iter().any(|(k, _)| k == "relay")
    })
    .await;

    let mut app = tokio::net::TcpStream::connect(local)
        .await
        .expect("endpoint");
    app.write_all(b"before").await.expect("write");
    assert_eq!(&read_exact(&mut app, 7).await, b"\x5abefore");

    // The direct path dies in the middle of the stream ...
    lan.cut().await;
    // ... and the same TCP connection keeps working, over the relay.
    app.write_all(b"after").await.expect("write after the cut");
    assert_eq!(
        &read_exact(&mut app, 6).await,
        b"\x5aafter",
        "the stream carried on over the other route"
    );
    eventually("the dead route to be reported down", || async {
        routes(&a.node).iter().any(|(k, up)| k == "lan" && !*up)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_outside_the_access_list_is_refused_and_it_is_audited() {
    let relay = TestRelay::start().await;
    let owner = TestNode::inbound_only("owner", &[relay.addr]).await;
    let friend = TestNode::inbound_only("friend", &[relay.addr]).await;
    let other = TestNode::inbound_only("other", &[relay.addr]).await;
    for n in [&friend, &other] {
        n.pair_with(&owner, "owner");
        owner.pair_with(n, "peer");
    }
    owner
        .node
        .expose("private", echo_service(1).await, vec![friend.id()], "")
        .expect("expose to friend only");

    friend
        .node
        .connect(&owner.id(), "private")
        .await
        .expect("the friend is let in");
    let err = other
        .node
        .connect(&owner.id(), "private")
        .await
        .expect_err("the other node is not");
    assert_eq!(err.code(), "denied", "{err}");
    let audit = transferd_overlay::ops::call(&owner.node, "overlay.audit", serde_json::json!({}))
        .await
        .expect("audit");
    assert!(
        audit
            .as_array()
            .expect("records")
            .iter()
            .any(|r| r["action"] == "denied" && r["peer"] == other.id()),
        "the refusal is in the audit trail: {audit}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_and_http_connect_reach_a_service_by_name() {
    let relay = TestRelay::start().await;
    let a = TestNode::inbound_only("a", &[relay.addr]).await;
    let b = TestNode::inbound_only("b", &[relay.addr]).await;
    a.pair_with(&b, "laptop");
    b.pair_with(&a, "a");
    b.node
        .expose("web", echo_service(0x77).await, vec!["*paired".into()], "")
        .expect("expose");
    let (socks, http) = a.node.start_proxies().await.expect("proxies");

    // SOCKS5, by the name the node was paired under.
    let mut s = tokio::net::TcpStream::connect(socks).await.expect("socks");
    s.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await.expect("method");
    assert_eq!(reply, [5, 0]);
    let host = b"web.laptop.td";
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).await.expect("connect");
    let mut ok = [0u8; 10];
    tokio::time::timeout(common::PATIENCE, s.read_exact(&mut ok))
        .await
        .expect("in time")
        .expect("reply");
    assert_eq!(ok[1], 0, "SOCKS5 success");
    s.write_all(b"socks").await.expect("write");
    assert_eq!(&read_exact(&mut s, 6).await, b"\x77socks");

    // HTTP CONNECT, by a short prefix of the node id (a whole id is longer than a DNS label).
    let mut h = tokio::net::TcpStream::connect(http).await.expect("http");
    let target = format!("web.{}.td:443", &b.id()[..12]);
    h.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .expect("connect");
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        tokio::time::timeout(common::PATIENCE, h.read_exact(&mut byte))
            .await
            .expect("in time")
            .expect("read");
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    h.write_all(b"http").await.expect("write");
    assert_eq!(&read_exact(&mut h, 5).await, b"\x77http");

    // A name that is not a paired node's service fails cleanly.
    let mut bad = tokio::net::TcpStream::connect(http).await.expect("http");
    bad.write_all(b"CONNECT web.nobody.td:443 HTTP/1.1\r\n\r\n")
        .await
        .expect("connect");
    let mut head = [0u8; 12];
    tokio::time::timeout(common::PATIENCE, bad.read_exact(&mut head))
        .await
        .expect("in time")
        .expect("read");
    assert_eq!(&head, b"HTTP/1.1 502");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_group_spreads_connections_over_the_nodes_that_offer_the_service() {
    let relay = TestRelay::start().await;
    let client = TestNode::inbound_only("client", &[relay.addr]).await;
    let one = TestNode::inbound_only("one", &[relay.addr]).await;
    let two = TestNode::inbound_only("two", &[relay.addr]).await;
    for (n, tag) in [(&one, 1u8), (&two, 2u8)] {
        client.pair_with(n, "worker");
        n.pair_with(&client, "client");
        n.node
            .expose("work", echo_service(tag).await, vec!["*paired".into()], "")
            .expect("expose");
    }
    client.node.set_group("workers", vec![one.id(), two.id()]);
    let (local, _) = client
        .node
        .connect("workers", "work")
        .await
        .expect("connect to the group");

    // Hold several connections open at once: placement counts what is already running.
    let mut seen = std::collections::HashSet::new();
    let mut held = Vec::new();
    for _ in 0..6 {
        let mut s = tokio::net::TcpStream::connect(local)
            .await
            .expect("endpoint");
        s.write_all(b"x").await.expect("write");
        seen.insert(read_exact(&mut s, 2).await[0]);
        held.push(s);
    }
    assert_eq!(
        seen,
        [1u8, 2u8].into_iter().collect(),
        "both members served some of them"
    );
}

async fn node_speaking(name: &str, relay: SocketAddr, max_version: u8) -> TestNode {
    let config = OverlayConfig {
        relays: vec![relay.to_string()],
        max_version,
        ..OverlayConfig::local(NodeIdentity::generate(name))
    };
    TestNode {
        node: OverlayNode::start(config).await.expect("starts"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_older_and_a_newer_peer_each_agree_on_the_highest_common_version() {
    let relay = TestRelay::start().await;
    let current = transferd_overlay::VERSION_CURRENT as u8;
    for (theirs, agreed) in [(1u8, 1u16), (current + 1, current as u16)] {
        let us = node_speaking("us", relay.addr, current).await;
        let them = node_speaking("them", relay.addr, theirs).await;
        us.pair_with(&them, "them");
        them.pair_with(&us, "us");
        them.node
            .expose("svc", echo_service(9).await, vec!["*paired".into()], "")
            .expect("expose");
        let (local, _) = us.node.connect(&them.id(), "svc").await.expect("they talk");
        let mut s = tokio::net::TcpStream::connect(local)
            .await
            .expect("endpoint");
        s.write_all(b"v").await.expect("write");
        assert_eq!(&read_exact(&mut s, 2).await, b"\x09v");
        let probe = transferd_overlay::ops::call(
            &us.node,
            "overlay.probe",
            serde_json::json!({"node_id": them.id()}),
        )
        .await
        .expect("probe");
        assert_eq!(
            probe["protocol_version"], agreed,
            "a peer speaking up to v{theirs}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_invite_pairs_both_ways_and_a_node_that_only_knows_an_id_is_not_paired() {
    let relay = TestRelay::start().await;
    let owner = TestNode::inbound_only("owner", &[relay.addr]).await;
    let friend = TestNode::inbound_only("friend", &[relay.addr]).await;
    let stranger = TestNode::inbound_only("stranger", &[relay.addr]).await;
    owner
        .node
        .expose("svc", echo_service(3).await, vec!["*paired".into()], "")
        .expect("expose");
    friend
        .node
        .expose("back", echo_service(4).await, vec!["*paired".into()], "")
        .expect("expose");

    // Only the friend accepts an invite; the owner never accepts one from the friend.
    friend.pair_with(&owner, "owner");
    friend
        .node
        .connect(&owner.id(), "svc")
        .await
        .expect("the friend is paired with the owner");
    // Its hello carried the invite's nonce, so the owner counts the friend as paired too.
    eventually(
        "the owner to reach the friend's *paired service",
        || async { owner.node.connect(&friend.id(), "back").await.is_ok() },
    )
    .await;

    // The stranger knows the owner's id (enough to open a session) but never paired.
    let err = stranger
        .node
        .connect(&owner.id(), "svc")
        .await
        .expect_err("not paired");
    assert_eq!(err.code(), "denied", "{err}");
}

/// A service that answers after reading everything (HTTP/1.0, netcat, a byte counter) still gets
/// its answer through: the client finishing sending ends one direction only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_after_the_client_finished_sending_still_arrives() {
    let relay = TestRelay::start().await;
    let a = TestNode::inbound_only("a", &[relay.addr]).await;
    let b = TestNode::inbound_only("b", &[relay.addr]).await;
    a.pair_with(&b, "b");
    b.pair_with(&a, "a");
    // Counts what it reads and, once the sender is done, answers with the count.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let counter = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut total = 0u64;
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    total += n as u64;
                }
                let _ = s.write_all(&total.to_be_bytes()).await;
            });
        }
    });
    b.node
        .expose("count", counter, vec!["*paired".into()], "")
        .expect("expose");
    let (local, _) = a.node.connect(&b.id(), "count").await.expect("connect");

    let mut s = tokio::net::TcpStream::connect(local)
        .await
        .expect("endpoint");
    let body = vec![7u8; 300 * 1024];
    s.write_all(&body).await.expect("write");
    s.shutdown().await.expect("done sending");
    let mut count = [0u8; 8];
    tokio::time::timeout(common::PATIENCE, s.read_exact(&mut count))
        .await
        .expect("the answer comes in time")
        .expect("the answer comes");
    assert_eq!(u64::from_be_bytes(count), body.len() as u64);
}
