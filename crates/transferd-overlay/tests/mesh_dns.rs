//! Mesh DNS end to end: a node answers DNS through a paired node's resolver, over a relay.
//!
//! The resolver is a stand-in that answers the way a filtering resolver does (a blocked name gets
//! `0.0.0.0`), served over TCP on the far node; the near node's forwarder is asked over real UDP
//! and TCP sockets. Neither node has a listener: the overlay path is the relay.

// Test code: a failed expectation is a panic, and that is the point.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::net::{IpAddr, SocketAddr};

use common::{TestNode, TestRelay};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transferd_dns::wire::{decode_answer, encode_query, RCODE_NXDOMAIN, RCODE_SERVFAIL, TYPE_A};
use transferd_overlay::ops;

/// A DNS server on TCP: `ads.example` is blocked (0.0.0.0), `nope.example` does not exist,
/// everything else is 192.0.2.1.
async fn stand_in_resolver() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if socket.read_exact(&mut len).await.is_err() {
                        break;
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    if socket.read_exact(&mut q).await.is_err() {
                        break;
                    }
                    let r = answer_for(&q);
                    let mut out = (r.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&r);
                    if socket.write_all(&out).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn answer_for(q: &[u8]) -> Vec<u8> {
    let (name, after) = transferd_dns::wire::decode_name(q, 12).expect("a question");
    let end = after + 4;
    let mut r = q[..end].to_vec();
    r[2] = 0x81;
    r[3] = 0x80;
    r[8..12].fill(0);
    let addr = match name.as_str() {
        "nope.example" => {
            r[3] |= RCODE_NXDOMAIN;
            r[6..8].fill(0);
            return r;
        }
        "ads.example" => [0, 0, 0, 0],
        _ => [192, 0, 2, 1],
    };
    r[6..8].copy_from_slice(&1u16.to_be_bytes());
    r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    r.extend_from_slice(&addr);
    r
}

async fn ask_udp(server: SocketAddr, id: u16, name: &str) -> transferd_dns::wire::Answer {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("binds");
    socket
        .send_to(&encode_query(id, name, TYPE_A).expect("query"), server)
        .await
        .expect("send");
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(common::PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("in time")
        .expect("recv");
    decode_answer(&buf[..n], id, name, TYPE_A).expect("an answer to our question")
}

async fn ask_tcp(server: SocketAddr, id: u16, name: &str) -> transferd_dns::wire::Answer {
    let mut s = tokio::net::TcpStream::connect(server)
        .await
        .expect("connects");
    let q = encode_query(id, name, TYPE_A).expect("query");
    let mut out = (q.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&q);
    s.write_all(&out).await.expect("write");
    let mut len = [0u8; 2];
    tokio::time::timeout(common::PATIENCE, s.read_exact(&mut len))
        .await
        .expect("in time")
        .expect("len");
    let mut r = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut r).await.expect("body");
    decode_answer(&r, id, name, TYPE_A).expect("an answer to our question")
}

fn addrs(a: &transferd_dns::wire::Answer) -> Vec<IpAddr> {
    a.addrs.iter().map(|r| r.addr).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_answers_dns_through_a_paired_nodes_resolver() {
    common::trace();
    let relay = TestRelay::start().await;
    let near = TestNode::inbound_only("near", &[relay.addr]).await;
    let far = TestNode::inbound_only("far", &[relay.addr]).await;
    near.pair_with(&far, "far");
    far.pair_with(&near, "near");
    let resolver = stand_in_resolver().await;
    far.node
        .expose("dns", resolver, vec!["*paired".into()], "the resolver")
        .expect("far shares its resolver");

    let status = ops::call(
        &near.node,
        "overlay.dns_set",
        json!({"upstreams": [far.id()], "listen": "127.0.0.1:0"}),
    )
    .await
    .expect("mesh DNS on");
    assert_eq!(status["enabled"], true);
    let listen: SocketAddr = status["listen"]
        .as_str()
        .expect("listen")
        .parse()
        .expect("an address");

    let real = ask_udp(listen, 0x1111, "example.com").await;
    assert_eq!(addrs(&real), vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
    let blocked = ask_udp(listen, 0x2222, "ads.example").await;
    assert_eq!(addrs(&blocked), vec!["0.0.0.0".parse::<IpAddr>().unwrap()]);
    let missing = ask_tcp(listen, 0x3333, "nope.example").await;
    assert_eq!(missing.rcode, RCODE_NXDOMAIN);
    // Many at once over one pipelined upstream connection, each with its own answer.
    let many = (0..20u16).map(|i| tokio::spawn(ask_udp(listen, 0x4000 + i, "example.com")));
    for answer in many {
        assert_eq!(addrs(&answer.await.expect("joined")).len(), 1);
    }

    let status = ops::call(&near.node, "overlay.dns_status", json!({}))
        .await
        .expect("status");
    let upstream = &status["upstreams"][0];
    assert_eq!(upstream["target"], far.id());
    assert_eq!(upstream["healthy"], true);
    assert_eq!(upstream["answered"], 23);
    assert_eq!(
        upstream["blocked"], 1,
        "the filtered answer is counted as blocked"
    );
    assert_eq!(upstream["nxdomain"], 1);
    assert_eq!(status["totals"]["failed"], 0);
    let far_status = ops::call(&far.node, "overlay.dns_status", json!({}))
        .await
        .expect("far status");
    assert_eq!(far_status["enabled"], false, "far forwards nothing itself");
    assert_eq!(
        far_status["serving"]["local_addr"],
        resolver.to_string(),
        "but shares its resolver"
    );

    ops::call(&near.node, "overlay.dns_set", json!({"upstreams": []}))
        .await
        .expect("off");
    assert!(
        tokio::net::UdpSocket::bind(listen).await.is_ok(),
        "turning it off frees the address"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_broken_upstream_is_skipped_and_all_broken_means_servfail() {
    let relay = TestRelay::start().await;
    let near = TestNode::inbound_only("near", &[relay.addr]).await;
    let good = TestNode::inbound_only("good", &[relay.addr]).await;
    let broken = TestNode::inbound_only("broken", &[relay.addr]).await;
    for other in [&good, &broken] {
        near.pair_with(other, "peer");
        other.pair_with(&near, "near");
    }
    good.node
        .expose("dns", stand_in_resolver().await, vec!["*paired".into()], "")
        .expect("expose");
    // A resolver that is not running: the stream opens, the far side cannot reach it.
    let gone = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds")
        .local_addr()
        .expect("addr");
    broken
        .node
        .expose("dns", gone, vec!["*paired".into()], "")
        .expect("expose");

    let status = ops::call(
        &near.node,
        "overlay.dns_set",
        json!({"upstreams": [broken.id(), good.id()], "listen": "127.0.0.1:0", "timeout_ms": 1500}),
    )
    .await
    .expect("on");
    let listen: SocketAddr = status["listen"]
        .as_str()
        .expect("listen")
        .parse()
        .expect("addr");

    let answer = ask_udp(listen, 7, "example.com").await;
    assert_eq!(
        addrs(&answer),
        vec!["192.0.2.1".parse::<IpAddr>().unwrap()],
        "the second upstream answered"
    );
    let status = ops::call(&near.node, "overlay.dns_status", json!({}))
        .await
        .expect("status");
    assert_eq!(
        status["upstreams"][0]["healthy"], false,
        "the broken one is set aside"
    );
    assert!(status["upstreams"][0]["last_error"]
        .as_str()
        .is_some_and(|e| !e.is_empty()));
    // Set aside, it is not asked again: the next answer comes straight from the good one.
    let started = std::time::Instant::now();
    ask_udp(listen, 8, "example.com").await;
    assert!(
        started.elapsed() < std::time::Duration::from_millis(1500),
        "no timeout paid twice"
    );

    ops::call(
        &near.node,
        "overlay.dns_set",
        json!({"upstreams": [broken.id()], "listen": "127.0.0.1:0", "timeout_ms": 1000}),
    )
    .await
    .expect("only the broken one");
    let listen: SocketAddr = ops::call(&near.node, "overlay.dns_status", json!({}))
        .await
        .expect("status")["listen"]
        .as_str()
        .expect("listen")
        .parse()
        .expect("addr");
    let failed = ask_udp(listen, 9, "example.com").await;
    assert_eq!(failed.rcode, RCODE_SERVFAIL, "an answer, not silence");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_mesh_dns_setting_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("td-mesh-dns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let state = dir.join("state.json");
    let identity = transferd_overlay::NodeIdentity::generate("n");
    let config = transferd_overlay::OverlayConfig {
        state_path: Some(state.clone()),
        ..transferd_overlay::OverlayConfig::local(identity)
    };
    let upstream = "a".repeat(64);
    {
        let node = transferd_overlay::OverlayNode::start(config.clone())
            .await
            .expect("starts");
        ops::call(
            &node,
            "overlay.dns_set",
            json!({"upstreams": [upstream], "listen": "127.0.0.1:0"}),
        )
        .await
        .expect("on");
        node.set_mesh_dns(None)
            .await
            .expect("stopped for the restart");
        // Turning it off forgets it; turn it on again so the file says "on" when the node goes.
        ops::call(
            &node,
            "overlay.dns_set",
            json!({"upstreams": [upstream], "listen": "127.0.0.1:0"}),
        )
        .await
        .expect("on");
    }
    let node = transferd_overlay::OverlayNode::start(config)
        .await
        .expect("starts again");
    let status = ops::call(&node, "overlay.dns_status", json!({}))
        .await
        .expect("status");
    assert_eq!(status["enabled"], true, "it came back from the state file");
    assert_eq!(status["upstreams"][0]["target"], upstream);
    let _ = std::fs::remove_dir_all(&dir);
}
