//! Throughput and latency through the overlay, for docs/OVERLAY.md.
//!
//! Ignored by default (it measures, it does not check): run it in release mode,
//!
//! ```text
//! cargo test --release -p transferd-overlay --test bench -- --ignored --nocapture
//! ```

// Test code: a failed expectation is a panic, and that is the point.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::net::SocketAddr;
use std::time::Instant;

use common::{echo_service, TestNode, TestRelay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A service that reads everything and answers with the byte count when the sender is done.
async fn sink() -> SocketAddr {
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
                let mut buf = vec![0u8; 64 * 1024];
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
    addr
}

async fn measure(label: &str, a: &TestNode, b: &TestNode) {
    b.node
        .expose("sink", sink().await, vec!["*paired".into()], "")
        .expect("expose");
    b.node
        .expose("echo", echo_service(0).await, vec!["*paired".into()], "")
        .expect("expose");
    let (sink_at, route) = a.node.connect(&b.id(), "sink").await.expect("sink");
    let (echo_at, _) = a.node.connect(&b.id(), "echo").await.expect("echo");

    // Latency: small round trips on one connection.
    let mut e = tokio::net::TcpStream::connect(echo_at).await.expect("echo");
    let _ = e.set_nodelay(true);
    let mut rtts = Vec::new();
    let mut buf = [0u8; 2];
    for _ in 0..200 {
        let t = Instant::now();
        e.write_all(b"x").await.expect("write");
        e.read_exact(&mut buf).await.expect("read");
        rtts.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    rtts.sort_by(|x, y| x.total_cmp(y));

    // Throughput: 64 MiB one way, counted at the far end.
    let total: u64 = 64 << 20;
    let mut s = tokio::net::TcpStream::connect(sink_at).await.expect("sink");
    let chunk = vec![0x5au8; 256 * 1024];
    let t = Instant::now();
    let mut sent = 0u64;
    while sent < total {
        s.write_all(&chunk).await.expect("write");
        sent += chunk.len() as u64;
    }
    s.shutdown().await.expect("done sending");
    let mut count = [0u8; 8];
    s.read_exact(&mut count).await.expect("the count");
    let secs = t.elapsed().as_secs_f64();
    assert_eq!(u64::from_be_bytes(count), total, "every byte arrived");
    println!(
        "{label:<8} route={:<6} rtt p50 {:.2} ms, p99 {:.2} ms | {:.0} MB/s ({:.0} Mbit/s)",
        route.as_str(),
        rtts[100],
        rtts[198],
        total as f64 / secs / 1e6,
        total as f64 * 8.0 / secs / 1e6
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a benchmark: run with --ignored --nocapture, in release mode"]
async fn throughput_and_latency_direct_and_relayed() {
    let relay = TestRelay::start().await;
    let a = TestNode::with_listener("a", &[]).await;
    let b = TestNode::with_listener("b", &[]).await;
    a.pair_with(&b, "b");
    b.pair_with(&a, "a");
    measure("direct", &a, &b).await;

    let c = TestNode::inbound_only("c", &[relay.addr]).await;
    let d = TestNode::inbound_only("d", &[relay.addr]).await;
    c.pair_with(&d, "d");
    d.pair_with(&c, "c");
    measure("relayed", &c, &d).await;
}
