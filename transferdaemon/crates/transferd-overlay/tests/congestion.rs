//! A slow, long path: the overlay fits itself to it instead of flooding it.
//!
//! The path is `common::Shaped`: a bottleneck of fixed rate with a small drop-tail buffer and a
//! delay each way, between two nodes that reach each other through a relay.

// Test code: a failed expectation is a panic, and that is the point.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::{Shaped, TestNode, TestRelay};
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
                let mut sum = 0u64;
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    total += n as u64;
                    sum = buf[..n]
                        .iter()
                        .fold(sum, |a, b| a.wrapping_mul(31).wrapping_add(*b as u64));
                }
                let _ = s.write_all(&total.to_be_bytes()).await;
                let _ = s.write_all(&sum.to_be_bytes()).await;
            });
        }
    });
    addr
}

/// The tests time a path; running side by side they would time each other's load.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Run {
    secs: f64,
    /// Retransmitted payload bytes over payload bytes sent, on the sending node.
    retx_ratio: f64,
    rto_ms: f64,
    srtt_ms: f64,
    probe_ms: f64,
    cwnd: u64,
    drop_share: f64,
    full_share: f64,
}

/// Send `total` bytes from `a` to a sink on `b` over a shaped path and measure it.
async fn transfer(rate: u64, buffer: usize, delay_ms: u64, total: u64) -> Run {
    common::trace();
    common::fine_timers();
    let relay = TestRelay::start().await;
    let path = Shaped::start(relay.addr, rate, buffer, Duration::from_millis(delay_ms)).await;
    let a = TestNode::inbound_only("a", &[path.addr]).await;
    let b = TestNode::inbound_only("b", &[path.addr]).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while a.node.relays().is_empty() || b.node.relays().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "both nodes register through the shaped path"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    a.pair_with(&b, "b");
    b.pair_with(&a, "a");
    b.node
        .expose("sink", sink().await, vec!["*paired".into()], "")
        .expect("expose");
    let (local, _) = a.node.connect(&b.id(), "sink").await.expect("connect");

    // Count only the transfer itself, not the setup.
    path.stats.reset();
    let mut s = tokio::net::TcpStream::connect(local)
        .await
        .expect("endpoint");
    let mut chunk = vec![0u8; 64 * 1024];
    let mut sum = 0u64;
    let mut sent = 0u64;
    let started = Instant::now();
    if std::env::var("CC_DEBUG").is_ok() {
        let node = a.node.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                println!("{}", node.peer_list()[0]["routes"]);
            }
        });
    }
    let mut next = 0u8;
    while sent < total {
        let n = chunk.len().min((total - sent) as usize);
        for (i, byte) in chunk[..n].iter_mut().enumerate() {
            *byte = (i as u8) ^ next;
        }
        next = next.wrapping_add(7);
        sum = chunk[..n]
            .iter()
            .fold(sum, |a, b| a.wrapping_mul(31).wrapping_add(*b as u64));
        s.write_all(&chunk[..n]).await.expect("write");
        sent += n as u64;
    }
    s.shutdown().await.expect("done sending");
    let mut answer = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(300), s.read_exact(&mut answer))
        .await
        .expect("the transfer finishes")
        .expect("the count");
    let secs = started.elapsed().as_secs_f64();
    assert_eq!(
        u64::from_be_bytes(answer[..8].try_into().unwrap()),
        total,
        "every byte arrived"
    );
    assert_eq!(
        u64::from_be_bytes(answer[8..].try_into().unwrap()),
        sum,
        "intact, in order"
    );

    // Let a few probe round trips land too: they are measured on an idle path.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let peers = a.node.peer_list();
    let routes = peers[0]["routes"].as_array().cloned().unwrap_or_default();
    let route = &routes[0];
    let (retx, data) = (
        route["retx_bytes"].as_u64().unwrap_or(0),
        route["sent_bytes"].as_u64().unwrap_or(0),
    );
    let (admitted, dropped) = path.stats.admitted_dropped();
    Run {
        secs,
        retx_ratio: retx as f64 / data.max(1) as f64,
        rto_ms: route["rto_ms"].as_f64().unwrap_or(0.0),
        srtt_ms: route["srtt_ms"].as_f64().unwrap_or(0.0),
        probe_ms: route["rtt_ms"].as_f64().unwrap_or(0.0),
        cwnd: route["cwnd"].as_u64().unwrap_or(0),
        drop_share: dropped as f64 / (admitted + dropped).max(1) as f64,
        full_share: path.stats.full_fraction(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bandwidth_limited_link_is_filled_but_not_flooded() {
    let _one = ONE_AT_A_TIME.lock().await;
    const RATE: u64 = 2_000_000;
    const TOTAL: u64 = 16 << 20;
    let run = transfer(RATE, 96 * 1024, 40, TOTAL).await;
    let achieved = TOTAL as f64 / run.secs;
    println!(
        "emulated 2 MB/s, 40 ms each way: {:.2} MB/s ({:.0}% of the link), resent {:.1}% of the bytes sent, \
         {:.1}% of the bytes offered dropped, buffer over 75% full for {:.0}% of the bytes arriving, srtt {:.0} ms, rto {:.0} ms, cwnd {} KiB",
        achieved / 1e6,
        achieved / RATE as f64 * 100.0,
        run.retx_ratio * 100.0,
        run.drop_share * 100.0,
        run.full_share * 100.0,
        run.srtt_ms,
        run.rto_ms,
        run.cwnd / 1024
    );
    // 75-85% on an idle machine; 60% is the floor that still catches a real regression (a halved window, a stall)
    // without failing when the machine running the tests is busy.
    assert!(
        achieved >= RATE as f64 * 0.60,
        "at least 60% of the link: {:.2} MB/s",
        achieved / 1e6
    );
    assert!(
        run.retx_ratio < 0.10,
        "resends stay modest: {:.1}% of the bytes sent",
        run.retx_ratio * 100.0
    );
    assert!(
        run.drop_share < 0.05,
        "no standing loss: {:.1}% of the bytes offered were dropped",
        run.drop_share * 100.0
    );
    assert!(
        run.full_share < 0.5,
        "the buffer does not stay full: {:.0}% of the bytes found it nearly full",
        run.full_share * 100.0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_retransmission_timeout_follows_the_path() {
    let _one = ONE_AT_A_TIME.lock().await;
    // Plenty of bandwidth: only the delay differs.
    let near = transfer(50_000_000, 4 << 20, 40, 256 << 10).await;
    println!(
        "40 ms each way: srtt {:.0} ms, probe rtt {:.0} ms, rto {:.0} ms",
        near.srtt_ms, near.probe_ms, near.rto_ms
    );
    assert!(
        near.rto_ms < 300.0,
        "on a 80 ms path the timeout settles well below the old 400 ms: {} ms",
        near.rto_ms
    );
    let far = transfer(50_000_000, 4 << 20, 300, 256 << 10).await;
    println!(
        "300 ms each way: srtt {:.0} ms, rto {:.0} ms",
        far.srtt_ms, far.rto_ms
    );
    assert!(
        far.rto_ms > 400.0,
        "on a 600 ms path the timeout rises above the old 400 ms: {} ms",
        far.rto_ms
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shallow_buffer_costs_speed_but_not_correctness() {
    let _one = ONE_AT_A_TIME.lock().await;
    // A buffer well under the path's bandwidth-delay product overflows whenever the window
    // outgrows the pipe: the window must back off, and every dropped frame must be repaired.
    const RATE: u64 = 2_000_000;
    const TOTAL: u64 = 8 << 20;
    let run = transfer(RATE, 64 * 1024, 40, TOTAL).await;
    let achieved = TOTAL as f64 / run.secs;
    println!(
        "emulated 2 MB/s, 64 KiB buffer: {:.2} MB/s ({:.0}% of the link), resent {:.1}% of the bytes sent, {:.1}% of the bytes offered dropped",
        achieved / 1e6,
        achieved / RATE as f64 * 100.0,
        run.retx_ratio * 100.0,
        run.drop_share * 100.0,
    );
    assert!(
        achieved >= RATE as f64 * 0.35,
        "a shallow buffer still gets over a third of the link: {:.2} MB/s",
        achieved / 1e6
    );
    assert!(
        run.retx_ratio < 0.15,
        "resends stay in proportion: {:.1}% of the bytes sent",
        run.retx_ratio * 100.0
    );
}
