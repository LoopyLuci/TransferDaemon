//! The relayed path losing a fifth of its datagrams, both ways: everything still arrives.
//!
//! Stream data is acknowledged cumulatively and resent; control frames (hello, open, accept,
//! window, close) carry receipts and are resent until one comes back; the relay handshake resends
//! its flight. None of that is visible to the application, which only sees a slower link.

// Test code: a failed expectation is a panic, and that is the point.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{Lossy, TestNode, TestRelay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// An echo that sends back exactly what it reads.
async fn plain_echo() -> SocketAddr {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_that_loses_a_fifth_of_its_datagrams_still_delivers_everything() {
    common::trace();
    let relay = TestRelay::start().await;
    let lossy = Lossy::start(relay.addr, 20).await;
    let a = TestNode::inbound_only("a", &[lossy.addr]).await;
    let b = TestNode::inbound_only("b", &[lossy.addr]).await;
    // Registration itself may lose a datagram; the node keeps trying until it is in.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    while a.node.relays().is_empty() || b.node.relays().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "both nodes register through the lossy link"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    a.pair_with(&b, "b");
    b.pair_with(&a, "a");
    b.node
        .expose("echo", plain_echo().await, vec!["*paired".into()], "")
        .expect("expose");

    let (local, _) = a
        .node
        .connect(&b.id(), "echo")
        .await
        .expect("connect through the loss");
    for round in 0..10u8 {
        let payload: Vec<u8> = (0..64 * 1024).map(|i| (i as u8) ^ round).collect();
        let mut s = tokio::net::TcpStream::connect(local)
            .await
            .expect("endpoint");
        let (mut r, mut w) = s.split();
        let send = async {
            w.write_all(&payload).await.expect("write");
        };
        let receive = async {
            let mut got = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(60), r.read_exact(&mut got))
                .await
                .unwrap_or_else(|_| panic!("round {round}: the echo stalled"))
                .expect("read");
            got
        };
        let ((), got) = tokio::join!(send, receive);
        assert!(got == payload, "round {round}: every byte, in order");
    }
}
