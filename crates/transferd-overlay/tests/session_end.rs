//! A session that ends in the middle of a stream is an error to the application, not a clean end.
//!
//! The application's TCP connection is the stream's endpoint. When the session under it ends before the
//! peer has finished sending, the connection must be reset, so the application sees an error. A clean
//! close would look like a complete response.

// Test code: a failed expectation is a panic, and that is the point.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{read_exact, TestNode, TestRelay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A service that greets each connection and then keeps it open without another word.
async fn quiet_service() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = socket.write_all(b"hi").await;
                tokio::time::sleep(Duration::from_secs(600)).await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_application_sees_a_reset_when_the_session_ends_mid_stream() {
    let relay = TestRelay::start().await;
    let a = TestNode::inbound_only("a", &[relay.addr]).await;
    let b = TestNode::with_listener("b", &[relay.addr]).await;
    a.pair_with(&b, "b");
    b.pair_with(&a, "a");
    b.node
        .expose("quiet", quiet_service().await, vec!["*paired".into()], "")
        .expect("expose");

    let (local, _route) = a.node.connect(&b.id(), "quiet").await.expect("connect");
    let mut app = tokio::net::TcpStream::connect(local)
        .await
        .expect("endpoint");
    assert_eq!(
        &read_exact(&mut app, 2).await,
        b"hi",
        "the greeting arrives"
    );

    // The session ends while the stream is still open: the peer has not finished sending.
    let session = a.node.ensure_session(&b.id()).await.expect("the session");
    session.shutdown().await;

    let mut buf = [0u8; 16];
    let outcome = tokio::time::timeout(Duration::from_secs(10), app.read(&mut buf))
        .await
        .expect("the application hears about the session ending");
    match outcome {
        Err(e) => assert_eq!(
            e.kind(),
            std::io::ErrorKind::ConnectionReset,
            "the connection is reset, not closed cleanly"
        ),
        Ok(0) => panic!("the application saw a clean end of stream although the session ended"),
        Ok(n) => panic!("the application read {n} bytes that were never sent"),
    }
}
