//! Two real cat endpoints on this machine: straight to each other, and through relayd's own dispatch loop.

use rand::RngCore;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use transferd_cat::{dial, CatAddress, Listener};

fn random(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

async fn exchange(listener: Listener, address: CatAddress, a: Vec<u8>, b: Vec<u8>) -> (Vec<u8>, Vec<u8>, bool) {
    let (a2, b2) = (a.clone(), b.clone());
    let l = tokio::spawn(async move {
        let s = listener.accept(Duration::from_secs(20)).await.expect("accept");
        let mut got = Vec::new();
        s.pipe(std::io::Cursor::new(a2), &mut got).await.expect("listener pipe");
        got
    });
    let d = dial(&address, Duration::from_secs(20)).await.expect("dial");
    let direct = d.direct;
    let mut got = Vec::new();
    d.pipe(std::io::Cursor::new(b2), &mut got).await.expect("dialer pipe");
    let l_got = l.await.expect("listener task");
    (l_got, got, direct)
}

#[tokio::test]
async fn both_ways_on_the_direct_path() {
    let listener = Listener::bind(None).await.expect("bind");
    let addr = listener.address.clone();
    let (a, b) = (random(2 << 20), random(2 << 20) );
    let (listener_got, dialer_got, direct) = exchange(listener, addr, a.clone(), b.clone()).await;
    assert!(direct, "no relay: the direct path");
    assert_eq!(listener_got, b, "the dialer's bytes reached the listener intact");
    assert_eq!(dialer_got, a, "and the listener's reached the dialer");
}

#[tokio::test]
async fn both_ways_through_the_relay() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("relay bind"));
    let relay_addr = sock.local_addr().expect("addr");
    let mut core = relayd::relay::Relay::new(4, 90, relayd::protocol::MAX_PAYLOAD);
    core.set_rate_limit(30, 100_000);
    tokio::spawn(relayd::server::serve(sock, Arc::new(Mutex::new(core))));
    let listener = Listener::bind(Some(relay_addr)).await.expect("bind");
    let mut addr = listener.address.clone();
    addr.direct.clear(); // only the relay
    let (a, b) = (random(1 << 20), random(512 << 10));
    let (listener_got, dialer_got, direct) = exchange(listener, addr, a.clone(), b.clone()).await;
    assert!(!direct, "through the relay");
    assert_eq!(listener_got, b);
    assert_eq!(dialer_got, a);
}

#[tokio::test]
async fn a_wrong_secret_gets_nowhere() {
    let listener = Listener::bind(None).await.expect("bind");
    let mut addr = listener.address.clone();
    addr.secret[0] ^= 1;
    let accept = tokio::spawn(listener.accept(Duration::from_secs(5)));
    let r = dial(&addr, Duration::from_secs(5)).await;
    assert!(r.is_err(), "the handshake confirmation must not check out with another secret");
    let _ = accept.await;
}

#[test]
fn addresses_round_trip() {
    let a = CatAddress { relay: Some("203.0.113.5:7777".parse().expect("addr")), token: [7; 32], secret: [9; 32],
                         direct: vec!["192.0.2.1:5000".parse().expect("addr")] };
    assert_eq!(CatAddress::parse(&a.to_text()).expect("parse"), a);
    assert!(CatAddress::parse("tdcat:-/zz/00/").is_err());
}
