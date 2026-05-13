//! TCP lane integration tests.
//!
//! Topology: Session → ATE → TcpLane(client) → loopback TCP → TcpLane(server) → ReassemblyWindow.
//! All tests use 127.0.0.1 with an OS-assigned port (no external services required).

use bytes::Bytes;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};
use transferd_core::ate::Ate;
use transferd_core::lanes::tcp_lane::TcpLane;
use transferd_core::plugin::{PluginRegistry, TcpPlugin, default_registry};
use transferd_core::receiver::ReassemblyWindow;
use transferd_core::session::Session;
use transferd_core::transport::{Chunk, TransportLane};
use transferd_core::types::{Gsn, SessionId};

const SESSION_KEY: &[u8; 32] = b"test-session-key-for-tcp-lane-!!";

// ---------------------------------------------------------------------------
// Helper: returns a connected (client_lane, server_lane) pair.
//
// Pattern: the server task binds on port 0, signals the real addr via oneshot,
// then blocks on accept(). The client connects after receiving the addr.
// This is race-free — no port is released between bind and connect.
// ---------------------------------------------------------------------------

async fn make_lane_pair(session_key: &'static [u8; 32]) -> (TcpLane, TcpLane) {
    let (addr_tx, addr_rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        addr_tx.send(addr).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        TcpLane::from_stream(1, stream, session_key).unwrap()
    });

    let server_addr = addr_rx.await.unwrap();
    let client = TcpLane::connect(0, server_addr, session_key).await.unwrap();
    let server = server_handle.await.unwrap();
    (client, server)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Single chunk: encrypt on client, decrypt on server, verify payload.
#[tokio::test]
async fn test_tcp_lane_single_chunk() {
    let (client, mut server) = make_lane_pair(SESSION_KEY).await;

    let chunk = Chunk {
        gsn: Gsn(0),
        session_id: SessionId([0u8; 16]),
        payload: Bytes::from_static(b"hello tcp lane"),
        key_epoch: 0,
        qos_critical: false,
    };
    client.send(chunk).await.expect("send failed");

    let received = timeout(Duration::from_secs(2), server.recv())
        .await
        .expect("recv timed out")
        .expect("channel closed")
        .expect("transport error");

    assert_eq!(received.payload.as_ref(), b"hello tcp lane");
    assert_eq!(received.gsn, Gsn(0));
    println!("test_tcp_lane_single_chunk: PASSED");
}

/// Five chunks through the ATE/Session pipeline; all arrive and reassemble contiguously.
#[tokio::test]
async fn test_tcp_lane_multi_chunk_reassembly() {
    let (client, mut server) = make_lane_pair(SESSION_KEY).await;

    let ate = Ate::new(1, 100);
    let mut session = Session::new(SessionId([0u8; 16]), ate, 64);
    for i in 0u8..5 {
        session.enqueue(Bytes::from(vec![i; 32]), 0);
    }
    let mut lanes: Vec<Box<dyn TransportLane>> = vec![Box::new(client)];
    session.process_tick(&mut lanes).await;

    let mut window = ReassemblyWindow::new(SessionId([0u8; 16]), 64);
    for _ in 0..5 {
        let chunk = timeout(Duration::from_secs(2), server.recv())
            .await
            .expect("recv timeout")
            .expect("channel closed")
            .expect("transport error");
        window.insert(chunk);
    }

    assert_eq!(window.delivered_up_to(), Gsn(5),
        "all 5 chunks must be contiguously delivered");
    println!("test_tcp_lane_multi_chunk_reassembly: PASSED");
}

/// Wrong session key on the server → GCM auth fails, frame silently dropped, recv times out.
#[tokio::test]
async fn test_tcp_lane_wrong_key_rejected() {
    let wrong_key: &'static [u8; 32] = b"wrong-key-for-tcp-lane-test-!!!!";

    let (addr_tx, addr_rx) = oneshot::channel();
    let server_handle = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        addr_tx.send(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        TcpLane::from_stream(1, stream, wrong_key).unwrap()
    });

    let addr = addr_rx.await.unwrap();
    let client = TcpLane::connect(0, addr, SESSION_KEY).await.unwrap();
    let mut server = server_handle.await.unwrap();

    client.send(Chunk {
        gsn: Gsn(0),
        session_id: SessionId([0u8; 16]),
        payload: Bytes::from_static(b"secret"),
        key_epoch: 0,
        qos_critical: false,
    }).await.unwrap();

    // Bad frame is silently discarded; recv should time out.
    let result = timeout(Duration::from_millis(300), server.recv()).await;
    assert!(result.is_err(), "wrong-key frame must be silently dropped — recv must time out");
    println!("test_tcp_lane_wrong_key_rejected: PASSED");
}

/// Large payload (48 KiB) round-trips correctly through the frame reader.
#[tokio::test]
async fn test_tcp_lane_large_payload() {
    let (client, mut server) = make_lane_pair(SESSION_KEY).await;

    let big = Bytes::from(vec![0xABu8; 48 * 1024]);
    client.send(Chunk {
        gsn: Gsn(42),
        session_id: SessionId([1u8; 16]),
        payload: big.clone(),
        key_epoch: 0,
        qos_critical: false,
    }).await.unwrap();

    let received = timeout(Duration::from_secs(3), server.recv())
        .await
        .expect("recv timed out")
        .expect("channel closed")
        .expect("transport error");

    assert_eq!(received.gsn, Gsn(42));
    assert_eq!(received.payload.len(), 48 * 1024);
    assert!(received.payload.iter().all(|&b| b == 0xAB));
    println!("test_tcp_lane_large_payload: PASSED");
}

/// QoS-critical chunk: verify qos_critical flag survives the encode → decode round-trip.
#[tokio::test]
async fn test_tcp_lane_qos_flag_survives_roundtrip() {
    let (client, mut server) = make_lane_pair(SESSION_KEY).await;

    client.send(Chunk {
        gsn: Gsn(7),
        session_id: SessionId([2u8; 16]),
        payload: Bytes::from_static(b"critical"),
        key_epoch: 0,
        qos_critical: true,
    }).await.unwrap();

    let received = timeout(Duration::from_secs(2), server.recv())
        .await.unwrap().unwrap().unwrap();

    assert!(received.qos_critical, "qos_critical must survive the TCP frame round-trip");
    println!("test_tcp_lane_qos_flag_survives_roundtrip: PASSED");
}

/// PluginRegistry resolves "tcp" scheme → creates a connected TcpLane.
#[tokio::test]
async fn test_plugin_registry_creates_tcp_lane() {
    let mut registry = PluginRegistry::new();
    registry.register(Box::new(TcpPlugin));

    assert!(registry.registered_schemes().contains(&"tcp"));
    assert!(registry.capabilities("tcp").max_bps > 0);

    let (addr_tx, addr_rx) = oneshot::channel();
    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        addr_tx.send(listener.local_addr().unwrap()).unwrap();
        let _ = listener.accept().await; // accept and discard — we only test creation
    });
    let addr = addr_rx.await.unwrap();

    let lane = registry
        .create_lane(0, "tcp", &addr.to_string(), SESSION_KEY)
        .await
        .expect("plugin must create a TcpLane");

    assert!(lane.is_alive());
    println!("test_plugin_registry_creates_tcp_lane: PASSED");
}

/// default_registry() covers tcp/relay/swarm; unknown and stub schemes error correctly.
#[tokio::test]
async fn test_default_registry_scheme_coverage() {
    let registry = default_registry();
    let schemes = registry.registered_schemes();
    assert!(schemes.contains(&"tcp"),   "tcp must be registered");
    assert!(schemes.contains(&"relay"), "relay must be registered");
    assert!(schemes.contains(&"swarm"), "swarm must be registered");

    // Unknown scheme → ProtocolViolation.
    assert!(registry.create_lane(0, "ftp", "127.0.0.1:21", SESSION_KEY).await.is_err());

    // SwarmLane stub → LinkDown error.
    assert!(registry.create_lane(0, "swarm", "magnet:?xt=...", SESSION_KEY).await.is_err());

    // RelayPlugin stub → ProtocolViolation.
    assert!(registry.create_lane(0, "relay", "127.0.0.1:7777", SESSION_KEY).await.is_err());

    println!("test_default_registry_scheme_coverage: PASSED");
}
