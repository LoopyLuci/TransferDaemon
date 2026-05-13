//! End-to-end multi-path relay integration tests.
//!
//! Topology:
//!   Sender Session → [RelayLane(primary) + SimulatedWiFiLane(mirror)]
//!                         ↓ UDP
//!                   inline relayd server (in-process tokio task)
//!                         ↓ UDP
//!                   Receiver RelayLane → ReassemblyWindow
//!
//! The relay server uses difficulty=0 so all PoW nonces are trivially valid.

use bytes::Bytes;
use relayd::protocol::{
    DeliveredMsg, ForwardMsg, RegisterMsg, Tag, encode, split,
};
use relayd::relay::Relay;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};
use transferd_core::ate::Ate;
use transferd_core::lanes::relay_lane::RelayLane;
use transferd_core::receiver::ReassemblyWindow;
use transferd_core::session::Session;
use transferd_core::transport::TransportLane;
use transferd_core::types::{Gsn, SessionId};

// ---------------------------------------------------------------------------
// Inline relay server task (mirrors relayd/src/main.rs dispatch loop)
// ---------------------------------------------------------------------------

async fn run_relay_server(socket: UdpSocket, relay: Arc<Mutex<Relay>>) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 65536];
    loop {
        let Ok((len, src)) = socket.recv_from(&mut buf).await else { return };
        let frame = &buf[..len];
        let Some((tag, body)) = split(frame) else { continue };

        let socket = socket.clone();
        let relay = relay.clone();

        match tag {
            Tag::Register => {
                if let Ok(msg) = bincode::deserialize::<RegisterMsg>(body) {
                    let _ = relay.lock().await.register(&msg, src);
                    // Send a minimal Ack so the RelayLane registration drain works.
                    let ack = encode(Tag::Ack, &relayd::protocol::AckMsg { sender_seq: 0 })
                        .unwrap_or_default();
                    let _ = socket.send_to(&ack, src).await;
                }
            }
            Tag::Forward => {
                if let Ok(msg) = bincode::deserialize::<ForwardMsg>(body) {
                    let result = relay.lock().await.forward(&msg);
                    if let Ok(dst) = result {
                        let delivered = encode(
                            Tag::Ack,
                            &DeliveredMsg {
                                sender_seq: msg.sender_seq,
                                ciphertext: msg.ciphertext,
                            },
                        )
                        .unwrap_or_default();
                        let _ = socket.send_to(&delivered, dst).await;
                        let ack = encode(
                            Tag::Ack,
                            &relayd::protocol::AckMsg { sender_seq: msg.sender_seq },
                        )
                        .unwrap_or_default();
                        let _ = socket.send_to(&ack, src).await;
                    }
                }
            }
            Tag::Keepalive | Tag::Challenge | Tag::Error | Tag::Ack => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: derive relay tokens (same KDF as relayd::protocol::derive_token)
// ---------------------------------------------------------------------------

fn derive_token(session_key: &[u8; 32], relay_id: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + relay_id.len());
    input.extend_from_slice(session_key);
    input.extend_from_slice(relay_id);
    blake3::derive_key("TransferDaemon-v1-relay-token", &input)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Single relay lane: sender forwards a chunk, receiver decrypts and delivers it.
#[tokio::test]
async fn test_relay_lane_single_chunk() {
    // 1. Spin up inline relay.
    let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr: SocketAddr = relay_socket.local_addr().unwrap();
    let relay = Arc::new(Mutex::new(Relay::new(0, 90, 64 * 1024)));
    tokio::spawn(run_relay_server(relay_socket, relay));

    // 2. Session key + token pair.
    let session_key = [0x42u8; 32];
    let receiver_token = derive_token(&session_key, b"receiver");
    let sender_token = derive_token(&session_key, b"sender");

    // 3. Receiver registers, sender stays unregistered (send-only).
    let mut receiver = RelayLane::new(
        1,
        relay_addr,
        Some(receiver_token), // registers this token
        sender_token,          // forward target (unused on recv side)
        &session_key,
        0, // difficulty=0
    )
    .await
    .unwrap();

    let sender = RelayLane::new(
        0,
        relay_addr,
        None,            // sender doesn't register
        receiver_token,  // forward to receiver
        &session_key,
        0,
    )
    .await
    .unwrap();

    // 4. Send one chunk through the ATE/Session.
    let ate = Ate::new(1, 100);
    let mut session = Session::new(SessionId([1u8; 16]), ate, 64);
    session.enqueue(Bytes::from_static(b"hello relay"), 0);

    let mut lanes: Vec<Box<dyn TransportLane>> = vec![Box::new(sender)];
    session.process_tick(&mut lanes).await;

    // 5. Receive and verify.
    let chunk = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("receive timed out")
        .expect("channel closed")
        .expect("transport error");

    assert_eq!(chunk.payload.as_ref(), b"hello relay");
    assert_eq!(chunk.gsn, Gsn(0));
    println!("test_relay_lane_single_chunk: PASSED — payload={:?}", chunk.payload);
}

/// Multi-chunk transfer through the relay with ReassemblyWindow.
#[tokio::test]
async fn test_relay_lane_multi_chunk_reassembly() {
    let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_socket.local_addr().unwrap();
    let relay = Arc::new(Mutex::new(Relay::new(0, 90, 64 * 1024)));
    tokio::spawn(run_relay_server(relay_socket, relay));

    let session_key = [0xABu8; 32];
    let receiver_token = derive_token(&session_key, b"rx-multi");

    let mut receiver = RelayLane::new(1, relay_addr, Some(receiver_token), [0u8; 32], &session_key, 0)
        .await
        .unwrap();

    let sender = RelayLane::new(0, relay_addr, None, receiver_token, &session_key, 0)
        .await
        .unwrap();

    let ate = Ate::new(1, 100);
    let mut session = Session::new(SessionId([2u8; 16]), ate, 64);
    let payloads: Vec<Bytes> = (0u8..4).map(|i| Bytes::from(vec![i; 64])).collect();
    for p in &payloads {
        session.enqueue(p.clone(), 0);
    }

    let mut lanes: Vec<Box<dyn TransportLane>> = vec![Box::new(sender)];
    session.process_tick(&mut lanes).await;

    // Collect received chunks (order may vary over UDP, window handles gaps).
    let mut window = ReassemblyWindow::new(SessionId([2u8; 16]), 64);
    for _ in 0..4 {
        let chunk = timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("recv timeout")
            .expect("channel closed")
            .expect("transport error");
        window.insert(chunk);
    }

    assert_eq!(window.delivered_up_to(), Gsn(4),
        "all 4 chunks should be contiguously delivered");
    println!("test_relay_lane_multi_chunk_reassembly: PASSED");
}

/// QoS-critical chunks are mirrored on a second lane (relay + simulated WiFi).
/// Verifies that duplicates are gracefully handled by the reassembly window.
#[tokio::test]
async fn test_multipath_qos_critical_redundancy() {
    use transferd_core::lanes::simulated_wifi::SimulatedWiFiLane;

    let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_socket.local_addr().unwrap();
    let relay = Arc::new(Mutex::new(Relay::new(0, 90, 64 * 1024)));
    tokio::spawn(run_relay_server(relay_socket, relay));

    let session_key = [0xCDu8; 32];
    let receiver_token = derive_token(&session_key, b"rx-qos");

    let mut receiver = RelayLane::new(1, relay_addr, Some(receiver_token), [0u8; 32], &session_key, 0)
        .await
        .unwrap();

    let relay_sender = RelayLane::new(0, relay_addr, None, receiver_token, &session_key, 0)
        .await
        .unwrap();

    // Second lane: SimulatedWiFiLane (mirror — its send() is fire-and-forget, no receiver).
    let wifi = SimulatedWiFiLane::new(1, Duration::from_millis(5), 100_000_000.0);

    let ate = Ate::new(2, 100);
    let mut session = Session::new(SessionId([3u8; 16]), ate, 64);
    // Enqueue one QoS-critical chunk — will be sent on both lanes.
    session.enqueue_qos(Bytes::from_static(b"critical payload"), 0, true);

    let mut lanes: Vec<Box<dyn TransportLane>> = vec![
        Box::new(relay_sender),
        Box::new(wifi),
    ];
    session.process_tick(&mut lanes).await;

    // Relay lane delivers the chunk; the WiFi mirror delivers to nowhere (no receiver).
    let chunk = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("recv timeout")
        .expect("channel closed")
        .expect("transport error");

    assert_eq!(chunk.payload.as_ref(), b"critical payload");
    assert!(chunk.qos_critical);

    // Inserting a duplicate (same GSN) should produce Retransmit, not panic.
    let mut window = ReassemblyWindow::new(SessionId([3u8; 16]), 64);
    use transferd_core::receiver::InsertResult;
    let r1 = window.insert(chunk.clone());
    let r2 = window.insert(chunk);
    assert!(matches!(r1, InsertResult::Delivered(_)));
    assert!(matches!(r2, InsertResult::Retransmit(_)));

    println!("test_multipath_qos_critical_redundancy: PASSED");
}

/// Lane health monitoring: error threshold marks lane dead, capacity drops to 0.
#[test]
fn test_lane_health_error_threshold() {
    use transferd_core::transport::LaneMetrics;
    let m = LaneMetrics::default();
    assert!(m.is_healthy());
    for _ in 0..9 {
        m.record_error(10);
        assert!(m.is_healthy(), "should still be healthy before threshold");
    }
    m.record_error(10); // 10th error hits threshold
    assert!(!m.is_healthy(), "should be dead at threshold");
}

/// ATE select_two_lanes returns two distinct indices when two lanes are available.
#[test]
fn test_ate_select_two_lanes() {
    use std::sync::atomic::Ordering;
    use transferd_core::ate::Ate;
    use transferd_core::transport::LaneMetrics;
    use transferd_core::types::Gsn;

    let ate = Ate::new(2, 100);
    let m0 = LaneMetrics::default();
    let m1 = LaneMetrics::default();
    m0.bandwidth_bps.store(10_000_000, Ordering::Relaxed);
    m1.bandwidth_bps.store(10_000_000, Ordering::Relaxed);
    m0.rtt_ms.store(10_000, Ordering::Relaxed);
    m1.rtt_ms.store(20_000, Ordering::Relaxed);

    let metrics = [&m0, &m1];
    let caps = [16usize, 16usize];
    let result = ate.select_two_lanes(Gsn(0), Gsn(0), &metrics, &caps);
    let (primary, mirror) = result.expect("two lanes should be available");
    assert_ne!(primary, mirror, "primary and mirror must be different lanes");
    // Lower RTT lane (0) should be preferred as primary.
    assert_eq!(primary, 0);
    assert_eq!(mirror, 1);
    println!("test_ate_select_two_lanes: PASSED");
}
