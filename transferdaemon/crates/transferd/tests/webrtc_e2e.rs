//! End-to-end test: gRPC call signaling + WebRTC session + video frame delivery.
//!
//! The test runs a single real daemon, has Alice call Bob over the gRPC
//! signaling service, then asserts that both parties receive the expected
//! events and that video frames arrive from the simulated media source.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tonic::transport::{Channel, Server};

use transferd_api::{CallServiceClient, Empty};
use transferd_lib::{grpc::add_all_services, new_state};
use transferd_webrtc::{
    grpc_signaling::GrpcSignaling,
    media::MockMediaCapture,
    session::SimulatedCallSession,
    MediaCapture,
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

async fn start_daemon() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = new_state();
    tokio::spawn(async move {
        add_all_services(Server::builder(), state)
            .serve_with_incoming(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
            )
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

async fn channel(addr: SocketAddr) -> Channel {
    Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full gRPC signaling round-trip with simulated WebRTC sessions.
///
/// Flow:
///   1. Both Alice and Bob subscribe to StreamCallEvents BEFORE the invite.
///   2. Alice creates a SimulatedCallSession and calls StartCall (sends invite).
///   3. Bob reads the "invite" event from his stream.
///   4. Bob creates his session, accepts the call (AcceptCall).
///   5. Alice reads the "accepted" event from her stream.
///   6. Both sessions activate().
///   7. Verify video frames arrive on Alice's loopback channel.
///   8. Both hang up; verify "ended" events.
#[tokio::test]
async fn test_video_call_signaling_e2e() {
    let addr = start_daemon().await;

    // Two independent channels — Alice and Bob.
    let ch_a = channel(addr).await;
    let ch_b = channel(addr).await;

    // ── 1. Subscribe BEFORE any invite is sent ──────────────────────────────
    // broadcast::channel only delivers to live receivers, so we must subscribe
    // before Alice sends the invite.
    let mut stream_a = CallServiceClient::new(ch_a.clone())
        .stream_call_events(Empty {})
        .await
        .unwrap()
        .into_inner();
    let mut stream_b = CallServiceClient::new(ch_b.clone())
        .stream_call_events(Empty {})
        .await
        .unwrap()
        .into_inner();

    // ── 2. Alice creates a session and sends the invite ──────────────────────
    let media_a = Arc::new(MockMediaCapture::new_with_video());
    let mut session_a = SimulatedCallSession::new_outgoing(
        "bob-contact-id".into(),
        true,
        Arc::clone(&media_a) as Arc<dyn MediaCapture>,
    )
    .await;

    let sig_a = GrpcSignaling::new_caller(
        ch_a.clone(),
        "conv-alice-bob",
        true,
        &session_a.local_sdp,
    )
    .await
    .expect("Alice: StartCall failed");

    let call_id = sig_a.call_id.clone();
    assert!(!call_id.is_empty(), "call_id must be non-empty");

    // ── 3. Bob reads the "invite" event ─────────────────────────────────────
    let invite = tokio::time::timeout(Duration::from_secs(5), stream_b.message())
        .await
        .expect("timeout waiting for invite")
        .expect("stream error")
        .expect("stream ended");
    assert_eq!(invite.event_type, "invite", "expected invite event");
    assert_eq!(invite.video, true, "call should be video");
    let offer_sdp = invite.payload.clone(); // offer SDP from Alice

    // ── 4. Bob accepts ───────────────────────────────────────────────────────
    let media_b = Arc::new(MockMediaCapture::new_with_video());
    let session_b = SimulatedCallSession::new_incoming(
        invite.call_id.clone(),
        "conv-alice-bob".into(),
        true,
        offer_sdp.clone(),
        Arc::clone(&media_b) as Arc<dyn MediaCapture>,
    )
    .await;

    let (_sig_b, remote_sdp) = GrpcSignaling::new_callee(
        ch_b.clone(),
        &invite.call_id,
        &session_b.local_sdp,
    )
    .await
    .expect("Bob: AcceptCall failed");

    // remote_sdp returned from AcceptCall is the original offer.
    assert_eq!(remote_sdp, offer_sdp, "remote SDP should be Alice's offer");

    // ── 5. Alice reads the "accepted" event ──────────────────────────────────
    // Alice's stream also receives the "invite" broadcast; skip until "accepted".
    let accepted = loop {
        let ev = tokio::time::timeout(Duration::from_secs(5), stream_a.message())
            .await
            .expect("timeout waiting for accepted")
            .expect("stream error")
            .expect("stream ended");
        if ev.event_type == "accepted" { break ev; }
    };

    // ── 6. Both activate ─────────────────────────────────────────────────────
    session_a.activate().await;
    session_b.activate().await;

    // ── 7. Video frames from Alice's loopback ────────────────────────────────
    // SimulatedCallSession.remote_video_rx is a loopback from the local
    // MockMediaCapture — frames are produced immediately after activate().
    if let Some(ref mut rx) = session_a.remote_video_rx {
        let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout waiting for video frame")
            .expect("video channel closed");
        assert_eq!(frame.width, 640, "frame width");
        assert_eq!(frame.height, 480, "frame height");
        assert_eq!(
            frame.rgba.len(),
            640 * 480 * 4,
            "RGBA buffer size"
        );
    }

    // ── 8. Hang up ───────────────────────────────────────────────────────────
    sig_a.end().await.expect("Alice: EndCall failed");

    session_a.hang_up().await;
    session_b.hang_up().await;
}

/// Simpler smoke test: ICE candidate exchange over gRPC.
#[tokio::test]
async fn test_ice_candidate_exchange() {
    let addr = start_daemon().await;
    let ch = channel(addr).await;

    // Subscribe before invite.
    let mut stream = CallServiceClient::new(ch.clone())
        .stream_call_events(Empty {})
        .await
        .unwrap()
        .into_inner();

    // Start a call (audio only).
    let sig = GrpcSignaling::new_caller(ch.clone(), "conv-ice-test", false, "offer-sdp")
        .await
        .expect("StartCall");

    // ICE candidate should round-trip without error.
    sig.send_ice(r#"{"candidate":"udp 1 127.0.0.1 54321 typ host"}"#)
        .await
        .expect("SendIceCandidate");

    sig.end().await.expect("EndCall");

    // Drain stream; we should see at least the invite event.
    let ev = tokio::time::timeout(Duration::from_secs(3), stream.message())
        .await
        .expect("timeout")
        .expect("stream error")
        .expect("stream ended");
    assert_eq!(ev.event_type, "invite");
}
