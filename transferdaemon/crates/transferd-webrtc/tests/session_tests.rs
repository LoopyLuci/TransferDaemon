//! Unit-level tests for `SimulatedCallSession`, `CallManager`, and `MediaCapture`.
//!
//! No networking required — all tests run entirely in-process.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use transferd_webrtc::{
    CallManager, CallState, MediaCapture, MockMediaCapture, SilentCapture, SimulatedCallSession,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mock_audio() -> Arc<MockMediaCapture> {
    Arc::new(MockMediaCapture::default())
}

fn mock_video() -> Arc<MockMediaCapture> {
    Arc::new(MockMediaCapture::new_with_video())
}

/// A remote SDP offer that works for both the simulated session (which ignores
/// the payload) and the real WebRTC backend (which requires a JSON-encoded,
/// structurally valid `RTCSessionDescription` for `set_remote_description`).
fn mock_remote_offer() -> String {
    let sdp = "v=0\r\n\
               o=- 0 0 IN IP4 127.0.0.1\r\n\
               s=-\r\n\
               t=0 0\r\n\
               a=group:BUNDLE 0\r\n\
               m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
               c=IN IP4 127.0.0.1\r\n\
               a=ice-ufrag:ufrag\r\n\
               a=ice-pwd:transferd-pwd\r\n\
               a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff\r\n\
               a=setup:actpass\r\n\
               a=mid:0\r\n\
               a=sendrecv\r\n\
               a=rtcp-mux\r\n\
               a=rtpmap:111 opus/48000/2\r\n";
    serde_json::json!({ "type": "offer", "sdp": sdp }).to_string()
}

// ---------------------------------------------------------------------------
// State machine tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_outgoing_session_starts_in_outgoing_state() {
    let sess = SimulatedCallSession::new_outgoing(
        "conv-1".into(), false, mock_audio(),
    ).await;
    assert!(matches!(sess.current_state().await, CallState::Outgoing { .. }));
    assert!(!sess.call_id.is_empty());
}

#[tokio::test]
async fn test_outgoing_session_activates() {
    let sess = SimulatedCallSession::new_outgoing(
        "conv-1".into(), false, mock_audio(),
    ).await;
    sess.activate().await;
    assert!(matches!(sess.current_state().await, CallState::Active { .. }));
}

#[tokio::test]
async fn test_hang_up_transitions_to_ended() {
    let sess = SimulatedCallSession::new_outgoing(
        "conv-1".into(), false, mock_audio(),
    ).await;
    sess.activate().await;
    assert!(sess.current_state().await.is_active());
    sess.hang_up().await;
    assert!(sess.current_state().await.is_ended());
}

#[tokio::test]
async fn test_incoming_session_starts_in_incoming_state() {
    let sess = SimulatedCallSession::new_incoming(
        "call-abc".into(),
        "conv-2".into(),
        false,
        "v=0\r\ns=offer\r\n".into(),
        mock_audio(),
    ).await;
    let state = sess.current_state().await;
    assert!(matches!(state, CallState::Incoming { .. }));
    if let CallState::Incoming { call_id, conv_id, .. } = state {
        assert_eq!(call_id, "call-abc");
        assert_eq!(conv_id, "conv-2");
    }
}

#[tokio::test]
async fn test_incoming_session_has_local_answer_sdp() {
    let sess = SimulatedCallSession::new_incoming(
        "call-def".into(), "conv-3".into(), false,
        "v=0\r\ns=offer\r\n".into(), mock_audio(),
    ).await;
    // Local SDP should be an answer.
    assert!(sess.local_sdp.contains("answer"));
    assert!(sess.local_sdp.contains("call-def"));
}

// ---------------------------------------------------------------------------
// Audio / Video channel tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_audio_channel_produces_samples() {
    let mut sess = SimulatedCallSession::new_outgoing(
        "conv-1".into(), false, mock_audio(),
    ).await;
    sess.activate().await;

    // Give the background task time to produce samples.
    let samples = timeout(Duration::from_millis(200), sess.remote_audio_rx.recv())
        .await
        .expect("timed out waiting for audio")
        .expect("channel closed");

    assert_eq!(samples.len(), 480, "each audio frame is 480 samples @ 48 kHz");
    assert!(samples.iter().any(|&s| s != 0.0), "non-silent audio expected");
}

#[tokio::test]
async fn test_audio_only_call_has_no_video_channel() {
    let sess = SimulatedCallSession::new_outgoing(
        "conv-1".into(),
        false,           // audio-only
        mock_audio(),
    ).await;
    assert!(sess.remote_video_rx.is_none());
}

#[tokio::test]
async fn test_video_call_has_video_channel() {
    let mut sess = SimulatedCallSession::new_outgoing(
        "conv-1".into(),
        true,            // video enabled
        mock_video(),
    ).await;

    let frame = timeout(Duration::from_millis(500), async {
        sess.remote_video_rx.as_mut()?.recv().await
    })
    .await
    .expect("timed out")
    .expect("no video frame produced");

    assert_eq!(frame.width,  640);
    assert_eq!(frame.height, 480);
    assert_eq!(frame.rgba.len(), 640 * 480 * 4);
}

// ---------------------------------------------------------------------------
// ICE candidate tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ice_candidate_generated_at_session_start() {
    let mut sess = SimulatedCallSession::new_outgoing(
        "conv-1".into(), false, mock_audio(),
    ).await;

    // The session pre-populates one loopback ICE candidate.
    let cand = timeout(Duration::from_millis(100), sess.ice_rx.recv())
        .await
        .expect("timed out")
        .expect("no ICE candidate");

    assert!(cand.candidate.contains("127.0.0.1"));
}

#[tokio::test]
async fn test_remote_ice_candidate_roundtrips() {
    use transferd_webrtc::IceCandidateInit;
    let mut sess = SimulatedCallSession::new_outgoing(
        "conv-1".into(), false, mock_audio(),
    ).await;

    let remote = IceCandidateInit {
        candidate:       "candidate:2 1 udp 1677721855 10.0.0.1 50000 typ srflx".into(),
        sdp_mid:         Some("0".into()),
        sdp_mline_index: Some(0),
    };
    sess.add_remote_ice(remote.clone()).await;

    // The pre-seeded local candidate comes first; then our injected remote one.
    let _ = sess.ice_rx.recv().await; // local
    let received = timeout(Duration::from_millis(100), sess.ice_rx.recv())
        .await
        .expect("timed out")
        .expect("injected ICE not received");

    assert!(received.candidate.contains("srflx"));
}

// ---------------------------------------------------------------------------
// CallManager tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_manager_idle_by_default() {
    let mgr = CallManager::new();
    assert!(matches!(mgr.state().await, CallState::Idle));
    assert!(!mgr.is_active().await);
}

#[tokio::test]
async fn test_manager_start_call() {
    let mgr = CallManager::new();
    let call_id = mgr.start_call("conv-1".into(), false, mock_audio()).await.unwrap();
    assert!(!call_id.is_empty());
    assert!(matches!(mgr.state().await, CallState::Outgoing { .. }));
}

#[tokio::test]
async fn test_manager_end_call_returns_to_idle() {
    let mgr = CallManager::new();
    let _ = mgr.start_call("conv-1".into(), false, mock_audio()).await;
    mgr.end_call().await;
    // After ending, no session remains.
    assert!(matches!(mgr.state().await, CallState::Idle));
}

#[tokio::test]
async fn test_manager_accept_call_is_active() {
    let mgr = CallManager::new();
    let _sdp = mgr.accept_call(
        "call-xyz".into(),
        "conv-5".into(),
        false,
        mock_remote_offer(),
        mock_audio(),
    ).await.expect("accept_call failed");
    assert!(mgr.is_active().await);
}

// ---------------------------------------------------------------------------
// Mock media quality tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mock_audio_frequency_peak() {
    let media = Arc::new(MockMediaCapture::with_freq(1000.0));
    let mut rx = media.start_audio().await;

    // Collect ~0.5 s of audio.
    let mut all_samples: Vec<f32> = Vec::new();
    for _ in 0..50 {
        if let Some(chunk) = rx.recv().await {
            all_samples.extend(chunk);
        }
    }
    media.stop_audio().await;

    // All samples should be bounded to ±0.5.
    let max = all_samples.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let min = all_samples.iter().cloned().fold(f32::INFINITY, f32::min);
    assert!(max <=  0.51, "max = {max}");
    assert!(min >= -0.51, "min = {min}");
    // Signal is not silence.
    assert!(max > 0.1);
}

#[tokio::test]
async fn test_silent_capture_produces_zeros() {
    let media = Arc::new(SilentCapture);
    let mut rx = media.start_audio().await;
    let chunk = timeout(Duration::from_millis(100), rx.recv()).await
        .expect("timed out").expect("closed");
    assert!(chunk.iter().all(|&s| s == 0.0));
}

// ---------------------------------------------------------------------------
// IceCandidateInit serialization
// ---------------------------------------------------------------------------

#[test]
fn test_ice_candidate_json_roundtrip() {
    use transferd_webrtc::IceCandidateInit;
    let c = IceCandidateInit {
        candidate:       "candidate:1 1 udp 2 127.0.0.1 49152 typ host".into(),
        sdp_mid:         Some("audio".into()),
        sdp_mline_index: Some(0),
    };
    let json = c.to_json();
    assert!(json.contains("127.0.0.1"));
    let parsed = IceCandidateInit::from_json(&json).expect("parse failed");
    assert_eq!(parsed.candidate, c.candidate);
    assert_eq!(parsed.sdp_mid, c.sdp_mid);
}
