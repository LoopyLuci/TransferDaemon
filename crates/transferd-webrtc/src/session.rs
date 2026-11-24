//! SimulatedCallSession — full call lifecycle without hardware WebRTC.
//!
//! This implementation exercises the exact same state machine, channels, and
//! SDP-exchange logic as `RtcCallSession` would use with `webrtc-rs`, but
//! replaces the actual codec/network stack with in-memory channels.  All tests
//! use this; the real WebRTC session is introduced per-platform later.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};
use crate::media::MediaCapture;
use crate::types::{AudioSamples, CallState, IceCandidateInit, VideoFrame};

// ---------------------------------------------------------------------------
// SimulatedCallSession
// ---------------------------------------------------------------------------

pub struct SimulatedCallSession {
    /// Stable call identifier assigned by the daemon.
    pub call_id: String,
    pub conv_id: String,
    pub video:   bool,

    /// Synthetic SDP offer produced by this session.
    pub local_sdp: String,

    /// Current call state (shared so the UI can observe it cheaply).
    pub state: Arc<Mutex<CallState>>,

    /// Incoming audio from the remote peer (looped-back from local capture
    /// in simulated mode; would be decoded RTP in real mode).
    pub remote_audio_rx: mpsc::Receiver<AudioSamples>,

    /// Incoming video from the remote peer. `None` for audio-only calls.
    pub remote_video_rx: Option<mpsc::Receiver<VideoFrame>>,

    /// ICE candidates queued by `on_ice_candidate` callbacks.
    pub ice_rx: mpsc::Receiver<IceCandidateInit>,
    ice_tx: mpsc::Sender<IceCandidateInit>,

    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl SimulatedCallSession {
    /// Create an outgoing call session.  SDP is generated immediately;
    /// call `activate()` once the remote answer arrives.
    pub async fn new_outgoing(
        conv_id: String,
        video: bool,
        media: Arc<dyn MediaCapture>,
    ) -> Self {
        let call_id = gen_id("call");
        let local_sdp = make_sdp(&call_id, "offer");
        let state = Arc::new(Mutex::new(CallState::Outgoing {
            call_id: call_id.clone(),
            conv_id: conv_id.clone(),
        }));
        Self::build(call_id, conv_id, video, local_sdp, state, media).await
    }

    /// Create an incoming call session.  `remote_sdp` is the caller's offer.
    /// Produces a local SDP answer; call `activate()` after sending the answer.
    pub async fn new_incoming(
        call_id: String,
        conv_id: String,
        video: bool,
        remote_sdp: String,
        media: Arc<dyn MediaCapture>,
    ) -> Self {
        let local_sdp = make_sdp(&call_id, "answer");
        let state = Arc::new(Mutex::new(CallState::Incoming {
            call_id: call_id.clone(),
            conv_id: conv_id.clone(),
            video,
            remote_sdp,
        }));
        Self::build(call_id, conv_id, video, local_sdp, state, media).await
    }

    async fn build(
        call_id: String,
        conv_id: String,
        video: bool,
        local_sdp: String,
        state: Arc<Mutex<CallState>>,
        media: Arc<dyn MediaCapture>,
    ) -> Self {
        let mut tasks = Vec::new();

        // Audio: pipe local capture into the remote_audio channel (loopback).
        let (audio_tx, remote_audio_rx) = mpsc::channel(64);
        let mut local_audio = media.start_audio().await;
        tasks.push(tokio::spawn(async move {
            while let Some(samples) = local_audio.recv().await {
                if audio_tx.send(samples).await.is_err() { break; }
            }
        }));

        // Video: if requested, pipe local video into the remote_video channel.
        let remote_video_rx = if video {
            if let Some(mut src) = media.start_video().await {
                let (vt, vr) = mpsc::channel(4);
                tasks.push(tokio::spawn(async move {
                    while let Some(f) = src.recv().await {
                        if vt.send(f).await.is_err() { break; }
                    }
                }));
                Some(vr)
            } else {
                None
            }
        } else {
            None
        };

        // ICE candidates channel (simulated — no actual network candidates).
        let (ice_tx, ice_rx) = mpsc::channel(16);

        // Synthesise a single loopback ICE candidate immediately.
        let candidate = IceCandidateInit {
            candidate:       format!("candidate:1 1 udp 2130706431 127.0.0.1 {} typ host", 49152),
            sdp_mid:         Some("0".into()),
            sdp_mline_index: Some(0),
        };
        let _ = ice_tx.try_send(candidate);

        Self {
            call_id,
            conv_id,
            video,
            local_sdp,
            state,
            remote_audio_rx,
            remote_video_rx,
            ice_rx,
            ice_tx,
            _tasks: tasks,
        }
    }

    /// Transition to `Active` state once both SDPs have been exchanged.
    pub async fn activate(&self) {
        let mut s = self.state.lock().await;
        *s = CallState::Active {
            call_id: self.call_id.clone(),
            conv_id: self.conv_id.clone(),
        };
    }

    /// Hang up the call, transitioning to `Ended`.
    pub async fn hang_up(&self) {
        *self.state.lock().await = CallState::Ended;
    }

    /// Snapshot the current call state without blocking the UI thread.
    pub async fn current_state(&self) -> CallState {
        self.state.lock().await.clone()
    }

    /// Inject an external ICE candidate (from the remote peer) into the session.
    pub async fn add_remote_ice(&self, candidate: IceCandidateInit) {
        let _ = self.ice_tx.send(candidate).await;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn gen_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("{prefix}-{nanos:08x}")
}

fn make_sdp(call_id: &str, kind: &str) -> String {
    format!(
        "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=TransferDaemon-{kind}-{call_id}\r\n\
         c=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio 49152 RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\n"
    )
}
