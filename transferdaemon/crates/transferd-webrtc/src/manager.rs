//! CallManager — coordinates call state in the UI layer.
//!
//! Sits between the UI and the session implementation, handling:
//!   - start / answer / reject / hang-up actions
//!   - incoming call notifications
//!   - forwarding ICE candidates to the gRPC layer
//!
//! With the `real-webrtc` feature, uses `RtcCallSession` for actual peer-to-peer
//! media transport. Without it, uses `SimulatedCallSession` for testing.

use std::sync::Arc;
use tokio::sync::Mutex;
use crate::media::MediaCapture;
use crate::session::SimulatedCallSession;
use crate::types::{CallState, IceCandidateInit, VideoFrame};

#[cfg(feature = "real-webrtc")]
use crate::rtc_session::RtcCallSession;

/// Internal session enum — either simulated or real WebRTC.
enum SessionInner {
    #[allow(dead_code)]
    Simulated(SimulatedCallSession),
    #[cfg(feature = "real-webrtc")]
    Real(RtcCallSession),
}

#[derive(Default)]
pub struct CallManager {
    session: Arc<Mutex<Option<SessionInner>>>,
    /// Send-bandwidth cap in kbps applied to calls (from the daemon's
    /// `limits.call_kbps`). `None` = unbounded. Set by the UI layer.
    pub max_kbps: Option<u64>,
}

impl CallManager {
    pub fn new() -> Self { Self::default() }

    /// Start an outgoing call.
    pub async fn start_call(
        &self,
        conv_id: String,
        video: bool,
        media: Arc<dyn MediaCapture>,
        max_kbps: Option<u64>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let max_kbps = max_kbps.or(self.max_kbps);
        #[cfg(feature = "real-webrtc")]
        {
            let sess = RtcCallSession::new_outgoing(conv_id, video, media, max_kbps).await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(e)
                })?;
            let call_id = sess.call_id.clone();
            let _local_sdp = sess.local_sdp_json().to_string();
            *self.session.lock().await = Some(SessionInner::Real(sess));
            Ok(call_id)
        }

        #[cfg(not(feature = "real-webrtc"))]
        {
            let sess = SimulatedCallSession::new_outgoing(conv_id, video, media).await;
            let call_id = sess.call_id.clone();
            *self.session.lock().await = Some(SessionInner::Simulated(sess));
            Ok(call_id)
        }
    }

    /// Accept an incoming call.
    pub async fn accept_call(
        &self,
        call_id: String,
        conv_id: String,
        video: bool,
        remote_sdp: String,
        media: Arc<dyn MediaCapture>,
        max_kbps: Option<u64>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let max_kbps = max_kbps.or(self.max_kbps);
        #[cfg(feature = "real-webrtc")]
        {
            let sess = RtcCallSession::new_incoming(
                call_id, conv_id, video, remote_sdp, media, max_kbps,
            ).await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(e)
                })?;
            let local_sdp = sess.local_sdp_json().to_string();
            sess.activate().await;
            *self.session.lock().await = Some(SessionInner::Real(sess));
            Ok(local_sdp)
        }

        #[cfg(not(feature = "real-webrtc"))]
        {
            let sess = SimulatedCallSession::new_incoming(
                call_id, conv_id, video, remote_sdp, media,
            ).await;
            let local_sdp = sess.local_sdp.clone();
            sess.activate().await;
            *self.session.lock().await = Some(SessionInner::Simulated(sess));
            Ok(local_sdp)
        }
    }

    /// Hang up or reject a call.
    pub async fn end_call(&self) {
        let mut guard = self.session.lock().await;
        if let Some(inner) = &*guard {
            match inner {
                SessionInner::Simulated(s) => s.hang_up().await,
                #[cfg(feature = "real-webrtc")]
                SessionInner::Real(s) => s.hang_up().await,
            }
        }
        *guard = None;
    }

    /// Snapshot of the current call state.
    pub async fn state(&self) -> CallState {
        match &*self.session.lock().await {
            Some(inner) => match inner {
                SessionInner::Simulated(s) => s.current_state().await,
                #[cfg(feature = "real-webrtc")]
                SessionInner::Real(s) => s.current_state().await,
            },
            None => CallState::Idle,
        }
    }

    /// `true` when a call is live.
    pub async fn is_active(&self) -> bool {
        self.state().await.is_active()
    }

    /// Non-blocking drain of the latest remote video frame, if any.
    /// Returns `None` when there is no active call or no pending frame.
    pub async fn poll_remote_video(&self) -> Option<VideoFrame> {
        let mut guard = self.session.lock().await;
        let inner = guard.as_mut()?;
        match inner {
            SessionInner::Simulated(s) => {
                let rx = s.remote_video_rx.as_mut()?;
                rx.try_recv().ok()
            }
            #[cfg(feature = "real-webrtc")]
            SessionInner::Real(s) => {
                let rx = s.remote_video_rx.as_mut()?;
                rx.try_recv().ok()
            }
        }
    }

    /// Inject an ICE candidate from the remote peer.
    pub async fn add_remote_ice(&self, candidate: IceCandidateInit) {
        let guard = self.session.lock().await;
        if let Some(inner) = &*guard {
            match inner {
                SessionInner::Simulated(s) => s.add_remote_ice(candidate).await,
                #[cfg(feature = "real-webrtc")]
                SessionInner::Real(s) => s.add_remote_ice(candidate).await,
            }
        }
    }

    /// Get the local SDP (offer or answer) as a JSON string.
    pub async fn local_sdp(&self) -> Option<String> {
        let guard = self.session.lock().await;
        guard.as_ref().map(|inner| match inner {
            SessionInner::Simulated(s) => s.local_sdp.clone(),
            #[cfg(feature = "real-webrtc")]
            SessionInner::Real(s) => s.local_sdp_json().to_string(),
        })
    }

    /// Set the remote SDP answer (for outgoing calls, real WebRTC only).
    pub async fn set_remote_answer(&self, _answer_sdp: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let guard = self.session.lock().await;
        if let Some(inner) = &*guard {
            match inner {
                SessionInner::Simulated(_) => {
                    // Simulated session doesn't need remote answer
                    Ok(())
                }
                #[cfg(feature = "real-webrtc")]
                SessionInner::Real(s) => {
                    s.set_remote_answer(_answer_sdp).await
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                            Box::new(e)
                        })
                }
            }
        } else {
            Ok(())
        }
    }
}
