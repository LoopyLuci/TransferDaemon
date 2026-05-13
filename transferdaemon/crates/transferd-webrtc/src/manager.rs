//! CallManager — coordinates call state in the UI layer.
//!
//! Sits between the UI and the `SimulatedCallSession`, handling:
//!   - start / answer / reject / hang-up actions
//!   - incoming call notifications
//!   - forwarding ICE candidates to the gRPC layer

use std::sync::Arc;
use tokio::sync::Mutex;
use crate::media::MediaCapture;
use crate::session::SimulatedCallSession;
use crate::types::CallState;

#[derive(Default)]
pub struct CallManager {
    session: Arc<Mutex<Option<SimulatedCallSession>>>,
}

impl CallManager {
    pub fn new() -> Self { Self::default() }

    /// Start an outgoing call.
    pub async fn start_call(
        &self,
        conv_id: String,
        video: bool,
        media: Arc<dyn MediaCapture>,
    ) -> String {
        let sess = SimulatedCallSession::new_outgoing(conv_id, video, media).await;
        let call_id = sess.call_id.clone();
        *self.session.lock().await = Some(sess);
        call_id
    }

    /// Accept an incoming call.
    pub async fn accept_call(
        &self,
        call_id: String,
        conv_id: String,
        video: bool,
        remote_sdp: String,
        media: Arc<dyn MediaCapture>,
    ) -> String {
        let sess = SimulatedCallSession::new_incoming(
            call_id, conv_id, video, remote_sdp, media,
        ).await;
        let local_sdp = sess.local_sdp.clone();
        sess.activate().await;
        *self.session.lock().await = Some(sess);
        local_sdp
    }

    /// Hang up or reject a call.
    pub async fn end_call(&self) {
        let mut guard = self.session.lock().await;
        if let Some(sess) = &*guard {
            sess.hang_up().await;
        }
        *guard = None;
    }

    /// Snapshot of the current call state.
    pub async fn state(&self) -> CallState {
        match &*self.session.lock().await {
            Some(s) => s.current_state().await,
            None    => CallState::Idle,
        }
    }

    /// `true` when a call is live.
    pub async fn is_active(&self) -> bool {
        self.state().await.is_active()
    }
}
