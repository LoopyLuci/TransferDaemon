/// gRPC-backed call signaling for TransferDaemon.
///
/// Requires the `grpc-signaling` feature.
use tonic::transport::Channel;
use transferd_api::{
    CallServiceClient,
    CallStartRequest, CallAcceptRequest, CallEndRequest, IceCandidateMsg,
    CallEvent, Empty,
};

// Re-exported so callers don't need to depend on transferd-api directly.
pub use transferd_api::CallEvent as SignalingEvent;

pub struct GrpcSignaling {
    channel: Channel,
    pub call_id: String,
}

impl GrpcSignaling {
    fn client(&self) -> CallServiceClient<Channel> {
        CallServiceClient::new(self.channel.clone())
    }

    /// Caller side: send an offer SDP and receive the call_id.
    pub async fn new_caller(
        channel: Channel,
        conv_id: &str,
        video: bool,
        offer_sdp: &str,
    ) -> Result<Self, tonic::Status> {
        let mut c = CallServiceClient::new(channel.clone());
        let resp = c
            .start_call(CallStartRequest {
                conv_id: conv_id.to_owned(),
                video,
                local_sdp: offer_sdp.to_owned(),
            })
            .await?
            .into_inner();
        Ok(Self { channel, call_id: resp.call_id })
    }

    /// Callee side: accept a pending call and get back the original offer SDP.
    pub async fn new_callee(
        channel: Channel,
        call_id: &str,
        answer_sdp: &str,
    ) -> Result<(Self, String), tonic::Status> {
        let mut c = CallServiceClient::new(channel.clone());
        let resp = c
            .accept_call(CallAcceptRequest {
                call_id: call_id.to_owned(),
                answer_sdp: answer_sdp.to_owned(),
            })
            .await?
            .into_inner();
        let offer_sdp = resp.remote_sdp;
        Ok((Self { channel, call_id: call_id.to_owned() }, offer_sdp))
    }

    /// Open the event stream.  Subscribe BEFORE sending an invite to avoid
    /// missing broadcast events (broadcast channel only delivers to live receivers).
    pub async fn subscribe(
        &self,
    ) -> Result<tonic::Streaming<CallEvent>, tonic::Status> {
        let mut c = self.client();
        Ok(c.stream_call_events(Empty {}).await?.into_inner())
    }

    /// Send an ICE candidate JSON string to the daemon.
    pub async fn send_ice(&self, candidate_json: &str) -> Result<(), tonic::Status> {
        let mut c = self.client();
        c.send_ice_candidate(IceCandidateMsg {
            call_id: self.call_id.clone(),
            candidate_json: candidate_json.to_owned(),
        })
        .await?;
        Ok(())
    }

    /// Terminate the call.
    pub async fn end(&self) -> Result<(), tonic::Status> {
        let mut c = self.client();
        c.end_call(CallEndRequest { call_id: self.call_id.clone() })
            .await?;
        Ok(())
    }
}
