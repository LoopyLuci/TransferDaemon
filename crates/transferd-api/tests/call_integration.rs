//! gRPC integration tests for `CallService` (Phase 8).
//!
//! Each test spins up an in-process tonic server with a `TestCallService`
//! implementation and exercises the full RPC round-trip.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::TcpListener;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use tonic::{transport::Server, Request, Response, Status};
use transferd_api::{
    CallAcceptRequest, CallAcceptResponse, CallEndRequest, CallEvent, CallRejectRequest,
    CallService, CallServiceClient, CallServiceServer, CallStartRequest, CallStartResponse,
    Empty, IceCandidateMsg,
};

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64
}

// ---------------------------------------------------------------------------
// Test CallService implementation
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct CallRecord {
    conv_id:   String,
    video:     bool,
    local_sdp: String,
    state:     String, // "calling" | "active" | "rejected" | "ended"
}

struct TestCallService {
    calls: Arc<Mutex<HashMap<String, CallRecord>>>,
    events: tokio::sync::broadcast::Sender<CallEvent>,
}

impl TestCallService {
    fn new() -> (Self, tokio::sync::broadcast::Receiver<CallEvent>) {
        let (tx, rx) = tokio::sync::broadcast::channel(64);
        (
            Self {
                calls: Arc::new(Mutex::new(HashMap::new())),
                events: tx,
            },
            rx,
        )
    }

    fn gen_id(prefix: &str) -> String {
        format!("{prefix}-{:08x}", now_nanos())
    }
}

type BoxStream<T> = Pin<Box<dyn futures_core::Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl CallService for TestCallService {
    type StreamCallEventsStream = BoxStream<CallEvent>;

    async fn start_call(
        &self, req: Request<CallStartRequest>,
    ) -> Result<Response<CallStartResponse>, Status> {
        let r = req.into_inner();
        if r.conv_id.is_empty() {
            return Err(Status::invalid_argument("conv_id required"));
        }
        let call_id = Self::gen_id("call");
        self.calls.lock().unwrap().insert(
            call_id.clone(),
            CallRecord {
                conv_id:   r.conv_id.clone(),
                video:     r.video,
                local_sdp: r.local_sdp.clone(),
                state:     "calling".into(),
            },
        );
        let _ = self.events.send(CallEvent {
            call_id:    call_id.clone(),
            event_type: "invite".into(),
            payload:    r.local_sdp,
            conv_id:    r.conv_id,
            video:      r.video,
        });
        Ok(Response::new(CallStartResponse { call_id }))
    }

    async fn accept_call(
        &self, req: Request<CallAcceptRequest>,
    ) -> Result<Response<CallAcceptResponse>, Status> {
        let r = req.into_inner();
        let mut calls = self.calls.lock().unwrap();
        match calls.get_mut(&r.call_id) {
            Some(rec) if rec.state == "calling" => {
                let remote_sdp = rec.local_sdp.clone();
                rec.state = "active".into();
                let _ = self.events.send(CallEvent {
                    call_id:    r.call_id.clone(),
                    event_type: "accepted".into(),
                    payload:    r.answer_sdp,
                    conv_id:    rec.conv_id.clone(),
                    video:      rec.video,
                });
                Ok(Response::new(CallAcceptResponse { accepted: true, remote_sdp }))
            }
            Some(_) => Err(Status::failed_precondition("call not in calling state")),
            None    => Err(Status::not_found("call not found")),
        }
    }

    async fn reject_call(
        &self, req: Request<CallRejectRequest>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();
        let mut calls = self.calls.lock().unwrap();
        match calls.get_mut(&r.call_id) {
            Some(rec) => {
                rec.state = "rejected".into();
                let _ = self.events.send(CallEvent {
                    call_id:    r.call_id,
                    event_type: "rejected".into(),
                    payload:    String::new(),
                    conv_id:    rec.conv_id.clone(),
                    video:      false,
                });
                Ok(Response::new(Empty {}))
            }
            None => Err(Status::not_found("call not found")),
        }
    }

    async fn end_call(
        &self, req: Request<CallEndRequest>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();
        let mut calls = self.calls.lock().unwrap();
        match calls.get_mut(&r.call_id) {
            Some(rec) => {
                rec.state = "ended".into();
                let _ = self.events.send(CallEvent {
                    call_id:    r.call_id,
                    event_type: "ended".into(),
                    payload:    String::new(),
                    conv_id:    rec.conv_id.clone(),
                    video:      false,
                });
                Ok(Response::new(Empty {}))
            }
            None => Err(Status::not_found("call not found")),
        }
    }

    async fn send_ice_candidate(
        &self, req: Request<IceCandidateMsg>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();
        let calls = self.calls.lock().unwrap();
        if !calls.contains_key(&r.call_id) {
            return Err(Status::not_found("call not found"));
        }
        let _ = self.events.send(CallEvent {
            call_id:    r.call_id,
            event_type: "ice_candidate".into(),
            payload:    r.candidate_json,
            conv_id:    String::new(),
            video:      false,
        });
        Ok(Response::new(Empty {}))
    }

    async fn stream_call_events(
        &self, _: Request<Empty>,
    ) -> Result<Response<Self::StreamCallEventsStream>, Status> {
        let rx = self.events.subscribe();
        let stream = BroadcastStream::new(rx).filter_map(|r| match r {
            Ok(e)  => Some(Ok(e)),
            Err(_) => None,
        });
        Ok(Response::new(Box::pin(stream)))
    }
}

// ---------------------------------------------------------------------------
// Test server launcher
// ---------------------------------------------------------------------------

async fn start_call_server() -> (SocketAddr, tokio::sync::broadcast::Receiver<CallEvent>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (svc, rx) = TestCallService::new();

    tokio::spawn(async move {
        Server::builder()
            .add_service(CallServiceServer::new(svc))
            .serve_with_incoming(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
            )
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, rx)
}

async fn call_client(addr: SocketAddr) -> CallServiceClient<tonic::transport::Channel> {
    let url = format!("http://{addr}");
    CallServiceClient::connect(url).await.unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_start_call_returns_call_id() {
    let (addr, _rx) = start_call_server().await;
    let mut c = call_client(addr).await;

    let resp = c.start_call(CallStartRequest {
        conv_id:   "conv-1".into(),
        video:     false,
        local_sdp: "v=0\r\ns=offer\r\n".into(),
    }).await.unwrap().into_inner();

    assert!(!resp.call_id.is_empty());
}

#[tokio::test]
async fn test_start_call_empty_conv_id_rejected() {
    let (addr, _rx) = start_call_server().await;
    let mut c = call_client(addr).await;

    let err = c.start_call(CallStartRequest {
        conv_id: "".into(), video: false, local_sdp: "".into(),
    }).await;
    assert!(err.is_err());
    assert_eq!(err.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_accept_call_returns_remote_sdp() {
    let (addr, _rx) = start_call_server().await;
    let mut c = call_client(addr).await;

    let offer_sdp = "v=0\r\ns=offer\r\n";
    let call_id = c.start_call(CallStartRequest {
        conv_id: "conv-1".into(), video: false, local_sdp: offer_sdp.into(),
    }).await.unwrap().into_inner().call_id;

    let accept = c.accept_call(CallAcceptRequest {
        call_id:    call_id.clone(),
        answer_sdp: "v=0\r\ns=answer\r\n".into(),
    }).await.unwrap().into_inner();

    assert!(accept.accepted);
    assert_eq!(accept.remote_sdp, offer_sdp, "remote SDP should be the original offer");
}

#[tokio::test]
async fn test_accept_unknown_call_rejected() {
    let (addr, _rx) = start_call_server().await;
    let mut c = call_client(addr).await;

    let err = c.accept_call(CallAcceptRequest {
        call_id: "nonexistent".into(), answer_sdp: "".into(),
    }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_reject_call() {
    let (addr, _rx) = start_call_server().await;
    let mut c = call_client(addr).await;

    let call_id = c.start_call(CallStartRequest {
        conv_id: "conv-2".into(), video: true, local_sdp: "v=0\r\n".into(),
    }).await.unwrap().into_inner().call_id;

    // Rejecting must succeed.
    c.reject_call(CallRejectRequest { call_id: call_id.clone() })
        .await.unwrap();

    // Accepting after rejection must fail.
    let err = c.accept_call(CallAcceptRequest {
        call_id, answer_sdp: "v=0\r\n".into(),
    }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn test_end_call_unknown_returns_not_found() {
    let (addr, _rx) = start_call_server().await;
    let mut c = call_client(addr).await;

    let err = c.end_call(CallEndRequest { call_id: "ghost".into() }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_ice_candidate_forwarded_as_event() {
    let (addr, mut rx) = start_call_server().await;
    let mut c = call_client(addr).await;

    let call_id = c.start_call(CallStartRequest {
        conv_id: "conv-3".into(), video: false, local_sdp: "v=0\r\n".into(),
    }).await.unwrap().into_inner().call_id;

    // Drain the "invite" event.
    let _ = rx.recv().await.unwrap();

    let ice_json = r#"{"candidate":"candidate:1 1 udp 2 127.0.0.1 49152 typ host","sdp_mid":"0","sdp_mline_index":0}"#;
    c.send_ice_candidate(IceCandidateMsg {
        call_id:        call_id.clone(),
        candidate_json: ice_json.into(),
    }).await.unwrap();

    let event = tokio::time::timeout(
        std::time::Duration::from_millis(200), rx.recv(),
    ).await.expect("timed out").unwrap();

    assert_eq!(event.event_type, "ice_candidate");
    assert_eq!(event.call_id, call_id);
    assert!(event.payload.contains("127.0.0.1"));
}

#[tokio::test]
async fn test_stream_call_events_receives_invite() {
    let (addr, _rx) = start_call_server().await;
    let url = format!("http://{addr}");

    // Connect two clients: one to stream events, one to start a call.
    let mut stream_client  = CallServiceClient::connect(url.clone()).await.unwrap();
    let mut caller_client  = CallServiceClient::connect(url).await.unwrap();

    // Subscribe to events before starting the call.
    let mut event_stream = stream_client
        .stream_call_events(Empty {})
        .await
        .unwrap()
        .into_inner();

    // Start a call.
    let call_id = caller_client.start_call(CallStartRequest {
        conv_id: "conv-4".into(), video: true, local_sdp: "v=0\r\ns=offer\r\n".into(),
    }).await.unwrap().into_inner().call_id;

    // The event stream should deliver the "invite" event.
    let event = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        event_stream.next(),
    ).await.expect("timed out waiting for event")
     .expect("stream ended")
     .unwrap();

    assert_eq!(event.event_type, "invite");
    assert_eq!(event.call_id, call_id);
    assert!(event.video);
    assert_eq!(event.conv_id, "conv-4");
}
