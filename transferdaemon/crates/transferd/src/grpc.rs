//! gRPC service implementations for all six TransferDaemon services.

use std::pin::Pin;
use std::sync::Arc;
use parking_lot::Mutex;
use tonic::{Request, Response, Status};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;

use transferd_api::{
    // Account
    AccountService, AccountServiceServer,
    CreateIdentityRequest, RestoreIdentityRequest, IdentityReply,
    RecoveryPhraseReply, PublicKeyReply, Empty,
    // Friends
    FriendService, FriendServiceServer,
    AddContactRequest, ContactReply, ContactList,
    // Messages
    MessageService, MessageServiceServer,
    GetMessagesRequest, MessageReply, MessageList, SendTextRequest,
    // Transfers
    TransferService, TransferServiceServer,
    TransferReply, TransferList, SendFileRequest,
    // Settings
    SettingsService, SettingsServiceServer,
    GetSettingRequest, SetSettingRequest, SettingReply,
    // Calls
    CallService, CallServiceServer,
    CallStartRequest, CallStartResponse,
    CallAcceptRequest, CallAcceptResponse,
    CallRejectRequest, CallEndRequest,
    IceCandidateMsg, CallEvent,
};

use crate::state::{DaemonState, Contact, CallRecord, StoredMessage, now_secs};

type State = Arc<Mutex<DaemonState>>;
type BoxStream<T> = Pin<Box<dyn futures::Stream<Item = Result<T, Status>> + Send>>;

// ---------------------------------------------------------------------------
// AccountServiceImpl
// ---------------------------------------------------------------------------

pub struct AccountServiceImpl(pub State);

#[tonic::async_trait]
impl AccountService for AccountServiceImpl {
    async fn get_identity(&self, _: Request<Empty>) -> Result<Response<IdentityReply>, Status> {
        let s = self.0.lock();
        Ok(Response::new(match &s.identity {
            Some(id) => IdentityReply {
                has_identity: true,
                public_key:   id.public_key.clone(),
                display_name: id.display_name.clone(),
            },
            None => IdentityReply { has_identity: false, ..Default::default() },
        }))
    }

    async fn create_identity(
        &self, req: Request<CreateIdentityRequest>,
    ) -> Result<Response<RecoveryPhraseReply>, Status> {
        let name = req.into_inner().display_name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("display name required"));
        }
        let phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident".to_string();
        let pk = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233".to_string();
        let mut s = self.0.lock();
        s.identity = Some(crate::state::Identity { public_key: pk, display_name: name, phrase: phrase.clone() });
        Ok(Response::new(RecoveryPhraseReply { phrase }))
    }

    async fn restore_identity(
        &self, req: Request<RestoreIdentityRequest>,
    ) -> Result<Response<IdentityReply>, Status> {
        let phrase = req.into_inner().phrase;
        if phrase.split_whitespace().count() < 12 {
            return Err(Status::invalid_argument("recovery phrase must be at least 12 words"));
        }
        let pk = "cafebabe00000000cafebabe00000000cafebabe00000000cafebabe00000000".to_string();
        let mut s = self.0.lock();
        s.identity = Some(crate::state::Identity {
            public_key: pk.clone(),
            display_name: "Restored Identity".into(),
            phrase: String::new(),
        });
        Ok(Response::new(IdentityReply { has_identity: true, public_key: pk, display_name: "Restored Identity".into() }))
    }

    async fn get_public_key_hex(&self, _: Request<Empty>) -> Result<Response<PublicKeyReply>, Status> {
        let s = self.0.lock();
        Ok(Response::new(PublicKeyReply {
            hex: s.identity.as_ref().map(|i| i.public_key.clone()).unwrap_or_default(),
        }))
    }
}

// ---------------------------------------------------------------------------
// FriendServiceImpl
// ---------------------------------------------------------------------------

pub struct FriendServiceImpl(pub State);

#[tonic::async_trait]
impl FriendService for FriendServiceImpl {
    async fn get_contacts(&self, _: Request<Empty>) -> Result<Response<ContactList>, Status> {
        let s = self.0.lock();
        let contacts = s.contacts.iter().map(|c| ContactReply {
            id:           c.id.clone(),
            name:         c.name.clone(),
            last_seen_ts: c.last_seen_ts,
            online:       c.online,
        }).collect();
        Ok(Response::new(ContactList { contacts }))
    }

    async fn add_contact(
        &self, req: Request<AddContactRequest>,
    ) -> Result<Response<ContactReply>, Status> {
        let r = req.into_inner();
        if r.public_key.len() != 64 {
            return Err(Status::invalid_argument("public key must be 64 hex chars"));
        }
        if r.name.trim().is_empty() {
            return Err(Status::invalid_argument("name required"));
        }
        let contact = Contact {
            id:           r.public_key.clone(),
            name:         r.name.clone(),
            last_seen_ts: 0,
            online:       false,
        };
        let mut s = self.0.lock();
        // Prevent duplicates.
        if s.contacts.iter().any(|c| c.id == r.public_key) {
            return Err(Status::already_exists("contact already exists"));
        }
        s.contacts.push(contact);
        Ok(Response::new(ContactReply {
            id:           r.public_key,
            name:         r.name,
            last_seen_ts: 0,
            online:       false,
        }))
    }
}

// ---------------------------------------------------------------------------
// MessageServiceImpl
// ---------------------------------------------------------------------------

pub struct MessageServiceImpl(pub State);

fn stored_to_reply(m: &StoredMessage) -> MessageReply {
    MessageReply {
        id:               m.id.clone(),
        contact_id:       m.contact_id.clone(),
        outbound:         m.outbound,
        content_type:     m.content_type.clone(),
        text:             m.text.clone(),
        file_name:        m.file_name.clone(),
        file_size_bytes:  m.file_size,
        file_transferred: m.file_xferd,
        file_mime:        m.file_mime.clone(),
        timestamp_ts:     m.timestamp_ts,
        status:           m.status.clone(),
    }
}

#[tonic::async_trait]
impl MessageService for MessageServiceImpl {
    async fn get_messages(
        &self, req: Request<GetMessagesRequest>,
    ) -> Result<Response<MessageList>, Status> {
        let cid = req.into_inner().contact_id;
        let s = self.0.lock();
        let messages = s.messages.get(&cid)
            .map(|v| v.iter().map(stored_to_reply).collect())
            .unwrap_or_default();
        Ok(Response::new(MessageList { messages }))
    }

    async fn send_text(
        &self, req: Request<SendTextRequest>,
    ) -> Result<Response<MessageReply>, Status> {
        let r = req.into_inner();
        if r.text.trim().is_empty() {
            return Err(Status::invalid_argument("message text required"));
        }
        let mut s = self.0.lock();
        let id = s.next_id();
        let msg = StoredMessage::new_text(id, r.contact_id.clone(), true, r.text);
        let reply = stored_to_reply(&msg);
        s.messages.entry(r.contact_id).or_default().push(msg);
        Ok(Response::new(reply))
    }
}

// ---------------------------------------------------------------------------
// TransferServiceImpl
// ---------------------------------------------------------------------------

pub struct TransferServiceImpl(pub State);

#[tonic::async_trait]
impl TransferService for TransferServiceImpl {
    async fn get_transfers(&self, _: Request<Empty>) -> Result<Response<TransferList>, Status> {
        let s = self.0.lock();
        let transfers = s.transfers.iter().map(|t| TransferReply {
            id:               t.id.clone(),
            contact_name:     t.contact_name.clone(),
            file_name:        t.file_name.clone(),
            size_bytes:       t.size_bytes,
            transferred_bytes: t.xferd_bytes,
            outbound:         t.outbound,
            lanes_active:     t.lanes_active,
            bps:              t.bps,
        }).collect();
        Ok(Response::new(TransferList { transfers }))
    }

    async fn send_file(
        &self, req: Request<SendFileRequest>,
    ) -> Result<Response<MessageReply>, Status> {
        let r = req.into_inner();
        if r.contact_id.is_empty() {
            return Err(Status::invalid_argument("contact_id required"));
        }
        let size_bytes = if r.file_size > 0 {
            r.file_size
        } else {
            std::fs::metadata(&r.file_path).map(|m| m.len()).unwrap_or(0)
        };
        let mut s = self.0.lock();
        let id = s.next_id();
        let msg = crate::state::StoredMessage {
            id: id.clone(),
            contact_id: r.contact_id.clone(),
            outbound: true,
            content_type: "file".into(),
            text: String::new(),
            file_name: r.file_name.clone(),
            file_size: size_bytes,
            file_xferd: size_bytes,
            file_mime: r.mime_type.clone(),
            timestamp_ts: now_secs(),
            status: "sent".into(),
        };
        let tid = s.next_id();
        s.transfers.push(crate::state::Transfer {
            id: tid,
            contact_name: r.contact_id.clone(),
            file_name: r.file_name,
            size_bytes,
            xferd_bytes: size_bytes,
            outbound: true,
            lanes_active: 1,
            bps: 0,
        });
        let reply = stored_to_reply(&msg);
        s.messages.entry(r.contact_id).or_default().push(msg);
        Ok(Response::new(reply))
    }
}

// ---------------------------------------------------------------------------
// SettingsServiceImpl
// ---------------------------------------------------------------------------

pub struct SettingsServiceImpl(pub State);

#[tonic::async_trait]
impl SettingsService for SettingsServiceImpl {
    async fn get_setting(
        &self, req: Request<GetSettingRequest>,
    ) -> Result<Response<SettingReply>, Status> {
        let key = req.into_inner().key;
        let s = self.0.lock();
        match s.settings.get(&key) {
            Some(v) => Ok(Response::new(SettingReply { value: v.clone(), found: true })),
            None    => Ok(Response::new(SettingReply { value: String::new(), found: false })),
        }
    }

    async fn set_setting(
        &self, req: Request<SetSettingRequest>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();
        self.0.lock().settings.insert(r.key, r.value);
        Ok(Response::new(Empty {}))
    }
}

// ---------------------------------------------------------------------------
// CallServiceImpl
// ---------------------------------------------------------------------------

pub struct CallServiceImpl {
    pub state:  State,
    pub events: broadcast::Sender<CallEvent>,
}

impl CallServiceImpl {
    pub fn new(state: State) -> Self {
        let (events, _) = broadcast::channel(64);
        Self { state, events }
    }
}

#[tonic::async_trait]
impl CallService for CallServiceImpl {
    type StreamCallEventsStream = BoxStream<CallEvent>;

    async fn start_call(
        &self, req: Request<CallStartRequest>,
    ) -> Result<Response<CallStartResponse>, Status> {
        let r = req.into_inner();
        if r.conv_id.is_empty() {
            return Err(Status::invalid_argument("conv_id required"));
        }
        let call_id = {
            let mut s = self.state.lock();
            let id = s.next_id();
            s.calls.insert(id.clone(), CallRecord {
                conv_id:   r.conv_id.clone(),
                video:     r.video,
                local_sdp: r.local_sdp.clone(),
                state:     "calling".into(),
            });
            id
        };
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
        let mut s = self.state.lock();
        match s.calls.get_mut(&r.call_id) {
            Some(rec) if rec.state == "calling" => {
                let remote_sdp = rec.local_sdp.clone();
                let conv_id = rec.conv_id.clone();
                let video = rec.video;
                rec.state = "active".into();
                let _ = self.events.send(CallEvent {
                    call_id:    r.call_id,
                    event_type: "accepted".into(),
                    payload:    r.answer_sdp,
                    conv_id,
                    video,
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
        let mut s = self.state.lock();
        match s.calls.get_mut(&r.call_id) {
            Some(rec) => {
                let conv_id = rec.conv_id.clone();
                rec.state = "rejected".into();
                let _ = self.events.send(CallEvent {
                    call_id: r.call_id, event_type: "rejected".into(),
                    payload: String::new(), conv_id, video: false,
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
        let mut s = self.state.lock();
        match s.calls.get_mut(&r.call_id) {
            Some(rec) => {
                let conv_id = rec.conv_id.clone();
                rec.state = "ended".into();
                let _ = self.events.send(CallEvent {
                    call_id: r.call_id, event_type: "ended".into(),
                    payload: String::new(), conv_id, video: false,
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
        let s = self.state.lock();
        if !s.calls.contains_key(&r.call_id) {
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

/// Attach all six TransferDaemon gRPC services to a tonic `Server::builder`.
pub fn add_all_services(
    mut builder: tonic::transport::Server,
    state: State,
) -> tonic::transport::server::Router {
    use transferd_api::{
        AccountServiceServer, FriendServiceServer, MessageServiceServer,
        TransferServiceServer, SettingsServiceServer, CallServiceServer,
    };
    let call_svc = CallServiceImpl::new(state.clone());
    builder
        .add_service(AccountServiceServer::new(AccountServiceImpl(state.clone())))
        .add_service(FriendServiceServer::new(FriendServiceImpl(state.clone())))
        .add_service(MessageServiceServer::new(MessageServiceImpl(state.clone())))
        .add_service(TransferServiceServer::new(TransferServiceImpl(state.clone())))
        .add_service(SettingsServiceServer::new(SettingsServiceImpl(state)))
        .add_service(CallServiceServer::new(call_svc))
}
