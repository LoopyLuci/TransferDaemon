//! Integration tests for the transferd gRPC API layer.
//!
//! Each test spins up a full in-process tonic server, connects a `GrpcDaemon`
//! client to it, and exercises the full RPC round-trip.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::TcpListener;
use tonic::{transport::Server, Request, Response, Status};
use transferd_api::{
    AccountService, AccountServiceServer,
    FriendService, FriendServiceServer,
    MessageService, MessageServiceServer,
    SendTypingRequest, ReactionRequest,
    TransferService, TransferServiceServer,
    SettingsService, SettingsServiceServer,
    AddContactRequest, ContactList, ContactReply,
    RenameContactRequest, RemoveContactRequest, BlockContactRequest,
    SafetyNumberRequest, SafetyNumberReply,
    CreateIdentityRequest, Empty,
    GetMessagesRequest, GetSettingRequest, IdentityReply, MessageList, MessageReply,
    PublicKeyReply, RecoveryPhraseReply, RestoreIdentityRequest, SendFileRequest,
    SendTextRequest, SetSettingRequest, SettingReply, TransferList, TransferReply,
    SearchMessagesRequest,
};

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// In-process test server state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ServerState {
    public_key: Option<String>,
    display_name: Option<String>,
    contacts: Vec<ContactReply>,
    messages: HashMap<String, Vec<MessageReply>>,
    settings: HashMap<String, String>,
    next_id: u64,
}

impl ServerState {
    fn next_id(&mut self) -> String {
        self.next_id += 1;
        format!("srv-{}", self.next_id)
    }
}

type SharedState = Arc<Mutex<ServerState>>;

// ---------------------------------------------------------------------------
// AccountService impl
// ---------------------------------------------------------------------------

struct TestAccountService(SharedState);

#[tonic::async_trait]
impl AccountService for TestAccountService {
    async fn get_identity(&self, _: Request<Empty>) -> Result<Response<IdentityReply>, Status> {
        let s = self.0.lock().unwrap();
        Ok(Response::new(IdentityReply {
            has_identity:      s.public_key.is_some(),
            public_key:        s.public_key.clone().unwrap_or_default(),
            hybrid_public_key: String::new(),
            display_name:      s.display_name.clone().unwrap_or_default(),
        }))
    }

    async fn create_identity(
        &self, req: Request<CreateIdentityRequest>,
    ) -> Result<Response<RecoveryPhraseReply>, Status> {
        let mut s = self.0.lock().unwrap();
        let name = req.into_inner().display_name;
        if name.is_empty() {
            return Err(Status::invalid_argument("display name required"));
        }
        s.display_name = Some(name);
        s.public_key = Some("aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233".into());
        Ok(Response::new(RecoveryPhraseReply {
            phrase: "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima".into(),
        }))
    }

    async fn restore_identity(
        &self, req: Request<RestoreIdentityRequest>,
    ) -> Result<Response<IdentityReply>, Status> {
        let phrase = req.into_inner().phrase;
        if phrase.split_whitespace().count() < 12 {
            return Err(Status::invalid_argument("phrase must be at least 12 words"));
        }
        let mut s = self.0.lock().unwrap();
        s.public_key = Some("cafebabe00000000cafebabe00000000cafebabe00000000cafebabe00000000".into());
        s.display_name = Some("Restored".into());
        Ok(Response::new(IdentityReply {
            has_identity:      true,
            public_key:        s.public_key.clone().unwrap(),
            hybrid_public_key: String::new(),
            display_name:      s.display_name.clone().unwrap(),
        }))
    }

    async fn get_public_key_hex(
        &self, _: Request<Empty>,
    ) -> Result<Response<PublicKeyReply>, Status> {
        let s = self.0.lock().unwrap();
        Ok(Response::new(PublicKeyReply {
            hex: s.public_key.clone().unwrap_or_default(),
        }))
    }
}

// ---------------------------------------------------------------------------
// FriendService impl
// ---------------------------------------------------------------------------

struct TestFriendService(SharedState);

#[tonic::async_trait]
impl FriendService for TestFriendService {
    async fn get_contacts(&self, _: Request<Empty>) -> Result<Response<ContactList>, Status> {
        let s = self.0.lock().unwrap();
        Ok(Response::new(ContactList { contacts: s.contacts.clone() }))
    }

    async fn add_contact(
        &self, req: Request<AddContactRequest>,
    ) -> Result<Response<ContactReply>, Status> {
        let r = req.into_inner();
        if r.public_key.len() != 64 {
            return Err(Status::invalid_argument("public key must be 64 hex chars"));
        }
        let contact = ContactReply {
            id: r.public_key.clone(),
            name: r.name,
            last_seen_ts: 0,
            online: false,
            blocked: false,
            typing: false,
        };
        self.0.lock().unwrap().contacts.push(contact.clone());
        Ok(Response::new(contact))
    }

    async fn rename_contact(
        &self, req: Request<RenameContactRequest>,
    ) -> Result<Response<ContactReply>, Status> {
        let r = req.into_inner();
        let mut s = self.0.lock().unwrap();
        let c = s.contacts.iter_mut().find(|c| c.id == r.contact_id)
            .ok_or_else(|| Status::not_found("contact not found"))?;
        c.name = r.name;
        Ok(Response::new(c.clone()))
    }

    async fn remove_contact(
        &self, req: Request<RemoveContactRequest>,
    ) -> Result<Response<Empty>, Status> {
        let id = req.into_inner().contact_id;
        let mut s = self.0.lock().unwrap();
        s.contacts.retain(|c| c.id != id);
        Ok(Response::new(Empty {}))
    }

    async fn block_contact(
        &self, req: Request<BlockContactRequest>,
    ) -> Result<Response<ContactReply>, Status> {
        self.set_blocked(req.into_inner().contact_id, true)
    }

    async fn unblock_contact(
        &self, req: Request<BlockContactRequest>,
    ) -> Result<Response<ContactReply>, Status> {
        self.set_blocked(req.into_inner().contact_id, false)
    }

    async fn get_safety_number(
        &self, req: Request<SafetyNumberRequest>,
    ) -> Result<Response<SafetyNumberReply>, Status> {
        let _ = req.into_inner();
        Ok(Response::new(SafetyNumberReply {
            safety_number: String::new(),
            verified: false,
        }))
    }
}

impl TestFriendService {
    #[allow(clippy::result_large_err)]
    fn set_blocked(&self, contact_id: String, blocked: bool) -> Result<Response<ContactReply>, Status> {
        let mut s = self.0.lock().unwrap();
        let c = s.contacts.iter_mut().find(|c| c.id == contact_id)
            .ok_or_else(|| Status::not_found("contact not found"))?;
        c.blocked = blocked;
        Ok(Response::new(c.clone()))
    }
}

// ---------------------------------------------------------------------------
// MessageService impl
// ---------------------------------------------------------------------------

struct TestMessageService(SharedState);

#[tonic::async_trait]
impl MessageService for TestMessageService {
    async fn get_messages(
        &self, req: Request<GetMessagesRequest>,
    ) -> Result<Response<MessageList>, Status> {
        let contact_id = req.into_inner().contact_id;
        let s = self.0.lock().unwrap();
        let msgs = s.messages.get(&contact_id).cloned().unwrap_or_default();
        Ok(Response::new(MessageList { messages: msgs }))
    }

    async fn search_messages(
         &self, req: Request<SearchMessagesRequest>,
     ) -> Result<Response<MessageList>, Status> {
         let r = req.into_inner();
         let q = r.query.to_lowercase();
         let s = self.0.lock().unwrap();
         let msgs = s.messages.get(&r.contact_id)
             .map(|v| v.iter()
                 .filter(|m| m.text.to_lowercase().contains(&q) || m.content_type.to_lowercase().contains(&q))
                 .cloned()
                 .collect())
             .unwrap_or_default();
         Ok(Response::new(MessageList { messages: msgs }))
     }

    async fn send_text(
        &self, req: Request<SendTextRequest>,
    ) -> Result<Response<MessageReply>, Status> {
        let r = req.into_inner();
        let mut s = self.0.lock().unwrap();
        let id = s.next_id();
        let msg = MessageReply {
            id,
            contact_id: r.contact_id.clone(),
            outbound: true,
            content_type: "text".into(),
            text: r.text,
            timestamp_ts: now_ts(),
            status: "sent".into(),
            ..Default::default()
        };
        s.messages.entry(r.contact_id).or_default().push(msg.clone());
        Ok(Response::new(msg))
    }

    async fn send_typing(
        &self, _req: Request<SendTypingRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn toggle_reaction(
        &self, _req: Request<ReactionRequest>,
    ) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }
}

// ---------------------------------------------------------------------------
// TransferService impl
// ---------------------------------------------------------------------------

struct TestTransferService;

#[tonic::async_trait]
impl TransferService for TestTransferService {
    async fn get_transfers(&self, _: Request<Empty>) -> Result<Response<TransferList>, Status> {
        Ok(Response::new(TransferList {
            transfers: vec![TransferReply {
                id: "t1".into(),
                contact_name: "Bob".into(),
                file_name: "data.bin".into(),
                size_bytes: 1_000_000,
                transferred_bytes: 250_000,
                outbound: true,
                lanes_active: 2,
                bps: 50_000,
            }],
        }))
    }

    async fn send_file(&self, _: Request<SendFileRequest>) -> Result<Response<MessageReply>, Status> {
        Err(Status::unimplemented("send_file not implemented in test stub"))
    }

    async fn cancel_transfer(&self, _: Request<transferd_api::CancelTransferRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn pause_transfer(&self, _: Request<transferd_api::CancelTransferRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    async fn resume_transfer(&self, _: Request<transferd_api::CancelTransferRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }
}

// ---------------------------------------------------------------------------
// SettingsService impl
// ---------------------------------------------------------------------------

struct TestSettingsService(SharedState);

#[tonic::async_trait]
impl SettingsService for TestSettingsService {
    async fn get_setting(
        &self, req: Request<GetSettingRequest>,
    ) -> Result<Response<SettingReply>, Status> {
        let key = req.into_inner().key;
        let s = self.0.lock().unwrap();
        match s.settings.get(&key) {
            Some(v) => Ok(Response::new(SettingReply { value: v.clone(), found: true })),
            None    => Ok(Response::new(SettingReply { value: String::new(), found: false })),
        }
    }

    async fn set_setting(
        &self, req: Request<SetSettingRequest>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();
        self.0.lock().unwrap().settings.insert(r.key, r.value);
        Ok(Response::new(Empty {}))
    }
}

// ---------------------------------------------------------------------------
// Test server launcher
// ---------------------------------------------------------------------------

async fn start_test_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state: SharedState = Arc::new(Mutex::new(ServerState::default()));

    tokio::spawn(async move {
        Server::builder()
            .add_service(AccountServiceServer::new(TestAccountService(state.clone())))
            .add_service(FriendServiceServer::new(TestFriendService(state.clone())))
            .add_service(MessageServiceServer::new(TestMessageService(state.clone())))
            .add_service(TransferServiceServer::new(TestTransferService))
            .add_service(SettingsServiceServer::new(TestSettingsService(state.clone())))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    // Give the server a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_account_create_and_get_identity() {
    let addr = start_test_server().await;
    let url = format!("http://{addr}");

    let mut ac = transferd_api::AccountServiceClient::connect(url.clone()).await.unwrap();

    // No identity yet.
    let r = ac.get_identity(Empty {}).await.unwrap().into_inner();
    assert!(!r.has_identity);

    // Create identity.
    let r = ac.create_identity(CreateIdentityRequest {
        display_name: "TestUser".into(),
    }).await.unwrap().into_inner();
    assert!(r.phrase.split_whitespace().count() >= 12);

    // Now identity exists.
    let r = ac.get_identity(Empty {}).await.unwrap().into_inner();
    assert!(r.has_identity);
    assert_eq!(r.display_name, "TestUser");
}

#[tokio::test]
async fn test_restore_identity_bad_phrase_rejected() {
    let addr = start_test_server().await;
    let url = format!("http://{addr}");

    let mut ac = transferd_api::AccountServiceClient::connect(url).await.unwrap();
    let err = ac.restore_identity(RestoreIdentityRequest {
        phrase: "only three words".into(),
    }).await;
    assert!(err.is_err());
    let status = err.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_friend_add_and_list() {
    let addr = start_test_server().await;
    let url = format!("http://{addr}");

    let mut fc = transferd_api::FriendServiceClient::connect(url).await.unwrap();

    // Initially empty.
    let list = fc.get_contacts(Empty {}).await.unwrap().into_inner();
    assert!(list.contacts.is_empty());

    // Add valid contact.
    let key = "a".repeat(64);
    let contact = fc.add_contact(AddContactRequest {
        public_key: key.clone(),
        name: "Eve".into(),
    }).await.unwrap().into_inner();
    assert_eq!(contact.name, "Eve");
    assert_eq!(contact.id, key);

    // List now has one.
    let list = fc.get_contacts(Empty {}).await.unwrap().into_inner();
    assert_eq!(list.contacts.len(), 1);
}

#[tokio::test]
async fn test_message_send_and_receive() {
    let addr = start_test_server().await;
    let url = format!("http://{addr}");

    let mut mc = transferd_api::MessageServiceClient::connect(url).await.unwrap();

    let contact_id = "contact_xyz";

    // No messages initially.
    let list = mc.get_messages(GetMessagesRequest {
        contact_id: contact_id.into(),
    }).await.unwrap().into_inner();
    assert!(list.messages.is_empty());

    // Send a message.
    let sent = mc.send_text(SendTextRequest {
        contact_id: contact_id.into(),
        text: "Hello from test".into(),
        reply_to: String::new(),
    }).await.unwrap().into_inner();
    assert!(sent.outbound);
    assert_eq!(sent.status, "sent");
    assert_eq!(sent.content_type, "text");
    assert_eq!(sent.text, "Hello from test");

    // Now one message in history.
    let list = mc.get_messages(GetMessagesRequest {
        contact_id: contact_id.into(),
    }).await.unwrap().into_inner();
    assert_eq!(list.messages.len(), 1);
}

#[tokio::test]
async fn test_transfer_list() {
    let addr = start_test_server().await;
    let url = format!("http://{addr}");

    let mut tc = transferd_api::TransferServiceClient::connect(url).await.unwrap();
    let list = tc.get_transfers(Empty {}).await.unwrap().into_inner();
    assert_eq!(list.transfers.len(), 1);
    let t = &list.transfers[0];
    assert_eq!(t.file_name, "data.bin");
    assert_eq!(t.lanes_active, 2);
    assert!(t.transferred_bytes < t.size_bytes);
}

#[tokio::test]
async fn test_settings_roundtrip() {
    let addr = start_test_server().await;
    let url = format!("http://{addr}");

    let mut sc = transferd_api::SettingsServiceClient::connect(url).await.unwrap();

    // Not found initially.
    let r = sc.get_setting(GetSettingRequest { key: "theme".into() }).await.unwrap().into_inner();
    assert!(!r.found);

    // Set it.
    sc.set_setting(SetSettingRequest {
        key: "theme".into(),
        value: "dark".into(),
    }).await.unwrap();

    // Now found.
    let r = sc.get_setting(GetSettingRequest { key: "theme".into() }).await.unwrap().into_inner();
    assert!(r.found);
    assert_eq!(r.value, "dark");
}

#[tokio::test]
async fn test_add_contact_bad_key_rejected() {
    let addr = start_test_server().await;
    let url = format!("http://{addr}");

    let mut fc = transferd_api::FriendServiceClient::connect(url).await.unwrap();
    let err = fc.add_contact(AddContactRequest {
        public_key: "tooshort".into(),
        name: "Hacker".into(),
    }).await;
    assert!(err.is_err());
    assert_eq!(err.unwrap_err().code(), tonic::Code::InvalidArgument);
}