//! Integration tests for the live TransferDaemon gRPC server.
//!
//! Each test starts the real `add_all_services` stack on a random port, connects
//! one or more clients, and drives the full RPC round-trip.

use std::net::SocketAddr;
use std::sync::Arc;
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tonic::transport::Server;
use transferd_api::{
    AccountServiceClient, FriendServiceClient, MessageServiceClient,
    TransferServiceClient, SettingsServiceClient, CallServiceClient,
    CreateIdentityRequest, RestoreIdentityRequest, AddContactRequest,
    GetMessagesRequest, SendTextRequest, Empty,
    GetSettingRequest, SetSettingRequest,
    CallStartRequest, CallAcceptRequest, CallRejectRequest, CallEndRequest,
    IceCandidateMsg,
};
use transferd_lib::{grpc::add_all_services, new_state};

// ---------------------------------------------------------------------------
// Test harness
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
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

macro_rules! client {
    ($T:ty, $addr:expr) => {{
        let url = format!("http://{}", $addr);
        <$T>::connect(url).await.unwrap()
    }};
}

// ---------------------------------------------------------------------------
// Account tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn daemon_create_identity_and_get() {
    let addr = start_daemon().await;
    let mut ac = client!(AccountServiceClient<_>, addr);

    // No identity yet.
    let r = ac.get_identity(Empty {}).await.unwrap().into_inner();
    assert!(!r.has_identity);

    // Create one.
    let phrase = ac.create_identity(CreateIdentityRequest {
        display_name: "TestUser".into(),
    }).await.unwrap().into_inner().phrase;
    assert!(phrase.split_whitespace().count() >= 12);

    // Now present.
    let r = ac.get_identity(Empty {}).await.unwrap().into_inner();
    assert!(r.has_identity);
    assert_eq!(r.display_name, "TestUser");
}

#[tokio::test]
async fn daemon_create_identity_empty_name_rejected() {
    let addr = start_daemon().await;
    let mut ac = client!(AccountServiceClient<_>, addr);
    let err = ac.create_identity(CreateIdentityRequest { display_name: "".into() }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn daemon_restore_identity_bad_phrase_rejected() {
    let addr = start_daemon().await;
    let mut ac = client!(AccountServiceClient<_>, addr);
    let err = ac.restore_identity(RestoreIdentityRequest { phrase: "too short".into() }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn daemon_restore_identity_twelve_words() {
    let addr = start_daemon().await;
    let mut ac = client!(AccountServiceClient<_>, addr);
    let r = ac.restore_identity(RestoreIdentityRequest {
        phrase: "abandon ability able about above absent absorb abstract absurd abuse access accident".into(),
    }).await.unwrap().into_inner();
    assert!(r.has_identity);
    assert!(!r.public_key.is_empty());
}

#[tokio::test]
async fn daemon_public_key_hex_empty_before_identity() {
    let addr = start_daemon().await;
    let mut ac = client!(AccountServiceClient<_>, addr);
    let r = ac.get_public_key_hex(Empty {}).await.unwrap().into_inner();
    assert!(r.hex.is_empty());
}

// ---------------------------------------------------------------------------
// Friend / contact tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn daemon_add_and_list_contacts() {
    let addr = start_daemon().await;
    let mut fc = client!(FriendServiceClient<_>, addr);

    let r = fc.get_contacts(Empty {}).await.unwrap().into_inner();
    assert!(r.contacts.is_empty());

    let key = "a".repeat(64);
    let contact = fc.add_contact(AddContactRequest {
        public_key: key.clone(), name: "Alice".into(),
    }).await.unwrap().into_inner();
    assert_eq!(contact.name, "Alice");
    assert_eq!(contact.id, key);

    let r = fc.get_contacts(Empty {}).await.unwrap().into_inner();
    assert_eq!(r.contacts.len(), 1);
}

#[tokio::test]
async fn daemon_add_contact_bad_key_rejected() {
    let addr = start_daemon().await;
    let mut fc = client!(FriendServiceClient<_>, addr);
    let err = fc.add_contact(AddContactRequest {
        public_key: "short".into(), name: "Eve".into(),
    }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn daemon_add_duplicate_contact_rejected() {
    let addr = start_daemon().await;
    let mut fc = client!(FriendServiceClient<_>, addr);
    let key = "b".repeat(64);
    fc.add_contact(AddContactRequest { public_key: key.clone(), name: "Bob".into() }).await.unwrap();
    let err = fc.add_contact(AddContactRequest { public_key: key, name: "Bob2".into() }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::AlreadyExists);
}

// ---------------------------------------------------------------------------
// Message tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn daemon_send_and_retrieve_messages() {
    let addr = start_daemon().await;
    let mut mc = client!(MessageServiceClient<_>, addr);

    let cid = "contact-abc";
    let r = mc.get_messages(GetMessagesRequest { contact_id: cid.into() }).await.unwrap().into_inner();
    assert!(r.messages.is_empty());

    let sent = mc.send_text(SendTextRequest {
        contact_id: cid.into(), text: "Hello daemon".into(),
    }).await.unwrap().into_inner();
    assert_eq!(sent.status, "sent");
    assert_eq!(sent.content_type, "text");
    assert_eq!(sent.text, "Hello daemon");
    assert!(sent.outbound);

    let r = mc.get_messages(GetMessagesRequest { contact_id: cid.into() }).await.unwrap().into_inner();
    assert_eq!(r.messages.len(), 1);
}

#[tokio::test]
async fn daemon_send_empty_message_rejected() {
    let addr = start_daemon().await;
    let mut mc = client!(MessageServiceClient<_>, addr);
    let err = mc.send_text(SendTextRequest { contact_id: "cid".into(), text: "  ".into() }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::InvalidArgument);
}

// ---------------------------------------------------------------------------
// Transfer tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn daemon_transfer_list_empty_by_default() {
    let addr = start_daemon().await;
    let mut tc = client!(TransferServiceClient<_>, addr);
    let r = tc.get_transfers(Empty {}).await.unwrap().into_inner();
    assert!(r.transfers.is_empty());
}

// ---------------------------------------------------------------------------
// Settings tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn daemon_settings_roundtrip() {
    let addr = start_daemon().await;
    let mut sc = client!(SettingsServiceClient<_>, addr);

    let r = sc.get_setting(GetSettingRequest { key: "lang".into() }).await.unwrap().into_inner();
    assert!(!r.found);

    sc.set_setting(SetSettingRequest { key: "lang".into(), value: "en-GB".into() }).await.unwrap();

    let r = sc.get_setting(GetSettingRequest { key: "lang".into() }).await.unwrap().into_inner();
    assert!(r.found);
    assert_eq!(r.value, "en-GB");
}

// ---------------------------------------------------------------------------
// Call tests (integrated with real CallServiceImpl)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn daemon_call_full_flow() {
    let addr = start_daemon().await;
    let mut cc = client!(CallServiceClient<_>, addr);

    // Start.
    let r = cc.start_call(CallStartRequest {
        conv_id: "conv-1".into(), video: false, local_sdp: "v=0\r\ns=offer\r\n".into(),
    }).await.unwrap().into_inner();
    assert!(!r.call_id.is_empty());
    let call_id = r.call_id;

    // Accept.
    let r = cc.accept_call(CallAcceptRequest {
        call_id: call_id.clone(), answer_sdp: "v=0\r\ns=answer\r\n".into(),
    }).await.unwrap().into_inner();
    assert!(r.accepted);
    assert!(r.remote_sdp.contains("offer"));

    // End.
    cc.end_call(CallEndRequest { call_id: call_id.clone() }).await.unwrap();

    // Double-end: call state is already "ended", accepting should fail.
    let err = cc.accept_call(CallAcceptRequest {
        call_id, answer_sdp: "v=0\r\n".into(),
    }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn daemon_call_reject_then_accept_fails() {
    let addr = start_daemon().await;
    let mut cc = client!(CallServiceClient<_>, addr);

    let call_id = cc.start_call(CallStartRequest {
        conv_id: "conv-2".into(), video: true, local_sdp: "v=0\r\n".into(),
    }).await.unwrap().into_inner().call_id;

    cc.reject_call(CallRejectRequest { call_id: call_id.clone() }).await.unwrap();

    let err = cc.accept_call(CallAcceptRequest { call_id, answer_sdp: "v=0\r\n".into() }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn daemon_ice_candidate_on_unknown_call_rejected() {
    let addr = start_daemon().await;
    let mut cc = client!(CallServiceClient<_>, addr);
    let err = cc.send_ice_candidate(IceCandidateMsg {
        call_id: "ghost".into(), candidate_json: "{}".into(),
    }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn daemon_multiple_services_share_state() {
    // Identity created through AccountService is visible in get_public_key_hex.
    let addr = start_daemon().await;
    let mut ac = client!(AccountServiceClient<_>, addr);

    ac.create_identity(CreateIdentityRequest { display_name: "SharedState".into() }).await.unwrap();
    let key = ac.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;
    assert!(!key.is_empty(), "public key must propagate from create_identity to get_public_key_hex");

    // Contact + message are independent namespaces on same server.
    let mut fc = client!(FriendServiceClient<_>, addr);
    fc.add_contact(AddContactRequest { public_key: "c".repeat(64), name: "Carol".into() }).await.unwrap();

    let mut mc = client!(MessageServiceClient<_>, addr);
    mc.send_text(SendTextRequest { contact_id: "c".repeat(64), text: "Hi".into() }).await.unwrap();

    let contacts = fc.get_contacts(Empty {}).await.unwrap().into_inner();
    let msgs = mc.get_messages(GetMessagesRequest { contact_id: "c".repeat(64) }).await.unwrap().into_inner();
    assert_eq!(contacts.contacts.len(), 1);
    assert_eq!(msgs.messages.len(), 1);
}
