//! Integration tests for the live TransferDaemon gRPC server.
//!
//! Each test starts the real `add_all_services` stack on a random port, connects
//! one or more clients, and drives the full RPC round-trip.

use std::net::SocketAddr;
use tokio::net::TcpListener;
use tonic::transport::Server;
use transferd_api::{
    AccountServiceClient, FriendServiceClient, MessageServiceClient,
    TransferServiceClient, SettingsServiceClient, CallServiceClient, GroupServiceClient,
    ConnectionServiceClient,
    CreateIdentityRequest, RestoreIdentityRequest, AddContactRequest,
    RenameContactRequest, RemoveContactRequest, BlockContactRequest,
    GetMessagesRequest, SendTextRequest, Empty,
    GetSettingRequest, SetSettingRequest,
    CallStartRequest, CallAcceptRequest, CallRejectRequest, CallEndRequest,
    IceCandidateMsg,
    CreateGroupRequest, GetGroupRequest, RenameGroupRequest,
    GroupMembersRequest, SetMemberRoleRequest, SendGroupTextRequest,
    SetConnectionPolicyRequest,
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
    // Create a fresh identity first to get a valid BIP-39 phrase.
    let created = ac.create_identity(CreateIdentityRequest { display_name: "Test".into() })
        .await.unwrap().into_inner();
    assert_eq!(created.phrase.split_whitespace().count(), 12);

    // Restore from the phrase — must reproduce the same public key.
    let original_pk = ac.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;

    let r = ac.restore_identity(RestoreIdentityRequest { phrase: created.phrase.clone() })
        .await.unwrap().into_inner();
    assert!(r.has_identity);
    assert_eq!(r.public_key.len(), 64, "restored public key must be 64 hex chars");
    assert_eq!(r.public_key, original_pk, "restored key must match the original");
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

#[tokio::test]
async fn daemon_rename_contact() {
    let addr = start_daemon().await;
    let mut fc = client!(FriendServiceClient<_>, addr);
    let key = "c".repeat(64);
    fc.add_contact(AddContactRequest { public_key: key.clone(), name: "Carol".into() }).await.unwrap();

    let r = fc.rename_contact(RenameContactRequest { contact_id: key.clone(), name: "Carolyn".into() })
        .await.unwrap().into_inner();
    assert_eq!(r.name, "Carolyn");

    let contacts = fc.get_contacts(Empty {}).await.unwrap().into_inner();
    assert_eq!(contacts.contacts[0].name, "Carolyn");

    // Missing name rejected.
    let err = fc.rename_contact(RenameContactRequest { contact_id: key, name: "  ".into() }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn daemon_remove_contact_clears_history() {
    let addr = start_daemon().await;
    let mut fc = client!(FriendServiceClient<_>, addr);
    let mut mc = client!(MessageServiceClient<_>, addr);
    let key = "d".repeat(64);
    fc.add_contact(AddContactRequest { public_key: key.clone(), name: "Dana".into() }).await.unwrap();
    mc.send_text(SendTextRequest { contact_id: key.clone(), text: "hi".into(), reply_to: String::new() }).await.unwrap();

    fc.remove_contact(RemoveContactRequest { contact_id: key.clone() }).await.unwrap();

    let contacts = fc.get_contacts(Empty {}).await.unwrap().into_inner();
    assert!(contacts.contacts.is_empty(), "contact must be removed");
    let msgs = mc.get_messages(GetMessagesRequest { contact_id: key.clone() }).await.unwrap().into_inner();
    assert!(msgs.messages.is_empty(), "message history must be cleared");

    // Removing a nonexistent contact fails.
    let err = fc.remove_contact(RemoveContactRequest { contact_id: key }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn daemon_block_contact() {
    let addr = start_daemon().await;
    let mut fc = client!(FriendServiceClient<_>, addr);
    let key = "e".repeat(64);
    fc.add_contact(AddContactRequest { public_key: key.clone(), name: "Eve".into() }).await.unwrap();

    let r = fc.block_contact(BlockContactRequest { contact_id: key.clone() }).await.unwrap().into_inner();
    assert!(r.blocked, "contact must be marked blocked");

    let contacts = fc.get_contacts(Empty {}).await.unwrap().into_inner();
    assert!(contacts.contacts[0].blocked);

    // Unblock clears the flag.
    let r = fc.unblock_contact(BlockContactRequest { contact_id: key.clone() }).await.unwrap().into_inner();
    assert!(!r.blocked, "unblock must clear the flag");
    let contacts = fc.get_contacts(Empty {}).await.unwrap().into_inner();
    assert!(!contacts.contacts[0].blocked);
}

#[tokio::test]
async fn daemon_connections_list_and_policy() {
    let addr = start_daemon().await;
    let mut cc = client!(ConnectionServiceClient<_>, addr);

    let list = cc.list_connections(Empty {}).await.unwrap().into_inner();
    // Always includes the virtual "direct" transport; interfaces vary per machine.
    assert!(list.connections.iter().any(|c| c.kind == "direct"), "direct transport must be listed");

    // Set a policy and verify it sticks.
    cc.set_connection_policy(SetConnectionPolicyRequest {
        connection_id: "direct".into(),
        policy: "stripe".into(),
    }).await.unwrap();

    let list2 = cc.list_connections(Empty {}).await.unwrap().into_inner();
    let direct = list2.connections.iter().find(|c| c.kind == "direct").unwrap();
    assert_eq!(direct.enabled, true);

    // Invalid policy rejected.
    let err = cc.set_connection_policy(SetConnectionPolicyRequest {
        connection_id: "direct".into(),
        policy: "banana".into(),
    }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::InvalidArgument);

    // The policy is persisted into settings.
    let mut sc = client!(SettingsServiceClient<_>, addr);
    let setting = sc.get_setting(GetSettingRequest { key: "conn.policy".into() }).await.unwrap().into_inner();
    assert!(setting.found);
    assert_eq!(setting.value, "stripe");
}

#[tokio::test]
async fn daemon_group_full_lifecycle() {
    let addr = start_daemon().await;
    let mut acct = client!(AccountServiceClient<_>, addr);
    acct.create_identity(CreateIdentityRequest { display_name: "Owner".into() }).await.unwrap();
    let my_pk = acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;

    let mut gc = client!(GroupServiceClient<_>, addr);
    let member = "ab".repeat(32); // 64 hex

    // Create.
    let g = gc.create_group(CreateGroupRequest {
        name: "Dev Team".into(),
        member_ids: vec![member.clone()],
    }).await.unwrap().into_inner();
    assert_eq!(g.name, "Dev Team");
    assert_eq!(g.owner, my_pk);
    assert_eq!(g.members.len(), 2);
    assert!(!g.group_id.is_empty());
    let gid = g.group_id.clone();

    // Rename.
    let renamed = gc.rename_group(RenameGroupRequest { group_id: gid.clone(), name: "R&D".into() })
        .await.unwrap().into_inner();
    assert_eq!(renamed.name, "R&D");

    // Add/remove members.
    let extra = "cd".repeat(32);
    gc.add_members(GroupMembersRequest { group_id: gid.clone(), member_ids: vec![extra.clone()] })
        .await.unwrap();
    gc.remove_members(GroupMembersRequest { group_id: gid.clone(), member_ids: vec![member.clone()] })
        .await.unwrap();
    let g = gc.get_group(GetGroupRequest { group_id: gid.clone() }).await.unwrap().into_inner();
    assert_eq!(g.members.len(), 2); // owner + extra

    // Set role.
    gc.set_member_role(SetMemberRoleRequest {
        group_id: gid.clone(),
        member_id: extra.clone(),
        role: transferd_api::GroupRole::Admin as i32,
    }).await.unwrap();

    // Send + retrieve group text.
    let sent = gc.send_group_text(SendGroupTextRequest { group_id: gid.clone(), text: "hello team".into() })
        .await.unwrap().into_inner();
    assert_eq!(sent.text, "hello team");
    assert_eq!(sent.group_id, gid);
    let msgs = gc.get_group_messages(GetGroupRequest { group_id: gid.clone() }).await.unwrap().into_inner();
    assert_eq!(msgs.messages.len(), 1);
    assert_eq!(msgs.messages[0].text, "hello team");

    // Leave then delete.
    gc.leave_group(GetGroupRequest { group_id: gid.clone() }).await.unwrap();
    // Owner re-joins by checking the group is gone after delete.
    gc.delete_group(GetGroupRequest { group_id: gid.clone() }).await.unwrap();
    let err = gc.get_group(GetGroupRequest { group_id: gid.clone() }).await;
    assert_eq!(err.unwrap_err().code(), tonic::Code::NotFound);
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
            reply_to: String::new(),
        }).await.unwrap().into_inner();
    // Outbound messages start queued ("pending"); they transition to "sent"
    // when the background transport tick dispatches them over a lane, and
    // "delivered" once the peer acknowledges.
    assert_eq!(sent.status, "pending");
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
    let err = mc.send_text(SendTextRequest { contact_id: "cid".into(), text: "  ".into(), reply_to: String::new() }).await;
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
    mc.send_text(SendTextRequest { contact_id: "c".repeat(64), text: "Hi".into(), reply_to: String::new() }).await.unwrap();

    let contacts = fc.get_contacts(Empty {}).await.unwrap().into_inner();
    let msgs = mc.get_messages(GetMessagesRequest { contact_id: "c".repeat(64) }).await.unwrap().into_inner();
    assert_eq!(contacts.contacts.len(), 1);
    assert_eq!(msgs.messages.len(), 1);
}
