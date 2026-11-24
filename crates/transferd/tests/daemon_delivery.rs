//! End-to-end delivery tests: two daemons exchange real traffic over a real
//! TCP connection with a real X25519 handshake and AES-256-GCM encrypted lanes.
//!
//! Topology:
//!   sender daemon (gRPC + transport)  →  receiver daemon (transport listener)
//!
//! The sender's `SendText`/`SendFile` are driven through the real gRPC handler;
//! the transport tick is pumped in-process exactly as the daemon binary does.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use transferd_api::{
    AccountServiceClient, CreateIdentityRequest, MessageServiceClient, SendFileRequest,
    SendTextRequest, TransferServiceClient, Empty, FriendServiceClient, SafetyNumberRequest,
    SendTypingRequest, ReactionRequest, SettingsServiceClient, GetSettingRequest,
};
use transferd_lib::state::{Contact, DaemonState};
use transferd_lib::transport::spawn_inbound_listener;
use transferd_lib::{grpc::add_all_services, new_state};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

async fn start_grpc(state: Arc<Mutex<DaemonState>>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        add_all_services(Server::builder(), state)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Pump the sender's transport tick, applying status/inbound events exactly as
/// the daemon binary's background loop does.
async fn pump_transport(state: &Arc<Mutex<DaemonState>>) {
    let transport = state.lock().transport.clone();
    let events = transport.lock().await.process_all_sessions().await;
    if !events.sent_msg_ids.is_empty() || !events.inbound.is_empty() {
        let mut s = state.lock();
        for id in events.sent_msg_ids {
            s.mark_status(&id, "sent");
        }
        for (_, msg) in events.inbound {
            let _ = s.apply_inbound(&msg);
        }
        s.try_save();
    }
}

/// Run `pump_transport` until `cond` holds (with a deadline).
async fn pump_until<F>(state: &Arc<Mutex<DaemonState>>, mut cond: F)
where
    F: FnMut() -> bool,
{
    for _ in 0..500 {
        pump_transport(state).await;
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ---------------------------------------------------------------------------
// Text delivery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn text_message_delivers_end_to_end() {
    // Receiver: state + inbound transport listener on an ephemeral port.
    let recv_state = new_state();
    recv_state.lock().install_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "Bob",
    );
    let recv_addr = spawn_inbound_listener(
        recv_state.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();

// Sender: state whose contact points at the receiver's transport address.
    let send_state = new_state();
    let peer_pk = recv_state.lock().identity.as_ref().unwrap().public_key.clone();
    {
        let mut s = send_state.lock();
        s.contacts.push(Contact {
            id: peer_pk.clone(),
            name: "Bob".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: Some(recv_addr.to_string()),
            hybrid_public_key: None,
            limits: None,
        });
    }
    let sender_addr = start_grpc(send_state.clone()).await;

    let url = format!("http://{sender_addr}");
    let mut acct = AccountServiceClient::connect(url.clone()).await.unwrap();
    acct.create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();

    let mut msg = MessageServiceClient::connect(url.clone()).await.unwrap();
    let reply = msg
        .send_text(SendTextRequest {
            contact_id: peer_pk.clone(),
            text: "hello over the wire".into(),
            reply_to: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.status, "pending", "outbound starts queued");
    let msg_id = reply.id;

    // Pump until the receiver has the message and the sender has the ack.
    pump_until(&send_state, || {
        let s = recv_state.lock();
        s.messages.values().flatten().any(|m| m.text == "hello over the wire")
    })
    .await;
    pump_until(&send_state, || {
        let s = send_state.lock();
        s.messages
            .values()
            .flatten()
            .find(|m| m.id == msg_id)
            .map(|m| m.status == "delivered")
            .unwrap_or(false)
    })
    .await;

    // Receiver stored the inbound message under the sender's identity.
    {
        let s = recv_state.lock();
        let got = s
            .messages
            .values()
            .flatten()
            .find(|m| m.text == "hello over the wire")
            .expect("receiver must have the message");
        assert!(!got.outbound);
        assert_eq!(got.status, "delivered");
    }

    // Sender observed delivery.
    {
        let s = send_state.lock();
        let sent = s
            .messages
            .values()
            .flatten()
            .find(|m| m.id == msg_id)
            .expect("sender keeps its outbound message");
        assert_eq!(sent.status, "delivered", "ack must flip outbound status to delivered");
    }
}

// ---------------------------------------------------------------------------
// File delivery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn file_delivers_end_to_end() {
    let downloads = tempfile::tempdir().unwrap();
    std::env::set_var("TRANSFERD_DOWNLOADS_DIR", downloads.path());

    let file_path = downloads.path().join("payload.bin");
    let payload: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&file_path, &payload).unwrap();

    // Receiver: state + inbound transport listener.
    let recv_state = new_state();
    recv_state.lock().install_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "Bob",
    );
    let recv_addr = spawn_inbound_listener(
        recv_state.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();

// Sender: state whose contact points at the receiver.
    let send_state = new_state();
    let peer_pk = recv_state.lock().identity.as_ref().unwrap().public_key.clone();
    {
        let mut s = send_state.lock();
        s.contacts.push(Contact {
            id: peer_pk.clone(),
            name: "Bob".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: Some(recv_addr.to_string()),
            hybrid_public_key: None,
            limits: None,
        });
    }
    let sender_addr = start_grpc(send_state.clone()).await;

    let url = format!("http://{sender_addr}");
    let mut acct = AccountServiceClient::connect(url.clone()).await.unwrap();
    acct.create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();

    let mut tr = TransferServiceClient::connect(url.clone()).await.unwrap();
    tr.send_file(SendFileRequest {
        contact_id: peer_pk.clone(),
        file_path: file_path.to_string_lossy().to_string(),
        file_name: "payload.bin".into(),
        file_size: payload.len() as u64,
        mime_type: "application/octet-stream".into(),
    })
    .await
    .unwrap();

    // Pump until the receiver has the file message and the written file exists.
    pump_until(&send_state, || {
        let s = recv_state.lock();
        s.messages
            .values()
            .flatten()
            .any(|m| m.content_type == "file" && m.file_name == "payload.bin")
    })
    .await;

    let written = downloads.path().join("payload.bin");
    for _ in 0..100 {
        if written.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Receiver stored the file message.
    {
        let s = recv_state.lock();
        let got = s
            .messages
            .values()
            .flatten()
            .find(|m| m.content_type == "file" && m.file_name == "payload.bin")
            .expect("receiver must have the file message");
        assert_eq!(got.file_size, payload.len() as u64);
    }

    // The reassembled bytes match the source exactly.
    let on_disk = std::fs::read(&written).expect("reassembled file must exist");
    assert_eq!(on_disk, payload, "reassembled bytes must match the source");
}

// ---------------------------------------------------------------------------
// Blocked-contact enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn blocked_contact_messages_are_dropped() {
    let recv_state = new_state();
    recv_state.lock().install_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "Bob",
    );
    let recv_addr = spawn_inbound_listener(
        recv_state.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();

    let send_state = new_state();
    let peer_pk = recv_state.lock().identity.as_ref().unwrap().public_key.clone();
    {
        let mut s = send_state.lock();
        s.contacts.push(Contact {
            id: peer_pk.clone(),
            name: "Bob".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: Some(recv_addr.to_string()),
            hybrid_public_key: None,
            limits: None,
        });
    }
    let sender_addr = start_grpc(send_state.clone()).await;

    let url = format!("http://{sender_addr}");
    let mut acct = AccountServiceClient::connect(url.clone()).await.unwrap();
    acct.create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();
    let sender_pk = acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;
    assert_eq!(sender_pk.len(), 64);

    // Receiver blocks the sender.
    {
        let mut s = recv_state.lock();
        s.contacts.push(Contact {
            id: sender_pk.clone(),
            name: "Alice".into(),
            last_seen_ts: 0,
            online: false,
            blocked: true,
            address: None,
			 hybrid_public_key: None,
            limits: None,
        });
    }

    let mut msg = MessageServiceClient::connect(url.clone()).await.unwrap();
    msg.send_text(SendTextRequest {
        contact_id: peer_pk.clone(),
        text: "should be dropped".into(),
            reply_to: String::new(),
        })
    .await
    .unwrap();

    // Pump long enough for the message to traverse the lane.
    for _ in 0..200 {
        pump_transport(&send_state).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // The receiver must NOT have stored the blocked sender's message.
    let s = recv_state.lock();
    let dropped = s
        .messages
        .values()
        .flatten()
        .any(|m| m.text == "should be dropped");
    assert!(!dropped, "messages from a blocked contact must be dropped");
}
// ---------------------------------------------------------------------------
// Safety numbers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn safety_numbers_match_on_both_sides() {
    // Receiver daemon with identity + transport + gRPC.
    let recv_state = new_state();
    recv_state.lock().install_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "Bob",
    );
    let recv_addr = spawn_inbound_listener(
        recv_state.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    let recv_grpc = start_grpc(recv_state.clone()).await;
    let recv_url = format!("http://{recv_grpc}");

    // Sender daemon.
    let send_state = new_state();
    let sender_grpc = start_grpc(send_state.clone()).await;
    let send_url = format!("http://{sender_grpc}");
    let mut send_acct = AccountServiceClient::connect(send_url.clone()).await.unwrap();
    send_acct
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();
    let alice_pk = send_acct
        .get_public_key_hex(Empty {})
        .await
        .unwrap()
        .into_inner()
        .hex;

    // Both sides know each other as contacts (direct TCP).
    let bob_pk = recv_state.lock().identity.as_ref().unwrap().public_key.clone();
    {
        let mut s = send_state.lock();
        s.contacts.push(Contact {
            id: bob_pk.clone(),
            name: "Bob".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: Some(recv_addr.to_string()),
            hybrid_public_key: None,
            limits: None,
        });
    }
    {
        let mut s = recv_state.lock();
        s.contacts.push(Contact {
            id: alice_pk.clone(),
            name: "Alice".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: None,
            hybrid_public_key: None,
            limits: None,
        });
    }

    // Force session establishment + fingerprint recording on BOTH sides.
    let mut msg = MessageServiceClient::connect(send_url.clone()).await.unwrap();
    msg.send_text(SendTextRequest {
        contact_id: bob_pk.clone(),
        text: "hi for safety numbers".into(),
            reply_to: String::new(),
        })
    .await
    .unwrap();
    pump_until(&send_state, || {
        recv_state
            .lock()
            .messages
            .values()
            .flatten()
            .any(|m| m.text == "hi for safety numbers")
    })
    .await;

    // Both sides must now report the SAME verified safety number.
    let mut send_friend = FriendServiceClient::connect(send_url).await.unwrap();
    let send_num = send_friend
        .get_safety_number(SafetyNumberRequest { contact_id: bob_pk })
        .await
        .unwrap()
        .into_inner();
    assert!(send_num.verified, "sender must have recorded the peer fingerprint");
    assert!(!send_num.safety_number.is_empty());
    assert_eq!(send_num.safety_number.split(' ').count(), 12);

    let mut recv_friend = FriendServiceClient::connect(recv_url).await.unwrap();
    let recv_num = recv_friend
        .get_safety_number(SafetyNumberRequest { contact_id: alice_pk })
        .await
        .unwrap()
        .into_inner();
    assert!(recv_num.verified, "receiver must have recorded the initiator fingerprint");
    assert_eq!(
        send_num.safety_number, recv_num.safety_number,
        "both peers must derive the identical safety number"
    );
}

// ---------------------------------------------------------------------------
// Typing indicators + reactions over the wire
// ---------------------------------------------------------------------------

#[tokio::test]
async fn typing_and_reactions_flow_over_the_wire() {
    let recv_state = new_state();
    recv_state.lock().install_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "Bob",
    );
    let recv_addr = spawn_inbound_listener(recv_state.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let send_state = new_state();
    let sender_grpc = start_grpc(send_state.clone()).await;
    let send_url = format!("http://{sender_grpc}");
    let mut send_acct = AccountServiceClient::connect(send_url.clone()).await.unwrap();
    send_acct
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();

    let bob_pk = recv_state.lock().identity.as_ref().unwrap().public_key.clone();
    {
        let mut s = send_state.lock();
        s.contacts.push(Contact {
            id: bob_pk.clone(),
            name: "Bob".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: Some(recv_addr.to_string()),
            hybrid_public_key: None,
            limits: None,
        });
    }

    // Send a text, then a typing indicator, then a reaction to the text.
    let mut mc = MessageServiceClient::connect(send_url).await.unwrap();
    let sent = mc
        .send_text(SendTextRequest { contact_id: bob_pk.clone(), text: "reaction target".into(), reply_to: String::new() })
        .await
        .unwrap()
        .into_inner();
    pump_until(&send_state, || {
        recv_state.lock().messages.values().flatten().any(|m| m.text == "reaction target")
    })
    .await;

    mc.send_typing(SendTypingRequest { contact_id: bob_pk.clone(), is_typing: true })
        .await
        .unwrap();
    pump_until(&send_state, || recv_state.lock().is_typing(&send_acct_pk(&send_state)))
        .await;

    mc.toggle_reaction(ReactionRequest {
        contact_id: bob_pk.clone(),
        target_msg_id: sent.id.clone(),
        emoji: "❤️".into(),
    })
    .await
    .unwrap();
    pump_until(&send_state, || {
        recv_state.lock().messages.values().flatten().any(|m| !m.reactions.is_empty())
    })
    .await;

    let s = recv_state.lock();
    let target = s.messages.values().flatten().find(|m| m.text == "reaction target").unwrap();
    assert!(!target.reactions.is_empty(), "reaction must reach the recipient");
    assert_eq!(target.reactions[0].0, "❤️");
}

fn send_acct_pk(state: &Arc<Mutex<DaemonState>>) -> String {
    state.lock().identity.as_ref().unwrap().public_key.clone()
}

// ---------------------------------------------------------------------------
// Per-message ratchet over the wire
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ratchet_advances_over_the_wire() {
    // Two real daemons; send more messages than RATCHET_INTERVAL so the
    // initiator performs actual DH ratchet steps, and confirm every message
    // survives end-to-end (per-message forward secrecy on the live transport).
    let recv_state = new_state();
    recv_state.lock().install_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "Bob",
    );
    let recv_addr = spawn_inbound_listener(recv_state.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let send_state = new_state();
    let sender_grpc = start_grpc(send_state.clone()).await;
    let send_url = format!("http://{sender_grpc}");
    let mut send_acct = AccountServiceClient::connect(send_url.clone()).await.unwrap();
    send_acct
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();

    let bob_pk = recv_state.lock().identity.as_ref().unwrap().public_key.clone();
    {
        let mut s = send_state.lock();
        s.contacts.push(Contact {
            id: bob_pk.clone(),
            name: "Bob".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: Some(recv_addr.to_string()),
            hybrid_public_key: None,
            limits: None,
        });
    }

    let mut mc = MessageServiceClient::connect(send_url).await.unwrap();
    const N: usize = 25;
    for i in 0..N {
        let text = format!("ratchet-message-{i}");
        mc.send_text(SendTextRequest {
            contact_id: bob_pk.clone(),
            text: text.clone(),
            reply_to: String::new(),
        })
        .await
        .unwrap();
    }

    // All messages must arrive (the ratchet advances > once over 25 sends).
    pump_until(&send_state, || {
        let s = recv_state.lock();
        (0..N).all(|i| s.messages.values().flatten().any(|m| m.text == format!("ratchet-message-{i}")))
    })
    .await;

    let s = recv_state.lock();
    let count = s.messages.values().flatten().filter(|m| m.text.starts_with("ratchet-message-")).count();
    assert_eq!(count, N, "all ratcheted messages must be delivered in order");
}

/// The sender refuses a transfer when the peer's advertised limits are smaller
/// than the payload — both text and files are gated by the recipient's caps.
#[tokio::test]
async fn send_refused_when_peer_advertised_cap_is_smaller() {
    // Receiver.
    let recv_state = new_state();
    recv_state.lock().install_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "Bob",
    );
    let recv_addr = spawn_inbound_listener(recv_state.clone(), "127.0.0.1:0".parse().unwrap()).await.unwrap();

    // Sender with a contact whose advertised limits cap text at 8 bytes and
    // photos at 1 KiB.
    let send_state = new_state();
    let peer_pk = recv_state.lock().identity.as_ref().unwrap().public_key.clone();
    {
        let mut s = send_state.lock();
        s.contacts.push(Contact {
            id: peer_pk.clone(),
            name: "Bob".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: Some(recv_addr.to_string()),
            hybrid_public_key: None,
            limits: Some(relayd::limits::TransferLimits {
                message_bytes: relayd::limits::MaxBytes::custom(8),
                photo_bytes: relayd::limits::MaxBytes::custom(1024),
                ..Default::default()
            }),
        });
    }
    let sender_addr = start_grpc(send_state.clone()).await;
    let url = format!("http://{sender_addr}");
    let mut msg = MessageServiceClient::connect(url).await.unwrap();

    // Over the text cap → refused before anything is queued.
    let long = "x".repeat(64);
    let err = msg
        .send_text(SendTextRequest { contact_id: peer_pk.clone(), text: long, reply_to: String::new() })
        .await
        .unwrap_err();
    assert!(err.message().contains("exceeds"), "expected a cap refusal, got: {err}");

    // Within the text cap → accepted.
    msg.send_text(SendTextRequest { contact_id: peer_pk.clone(), text: "short".into(), reply_to: String::new() })
        .await
        .expect("within-cap text must send");

// Over the photo cap → refused.
    let big = std::env::temp_dir().join("harbor-over-cap.png");
    std::fs::write(&big, vec![0u8; 4096]).unwrap();
    let mut tr = TransferServiceClient::connect(format!("http://{sender_addr}")).await.unwrap();
    let err = tr
        .send_file(SendFileRequest {
            contact_id: peer_pk.clone(),
            file_path: big.to_string_lossy().into_owned(),
            file_name: "pic.png".into(),
            file_size: 4096,
            mime_type: "image/png".into(),
        })
        .await
        .unwrap_err();
    assert!(err.message().contains("exceeds"), "expected a photo cap refusal, got: {err}");
    let _ = std::fs::remove_file(&big);
}

/// Transfer limits are settable via the SettingsService and enforced: a text
/// over the newly-set cap is refused by the sender's own limits.
#[tokio::test]
async fn limits_set_via_settings_are_enforced() {
    let recv_state = new_state();
    recv_state.lock().install_identity(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "Bob",
    );
    let recv_addr = spawn_inbound_listener(recv_state.clone(), "127.0.0.1:0".parse().unwrap()).await.unwrap();

    let send_state = new_state();
    let peer_pk = recv_state.lock().identity.as_ref().unwrap().public_key.clone();
    {
        let mut s = send_state.lock();
        s.contacts.push(Contact {
            id: peer_pk.clone(),
            name: "Bob".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: Some(recv_addr.to_string()),
            hybrid_public_key: None,
            limits: None,
        });
        // User sets a tiny message cap via the settings map.
        s.settings.insert("limits.message_bytes".into(), "8".into());
    }
    let sender_addr = start_grpc(send_state.clone()).await;
    let url = format!("http://{sender_addr}");
    let mut msg = MessageServiceClient::connect(url).await.unwrap();

    // Read the effective limit back (synthesized by the SettingsService).
    let mut settings = SettingsServiceClient::connect(format!("http://{sender_addr}")).await.unwrap();
    let reply = settings.get_setting(GetSettingRequest { key: "limits.message_bytes".into() }).await.unwrap().into_inner();
    assert!(reply.found && reply.value.contains("8"), "effective cap should reflect the setting: {reply:?}");

    let err = msg
        .send_text(SendTextRequest { contact_id: peer_pk.clone(), text: "x".repeat(64), reply_to: String::new() })
        .await
        .unwrap_err();
    assert!(err.message().contains("exceeds"), "expected a cap refusal, got: {err}");
}
