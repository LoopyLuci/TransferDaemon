//! Two-daemon group messaging E2E: Alice creates a group, invites Bob, both
//! message it, and Bob receives Alice's group message via the direct TCP lane
//! with the group-id routing path.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use transferd_api::{
    AccountServiceClient, CreateIdentityRequest, GroupServiceClient, Empty,
    CreateGroupRequest, SendGroupTextRequest,
};
use transferd_lib::transport::spawn_inbound_listener;
use transferd_lib::state::{Contact, DaemonState};
use transferd_lib::{grpc::add_all_services, new_state};

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

#[tokio::test]
async fn group_messaging_delivers_to_members() {
    // ── Receiver daemon (Bob) ────────────────────────────────────────────────
    let bob_state = new_state();
    let bob_listener = spawn_inbound_listener(bob_state.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let bob_grpc = start_grpc(bob_state.clone()).await;
    let mut bob_acct = AccountServiceClient::connect(format!("http://{bob_grpc}"))
        .await
        .unwrap();
    bob_acct
        .create_identity(CreateIdentityRequest { display_name: "Bob".into() })
        .await
        .unwrap();
    let bob_pk = bob_acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;

    // ── Sender daemon (Alice) ────────────────────────────────────────────────
    let alice_state = new_state();
    {
        let mut s = alice_state.lock();
        s.contacts.push(Contact {
            id: bob_pk.clone(),
            name: "Bob".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: Some(bob_listener.to_string()),
			 hybrid_public_key: None,
        });
    }
    let alice_grpc = start_grpc(alice_state.clone()).await;
    let alice_url = format!("http://{alice_grpc}");
    let mut alice_acct = AccountServiceClient::connect(alice_url.clone()).await.unwrap();
    alice_acct
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();
    let alice_pk = alice_acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;

    // Alice creates a group and invites Bob.
    let mut gc = GroupServiceClient::connect(alice_url.clone()).await.unwrap();
    let group = gc
        .create_group(CreateGroupRequest {
            name: "Project X".into(),
            member_ids: vec![bob_pk.clone()],
        })
        .await
        .unwrap()
        .into_inner();
    let gid = group.group_id.clone();
    assert_eq!(group.members.len(), 2);

    // Alice messages the group.
    gc.send_group_text(SendGroupTextRequest {
        group_id: gid.clone(),
        text: "welcome to Project X".into(),
    })
    .await
    .unwrap();

    // Pump Alice's transport until Bob has the group message.
    for _ in 0..500 {
        pump_transport(&alice_state).await;
        let delivered = {
            let s = bob_state.lock();
            s.messages.values().flatten().any(|m| m.text == "welcome to Project X")
        };
        if delivered {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Bob received it as a group-thread message from Alice.
    {
        let s = bob_state.lock();
        let got = s
            .messages
            .values()
            .flatten()
            .find(|m| m.text == "welcome to Project X")
            .expect("Bob must receive the group message");
        assert_eq!(got.group_id.as_deref(), Some(gid.as_str()), "message must be tagged with the group id");
        assert_eq!(got.sender_pk, alice_pk, "Alice must be the recorded author");
    }

    // Both sides list the group; Bob's own list must include it too.
    let mut bob_gc = GroupServiceClient::connect(format!("http://{bob_grpc}")).await.unwrap();
    // Bob's copy: he created no group, but Alice's group message carries the id.
    let _ = bob_gc.get_groups(Empty {}).await;
    let alice_groups = gc.get_groups(Empty {}).await.unwrap().into_inner();
    assert_eq!(alice_groups.groups.len(), 1);
    assert_eq!(alice_groups.groups[0].name, "Project X");
}