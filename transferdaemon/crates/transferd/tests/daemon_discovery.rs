//! Peer discovery E2E: daemons find each other via the DHT and deliver a
//! message over the relay — no explicit contact address needed.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use relayd::protocol::{DeliveredMsg, ForwardMsg, RegisterMsg, Tag, encode, split};
use relayd::relay::Relay;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex as TokioMutex;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use transferd_api::{AccountServiceClient, CreateIdentityRequest, MessageServiceClient, SendTextRequest, Empty};
use transferd_lib::peer_discovery::{publish_endpoint_if_ready, resolve_peer};
use transferd_lib::state::{Contact, DaemonState};
use transferd_lib::{grpc::add_all_services, new_state};

async fn run_relay_server(socket: UdpSocket, relay: Arc<TokioMutex<Relay>>) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 65536];

    async fn send_challenge(relay: &Arc<TokioMutex<Relay>>, socket: &Arc<UdpSocket>, src: std::net::SocketAddr) {
        let (challenge, expires_at, difficulty) = {
            let mut r = relay.lock().await;
            let c = r.current_challenge();
            (c.bytes, c.expires_at, c.difficulty)
        };
        let frame = encode(
            Tag::Challenge,
            &relayd::protocol::ChallengeMsg { challenge, expires_at, difficulty },
        )
        .unwrap_or_default();
        let _ = socket.send_to(&frame, src).await;
    }

    loop {
        let Ok((len, src)) = socket.recv_from(&mut buf).await else { return };
        let frame = &buf[..len];
        let Some((tag, body)) = split(frame) else { continue };
        let socket = socket.clone();
        let relay = relay.clone();
        match tag {
            Tag::Challenge => send_challenge(&relay, &socket, src).await,
            Tag::Register => {
                if let Ok(msg) = bincode::deserialize::<RegisterMsg>(body) {
                    let _ = relay.lock().await.register(&msg, src);
                    send_challenge(&relay, &socket, src).await;
                }
            }
            Tag::Forward => {
                if let Ok(msg) = bincode::deserialize::<ForwardMsg>(body) {
                    if let Ok(dst) = relay.lock().await.forward(&msg) {
                        let delivered = encode(
                            Tag::Ack,
                            &DeliveredMsg { sender_seq: msg.sender_seq, ciphertext: msg.ciphertext },
                        )
                        .unwrap_or_default();
                        let _ = socket.send_to(&delivered, dst).await;
                        let ack = encode(
                            Tag::Ack,
                            &relayd::protocol::AckMsg { sender_seq: msg.sender_seq },
                        )
                        .unwrap_or_default();
                        let _ = socket.send_to(&ack, src).await;
                    }
                }
            }
            Tag::Keepalive | Tag::Error | Tag::Ack => {}
        }
    }
}

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

async fn wait_for_hub(state: &Arc<Mutex<DaemonState>>) {
    for _ in 0..100 {
        if state.lock().relay_hub.is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("relay hub did not start");
}

#[tokio::test]
async fn peer_discovers_contact_via_dht_and_delivers() {
    // Inline relay.
    let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_socket.local_addr().unwrap();
    let relay = Arc::new(TokioMutex::new(Relay::new(8, 90, 63 * 1024)));
    tokio::spawn(run_relay_server(relay_socket, relay));

    std::env::set_var("TRANSFERD_RELAY_ADDR", relay_addr.to_string());

    // Two DHT nodes that know each other.
    let dht_a = transferd_relay::DhtNode::start("127.0.0.1:0", [1u8; 32]).await.unwrap();
    let dht_b = transferd_relay::DhtNode::start("127.0.0.1:0", [2u8; 32]).await.unwrap();
    let dht_a_addr = dht_a.addr();
    let dht_b_addr = dht_b.addr();
    let dht_a = Arc::new(dht_a);
    let dht_b = Arc::new(dht_b);
    dht_a.bootstrap(vec![dht_b_addr]).await;
    dht_b.bootstrap(vec![dht_a_addr]).await;

    // ── Receiver daemon (Bob) ────────────────────────────────────────────────
    let recv_state = new_state();
    recv_state.lock().dht = Some(dht_b.clone());
    let recv_grpc = start_grpc(recv_state.clone()).await;
    let recv_url = format!("http://{recv_grpc}");
    let mut recv_acct = AccountServiceClient::connect(recv_url.clone()).await.unwrap();
    recv_acct
        .create_identity(CreateIdentityRequest { display_name: "Bob".into() })
        .await
        .unwrap();
    wait_for_hub(&recv_state).await;
    // Publish Bob's endpoint so the sender can discover it.
    publish_endpoint_if_ready(&recv_state).await;
    let recv_pk = recv_acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;
    // Give the DHT a moment to replicate.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ── Sender daemon (Alice) ────────────────────────────────────────────────
    let send_state = new_state();
    send_state.lock().dht = Some(dht_a.clone());
    let sender_grpc = start_grpc(send_state.clone()).await;
    let sender_url = format!("http://{sender_grpc}");
    let mut send_acct = AccountServiceClient::connect(sender_url.clone()).await.unwrap();
    send_acct
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();
    wait_for_hub(&send_state).await;

    // Sanity: Alice can resolve Bob's endpoint purely from his public key.
    let resolved = resolve_peer(&dht_a, &recv_pk).await.expect("must resolve Bob via DHT");
    assert!(!resolved.is_empty(), "resolved endpoint list must be non-empty");
    assert!(resolved.iter().any(|a| a.starts_with("relay://")), "resolved addresses must be relay URIs: {resolved:?}");

    // Alice adds Bob WITHOUT an address — discovery must fill it in.
    {
        let mut s = send_state.lock();
        s.contacts.push(Contact {
            id: recv_pk.clone(),
            name: "Bob".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: None,
			 hybrid_public_key: None,
        });
    }

    let mut send_msg = MessageServiceClient::connect(sender_url.clone()).await.unwrap();
    send_msg
        .send_text(SendTextRequest {
            contact_id: recv_pk.clone(),
            text: "found you via the DHT".into(),
            reply_to: String::new(),
        })
        .await
        .unwrap();

    for _ in 0..500 {
        pump_transport(&send_state).await;
        let delivered = {
            let s = recv_state.lock();
            s.messages.values().flatten().any(|m| m.text == "found you via the DHT")
        };
        if delivered {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let s = recv_state.lock();
    let got = s
        .messages
        .values()
        .flatten()
        .find(|m| m.text == "found you via the DHT")
        .expect("receiver must have the discovered message");
    assert!(!got.outbound);
}
