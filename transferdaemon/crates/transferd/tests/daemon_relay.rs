//! Two-daemon end-to-end delivery over a real UDP relay.
//!
//! Topology:
//!   sender daemon → RelayLane → inline relayd (UDP) → receiver daemon's RelayHub
//!
//! Exercises: PoW challenge bootstrap, X25519 handshake tunneled over the relay,
//! per-direction AES-GCM keys, power-of-two padding, and end-to-end delivery.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use relayd::protocol::{DeliveredMsg, ForwardMsg, RegisterMsg, Tag, encode, split};
use relayd::relay::Relay;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex as TokioMutex;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use transferd_api::{
    AccountServiceClient, CreateIdentityRequest, MessageServiceClient,
    SendTextRequest, Empty,
};
use transferd_lib::peer_discovery::{publish_endpoint_if_ready, resolve_peer};
use transferd_lib::relay_hub::relay_token_for;
use transferd_lib::state::{Contact, DaemonState};
use transferd_lib::{grpc::add_all_services, new_state};

/// The relay address comes from a process-global env var, so relay tests must
/// not run concurrently (tokio::test defaults to parallel) or one test's hub
/// can register with the other's relay.
static RELAY_TEST_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

async fn relay_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    RELAY_TEST_LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await
}

// ---------------------------------------------------------------------------
// Inline relay server (difficulty 8 → fast PoW, still exercises the solver)
// ---------------------------------------------------------------------------

async fn run_relay_server(
    socket: Arc<UdpSocket>,
    relay: Arc<TokioMutex<Relay>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
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
        tokio::select! {
            _ = stop.changed() => return,
            result = socket.recv_from(&mut buf) => {
                let (len, src) = match result { Ok(x) => x, Err(_) => return };
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
    }
}

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

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn text_delivers_between_two_daemons_over_relay() {
    let _guard = relay_test_lock().await;
    // Spin up the relay (difficulty 8) on an ephemeral port.
    let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_socket.local_addr().unwrap();
    let relay = Arc::new(TokioMutex::new(Relay::new(8, 90, 63 * 1024)));
    let (_stop, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(run_relay_server(Arc::new(relay_socket), relay, stop_rx));

    // Both daemons use this relay.
    std::env::set_var("TRANSFERD_RELAY_ADDR", relay_addr.to_string());

    // ── Receiver daemon ────────────────────────────────────────────────────
    let recv_state = new_state();
    let recv_grpc = start_grpc(recv_state.clone()).await;
    let recv_url = format!("http://{recv_grpc}");
    let mut recv_acct = AccountServiceClient::connect(recv_url.clone()).await.unwrap();
    recv_acct
        .create_identity(CreateIdentityRequest { display_name: "Bob".into() })
        .await
        .unwrap();
    // Wait for the relay hub to register Bob's token.
    for _ in 0..100 {
        if recv_state.lock().relay_hub.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(recv_state.lock().relay_hub.is_some(), "receiver relay hub must start");
    let recv_pk = recv_acct
        .get_public_key_hex(Empty {})
        .await
        .unwrap()
        .into_inner()
        .hex;
    let recv_token = relay_token_for(&recv_pk);

    // ── Sender daemon ──────────────────────────────────────────────────────
    let send_state = new_state();
    let sender_grpc = start_grpc(send_state.clone()).await;
    let sender_url = format!("http://{sender_grpc}");
    let mut send_acct = AccountServiceClient::connect(sender_url.clone()).await.unwrap();
    send_acct
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();
    for _ in 0..100 {
        if send_state.lock().relay_hub.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(send_state.lock().relay_hub.is_some(), "sender relay hub must start");

    // Sender adds Bob via his relay address (token derived from Bob's public key).
    let peer_pk = recv_pk.clone();
    {
        let mut s = send_state.lock();
        s.contacts.push(Contact {
            id: peer_pk.clone(),
            name: "Bob".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: Some(format!("relay://{relay_addr}/{}", hex::encode(recv_token))),
            hybrid_public_key: None,
            limits: None,
        });
    }
    // (The contact + relay address are set directly on the state above;
    //  add_contact RPC does not carry an address.)

    // Send a text message over the relay.
    let mut send_msg = MessageServiceClient::connect(sender_url.clone()).await.unwrap();
    send_msg
        .send_text(SendTextRequest {
            contact_id: peer_pk.clone(),
            text: "hello over the relay".into(),

            reply_to: String::new(),
        })
        .await
        .unwrap();

    // Pump the sender transport until the receiver has the message.
    for _ in 0..500 {
        pump_transport(&send_state).await;
        let delivered = {
            let s = recv_state.lock();
            s.messages.values().flatten().any(|m| m.text == "hello over the relay")
        };
        if delivered {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The receiver stored the inbound message from Alice.
    {
        let s = recv_state.lock();
        let got = s
            .messages
            .values()
            .flatten()
            .find(|m| m.text == "hello over the relay")
            .expect("receiver must have the relayed message");
        assert!(!got.outbound);
        assert_eq!(got.status, "delivered");
    }
}

/// Both peers initiate relay sessions to each other AND reply over the relay.
/// Exercises the role-aware session table: a single per-token session slot
/// would let the reverse handshake overwrite the forward one and drop the reply.
#[tokio::test]
async fn text_round_trips_between_two_daemons_over_relay() {
    let _guard = relay_test_lock().await;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("transferd_lib=debug,relayd=debug"))
        .with_test_writer()
        .try_init();
    let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_socket.local_addr().unwrap();
    let relay = Arc::new(TokioMutex::new(Relay::new(8, 90, 63 * 1024)));
    let (_stop, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(run_relay_server(Arc::new(relay_socket), relay, stop_rx));

    std::env::set_var("TRANSFERD_RELAY_ADDR", relay_addr.to_string());

    // Daemon A.
    let a_state = new_state();
    let a_grpc = start_grpc(a_state.clone()).await;
    let a_url = format!("http://{a_grpc}");
    let mut a_acct = AccountServiceClient::connect(a_url.clone()).await.unwrap();
    a_acct
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();
    for _ in 0..100 {
        if a_state.lock().relay_hub.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(a_state.lock().relay_hub.is_some(), "A relay hub must start");
    let a_pk = a_acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;
    let a_token = relay_token_for(&a_pk);

    // Daemon B.
    let b_state = new_state();
    let b_grpc = start_grpc(b_state.clone()).await;
    let b_url = format!("http://{b_grpc}");
    let mut b_acct = AccountServiceClient::connect(b_url.clone()).await.unwrap();
    b_acct
        .create_identity(CreateIdentityRequest { display_name: "Bob".into() })
        .await
        .unwrap();
    for _ in 0..100 {
        if b_state.lock().relay_hub.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(b_state.lock().relay_hub.is_some(), "B relay hub must start");
    let b_pk = b_acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;
    let b_token = relay_token_for(&b_pk);

    // Each daemon adds the other with the explicit relay address.
    for (state, peer, token) in [
        (&a_state, b_pk.clone(), b_token),
        (&b_state, a_pk.clone(), a_token),
    ] {
        state.lock().contacts.push(Contact {
            id: peer,
            name: "peer".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: Some(format!("relay://{relay_addr}/{}", hex::encode(token))),
            hybrid_public_key: None,
            limits: None,
        });
    }

    // A → B over the relay.
    eprintln!("[probe] A→B send");
    let mut a_msg = MessageServiceClient::connect(a_url.clone()).await.unwrap();
    a_msg
        .send_text(SendTextRequest { contact_id: b_pk.clone(), text: "from A".into(), reply_to: String::new() })
        .await
        .unwrap();
    eprintln!("[probe] A→B sent, pumping");
    for _ in 0..500 {
        pump_transport(&a_state).await;
        if b_state.lock().messages.values().flatten().any(|m| m.text == "from A") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    eprintln!("[probe] A→B done: {}", b_state.lock().messages.values().flatten().any(|m| m.text == "from A"));
    assert!(
        b_state.lock().messages.values().flatten().any(|m| m.text == "from A"),
        "B must receive A's message"
    );

    // B → A (the reverse session over the same relay).
    eprintln!("[probe] B→A send");
    let mut b_msg = MessageServiceClient::connect(b_url.clone()).await.unwrap();
    b_msg
        .send_text(SendTextRequest { contact_id: a_pk.clone(), text: "from B".into(), reply_to: String::new() })
        .await
        .unwrap();
    eprintln!("[probe] B→A sent, pumping");
    for _ in 0..500 {
        pump_transport(&b_state).await;
        if a_state.lock().messages.values().flatten().any(|m| m.text == "from B") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    eprintln!("[probe] B→A done: {}", a_state.lock().messages.values().flatten().any(|m| m.text == "from B"));
    {
        let s = a_state.lock();
        eprintln!("[probe] A pk starts={} b_pk starts={}", &a_pk[..8], &b_pk[..8]);
        for (k, v) in &s.messages {
            eprintln!("[probe] A key={} msgs={:?}", &k[..8], v.iter().map(|m| (&m.text[..], m.outbound, &m.status[..])).collect::<Vec<_>>());
        }
    }
    assert!(
        a_state.lock().messages.values().flatten().any(|m| m.text == "from B"),
        "A must receive B's reverse-session reply"
    );
}

/// Two daemons on TWO relays, discovered via the DHT. The session builds a lane
/// to every shared relay; when one relay dies, delivery continues over the
/// other (auto-routing / failover). Both directions survive.
#[tokio::test]
async fn text_round_trips_over_two_relays_with_failover() {
    let _guard = relay_test_lock().await;
// Two inline relays.
    let (stop1_tx, stop1_rx) = tokio::sync::watch::channel(false);
    let (_stop2, stop2_rx) = tokio::sync::watch::channel(false);
    let r1_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let r1_addr = r1_socket.local_addr().unwrap();
    let r2_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let r2_addr = r2_socket.local_addr().unwrap();
    tokio::spawn(run_relay_server(r1_socket, Arc::new(TokioMutex::new(Relay::new(8, 90, 63 * 1024))), stop1_rx));
    tokio::spawn(run_relay_server(r2_socket, Arc::new(TokioMutex::new(Relay::new(8, 90, 63 * 1024))), stop2_rx));

    std::env::set_var("TRANSFERD_RELAY_ADDR", format!("{r1_addr},{r2_addr}"));

    // Two DHT nodes that know each other.
    let dht_a = Arc::new(transferd_relay::DhtNode::start("127.0.0.1:0", [0x31u8; 32]).await.unwrap());
    let dht_b = Arc::new(transferd_relay::DhtNode::start("127.0.0.1:0", [0x32u8; 32]).await.unwrap());
    let (da, db) = (dht_a.addr(), dht_b.addr());
    dht_a.bootstrap(vec![db]).await;
    dht_b.bootstrap(vec![da]).await;

    // ── Bob (receiver) ───────────────────────────────────────────────────────
    let b_state = new_state();
    b_state.lock().dht = Some(dht_b.clone());
    let b_grpc = start_grpc(b_state.clone()).await;
    let b_url = format!("http://{b_grpc}");
    let mut b_acct = AccountServiceClient::connect(b_url.clone()).await.unwrap();
    b_acct
        .create_identity(CreateIdentityRequest { display_name: "Bob".into() })
        .await
        .unwrap();
    for _ in 0..100 {
        if b_state.lock().relay_hub.is_some() { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(b_state.lock().relay_hub.is_some(), "Bob hub must register on both relays");
    publish_endpoint_if_ready(&b_state).await;
    let b_pk = b_acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Alice (sender) ───────────────────────────────────────────────────────
    let a_state = new_state();
    a_state.lock().dht = Some(dht_a.clone());
    let a_grpc = start_grpc(a_state.clone()).await;
    let a_url = format!("http://{a_grpc}");
    let mut a_acct = AccountServiceClient::connect(a_url.clone()).await.unwrap();
    a_acct
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();
    for _ in 0..100 {
        if a_state.lock().relay_hub.is_some() { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(a_state.lock().relay_hub.is_some(), "Alice hub must register on both relays");
    let a_pk = a_acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;

    // Bob publishes BOTH relays; Alice resolves both.
    let resolved = resolve_peer(&dht_a, &b_pk).await.expect("resolve Bob via DHT").0;
    assert_eq!(resolved.len(), 2, "Bob must publish both relays: {resolved:?}");

    a_state.lock().contacts.push(Contact {
        id: b_pk.clone(),
        name: "Bob".into(),
        last_seen_ts: 0,
        online: false,
        blocked: false,
        address: None,
        hybrid_public_key: None,
            limits: None,
    });

    // Message 1: over both relays (2 lanes).
    let mut a_msg = MessageServiceClient::connect(a_url.clone()).await.unwrap();
    a_msg
        .send_text(SendTextRequest { contact_id: b_pk.clone(), text: "over two relays".into(), reply_to: String::new() })
        .await
        .unwrap();
    for _ in 0..500 {
        pump_transport(&a_state).await;
        if b_state.lock().messages.values().flatten().any(|m| m.text == "over two relays") { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        b_state.lock().messages.values().flatten().any(|m| m.text == "over two relays"),
        "message must deliver over the two-relay session"
    );

// Kill relay 1. Delivery must continue over relay 2 (auto-routing).
    let _ = stop1_tx.send(true);

    a_msg
        .send_text(SendTextRequest { contact_id: b_pk.clone(), text: "after relay1 died".into(), reply_to: String::new() })
        .await
        .unwrap();
    for _ in 0..1500 {
        pump_transport(&a_state).await;
        if b_state.lock().messages.values().flatten().any(|m| m.text == "after relay1 died") { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        b_state.lock().messages.values().flatten().any(|m| m.text == "after relay1 died"),
        "delivery must fail over to relay 2 after relay 1 dies"
    );

    // Reverse leg after failover.
    let mut b_msg = MessageServiceClient::connect(b_url.clone()).await.unwrap();
    b_msg
        .send_text(SendTextRequest { contact_id: a_pk.clone(), text: "reply after failover".into(), reply_to: String::new() })
        .await
        .unwrap();
    for _ in 0..1500 {
        pump_transport(&b_state).await;
        if a_state.lock().messages.values().flatten().any(|m| m.text == "reply after failover") { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        a_state.lock().messages.values().flatten().any(|m| m.text == "reply after failover"),
        "reverse leg must survive relay 1 death"
    );
}
/// Two daemons deliver through a WebSocket relay (the relayd-ws protocol) —
/// the firewall-agnostic transport. Both register on the WS relay, publish
/// ws:// endpoints to the DHT, and the session builds a WS relay lane.
#[tokio::test]
async fn text_delivers_between_two_daemons_over_ws_relay() {
    let _guard = relay_test_lock().await;
    // In-process WebSocket relay (difficulty 4 = fast PoW).
    let ws_relay = Arc::new(TokioMutex::new(relayd::ws::WsRelay::new(4, 90)));
    tokio::spawn(relayd::ws::maintenance_loop(ws_relay.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else { break };
            let ws_relay = ws_relay.clone();
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else { return };
                relayd::ws::handle_connection(ws, peer, ws_relay).await;
            });
        }
    });

    std::env::set_var("TRANSFERD_RELAY_ADDR", format!("ws://{ws_addr}"));

    // Two DHT nodes that know each other.
    let dht_a = Arc::new(transferd_relay::DhtNode::start("127.0.0.1:0", [0x41u8; 32]).await.unwrap());
    let dht_b = Arc::new(transferd_relay::DhtNode::start("127.0.0.1:0", [0x42u8; 32]).await.unwrap());
    let (da, db) = (dht_a.addr(), dht_b.addr());
    dht_a.bootstrap(vec![db]).await;
    dht_b.bootstrap(vec![da]).await;

    // ── Bob (receiver) ───────────────────────────────────────────────────────
    let b_state = new_state();
    b_state.lock().dht = Some(dht_b.clone());
    let b_grpc = start_grpc(b_state.clone()).await;
    let b_url = format!("http://{b_grpc}");
    let mut b_acct = AccountServiceClient::connect(b_url.clone()).await.unwrap();
    b_acct
        .create_identity(CreateIdentityRequest { display_name: "Bob".into() })
        .await
        .unwrap();
    for _ in 0..100 {
        if b_state.lock().relay_hub.is_some() { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(b_state.lock().relay_hub.is_some(), "Bob hub must register on the WS relay");
    publish_endpoint_if_ready(&b_state).await;
    let b_pk = b_acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Alice (sender) ───────────────────────────────────────────────────────
    let a_state = new_state();
    a_state.lock().dht = Some(dht_a.clone());
    let a_grpc = start_grpc(a_state.clone()).await;
    let a_url = format!("http://{a_grpc}");
    let mut a_acct = AccountServiceClient::connect(a_url.clone()).await.unwrap();
    a_acct
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();
    for _ in 0..100 {
        if a_state.lock().relay_hub.is_some() { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(a_state.lock().relay_hub.is_some(), "Alice hub must register on the WS relay");

    // Bob published a ws:// endpoint; Alice resolves a wsrelay:// URI.
    let resolved = resolve_peer(&dht_a, &b_pk).await.expect("resolve Bob via DHT").0;
    assert!(resolved.iter().any(|a| a.starts_with("wsrelay://")), "Bob must publish a WS relay URI: {resolved:?}");

    a_state.lock().contacts.push(Contact {
        id: b_pk.clone(),
        name: "Bob".into(),
        last_seen_ts: 0,
        online: false,
        blocked: false,
        address: None,
        hybrid_public_key: None,
            limits: None,
    });

    let mut a_msg = MessageServiceClient::connect(a_url.clone()).await.unwrap();
    a_msg
        .send_text(SendTextRequest { contact_id: b_pk.clone(), text: "over the websocket relay".into(), reply_to: String::new() })
        .await
        .unwrap();
    for _ in 0..1000 {
        pump_transport(&a_state).await;
        if b_state.lock().messages.values().flatten().any(|m| m.text == "over the websocket relay") { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let s = b_state.lock();
    let got = s
        .messages
        .values()
        .flatten()
        .find(|m| m.text == "over the websocket relay")
        .expect("receiver must get the WS-relayed message");
    assert!(!got.outbound);
}

/// Direct P2P discovery: a peer publishes a direct 	cp:// address (e.g. a
/// Tailscale / LAN address); the other discovers it via the DHT and connects
/// WITHOUT any relay — the direct lane is preferred over relays.
#[tokio::test]
async fn peer_discovers_direct_address_and_connects_without_a_relay() {
    let _guard = relay_test_lock().await;
    // No relay at all. Two DHT nodes that know each other.
    let dht_a = Arc::new(transferd_relay::DhtNode::start("127.0.0.1:0", [0x51u8; 32]).await.unwrap());
    let dht_b = Arc::new(transferd_relay::DhtNode::start("127.0.0.1:0", [0x52u8; 32]).await.unwrap());
    let (da, db) = (dht_a.addr(), dht_b.addr());
    dht_a.bootstrap(vec![db]).await;
    dht_b.bootstrap(vec![da]).await;

    // ── Bob: daemon + a peer transport listener on a reachable address ───────
    let b_state = new_state();
    b_state.lock().dht = Some(dht_b.clone());
    let b_grpc = start_grpc(b_state.clone()).await;
    let b_url = format!("http://{b_grpc}");
    let mut b_acct = AccountServiceClient::connect(b_url.clone()).await.unwrap();
    b_acct
        .create_identity(CreateIdentityRequest { display_name: "Bob".into() })
        .await
        .unwrap();
    // Spawn the peer transport listener (localhost for the test) + record it.
    let b_listener = transferd_lib::transport::spawn_inbound_listener(
        b_state.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    b_state.lock().peer_listen = Some(b_listener);
    publish_endpoint_if_ready(&b_state).await;
    let b_pk = b_acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Alice ─────────────────────────────────────────────────────────────────
    let a_state = new_state();
    a_state.lock().dht = Some(dht_a.clone());
    let a_grpc = start_grpc(a_state.clone()).await;
    let a_url = format!("http://{a_grpc}");
    let mut a_acct = AccountServiceClient::connect(a_url.clone()).await.unwrap();
    a_acct
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap();

    // Bob published a DIRECT address (no relay configured at all).
    let resolved = resolve_peer(&dht_a, &b_pk).await.expect("resolve Bob via DHT").0;
    assert!(resolved.iter().any(|a| a.starts_with("tcp://")), "Bob must publish a direct tcp:// address: {resolved:?}");
    assert!(!resolved.iter().any(|a| a.starts_with("relay://")), "no relay should be published: {resolved:?}");

    a_state.lock().contacts.push(Contact {
        id: b_pk.clone(),
        name: "Bob".into(),
        last_seen_ts: 0,
        online: false,
        blocked: false,
        address: None,
        hybrid_public_key: None,
            limits: None,
    });

    let mut a_msg = MessageServiceClient::connect(a_url.clone()).await.unwrap();
    a_msg
        .send_text(SendTextRequest { contact_id: b_pk.clone(), text: "straight to the tailnet".into(), reply_to: String::new() })
        .await
        .unwrap();
    for _ in 0..500 {
        pump_transport(&a_state).await;
        if b_state.lock().messages.values().flatten().any(|m| m.text == "straight to the tailnet") { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let s = b_state.lock();
    let got = s
        .messages
        .values()
        .flatten()
        .find(|m| m.text == "straight to the tailnet")
        .expect("receiver must get the direct-delivered message");
    assert!(!got.outbound);
}

/// LIVE INTERNET E2E: two daemons deliver through the deployed Cloudflare
/// Worker relay (free tier, zero servers) at
/// wss://transferd-relay.limpidluci.workers.dev:443. The relay leg crosses
/// the public Internet — same client code as a self-hosted relayd-ws.
/// Ignored by default; run with -- --ignored once the Worker is deployed.
#[tokio::test]
#[ignore]
async fn text_delivers_between_two_daemons_over_public_cloudflare_worker() {
let _guard = relay_test_lock().await;
    std::env::set_var(
        "TRANSFERD_RELAY_ADDR",
        "wss://transferd-relay.limpidluci.workers.dev:443",
    );

    // Two loopback DHT nodes for discovery; the RELAY is the public Worker.
    let dht_a = Arc::new(transferd_relay::DhtNode::start("127.0.0.1:0", [0x61u8; 32]).await.unwrap());
    let dht_b = Arc::new(transferd_relay::DhtNode::start("127.0.0.1:0", [0x62u8; 32]).await.unwrap());
    let (da, db) = (dht_a.addr(), dht_b.addr());
    dht_a.bootstrap(vec![db]).await;
    dht_b.bootstrap(vec![da]).await;

    // ── Bob ──────────────────────────────────────────────────────────────────
    let b_state = new_state();
    b_state.lock().dht = Some(dht_b.clone());
    let b_grpc = start_grpc(b_state.clone()).await;
    let b_url = format!("http://{b_grpc}");
    let mut b_acct = AccountServiceClient::connect(b_url.clone()).await.unwrap();
    b_acct.create_identity(CreateIdentityRequest { display_name: "Bob".into() }).await.unwrap();
    for _ in 0..300 {
        if b_state.lock().relay_hub.is_some() { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(b_state.lock().relay_hub.is_some(), "Bob hub must register on the public Worker");
    publish_endpoint_if_ready(&b_state).await;
    let b_pk = b_acct.get_public_key_hex(Empty {}).await.unwrap().into_inner().hex;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ── Alice ────────────────────────────────────────────────────────────────
    let a_state = new_state();
    a_state.lock().dht = Some(dht_a.clone());
    let a_grpc = start_grpc(a_state.clone()).await;
    let a_url = format!("http://{a_grpc}");
    let mut a_acct = AccountServiceClient::connect(a_url.clone()).await.unwrap();
    a_acct.create_identity(CreateIdentityRequest { display_name: "Alice".into() }).await.unwrap();
    for _ in 0..300 {
        if a_state.lock().relay_hub.is_some() { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(a_state.lock().relay_hub.is_some(), "Alice hub must register on the public Worker");

    let resolved = resolve_peer(&dht_a, &b_pk).await.expect("resolve Bob via DHT").0;
    assert!(resolved.iter().any(|a| a.starts_with("wsrelay://")), "Bob must publish a wsrelay URI: {resolved:?}");

    a_state.lock().contacts.push(Contact {
        id: b_pk.clone(),
        name: "Bob".into(),
        last_seen_ts: 0,
        online: false,
        blocked: false,
        address: None,
        hybrid_public_key: None,
            limits: None,
    });

    let mut a_msg = MessageServiceClient::connect(a_url.clone()).await.unwrap();
    a_msg
        .send_text(SendTextRequest { contact_id: b_pk.clone(), text: "across the internet via the cloudflare worker".into(), reply_to: String::new() })
        .await
        .unwrap();
    for _ in 0..600 {
        pump_transport(&a_state).await;
        if b_state.lock().messages.values().flatten().any(|m| m.text == "across the internet via the cloudflare worker") { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let s = b_state.lock();
    let got = s
        .messages
        .values()
        .flatten()
        .find(|m| m.text == "across the internet via the cloudflare worker")
        .expect("receiver must get the Internet-relayed message");
    assert!(!got.outbound);
}





/// LIVE ON-DEVICE E2E: the DESKTOP daemon delivers a message to the real Kindle
/// through the deployed Cloudflare Worker. The Kindle's relay token is
/// identity-derived (relay_token_for), so the desktop addresses it directly via
/// the Worker's wss:// endpoint — no DHT needed for the delivery leg. Ignored;
/// run with -- --ignored with the Kindle running.
#[tokio::test]
#[ignore]
async fn desktop_sends_to_real_kindle_over_public_worker() {
    let _guard = relay_test_lock().await;
    std::env::set_var("TRANSFERD_RELAY_ADDR", "wss://transferd-relay.limpidluci.workers.dev:443");

    let a_state = new_state();
    let a_grpc = start_grpc(a_state.clone()).await;
    let a_url = format!("http://{a_grpc}");
    let mut a_acct = AccountServiceClient::connect(a_url.clone()).await.unwrap();
    a_acct.create_identity(CreateIdentityRequest { display_name: "Desktop".into() }).await.unwrap();
    for _ in 0..300 {
        if a_state.lock().relay_hub.is_some() { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(a_state.lock().relay_hub.is_some(), "desktop hub must register on the Worker");

// The Kindle's public key (from env KINDLE_PK; identity is re-created each
    // app launch since the mobile daemon doesn't persist it across restarts).
    let kindle_pk = std::env::var("KINDLE_PK").unwrap_or_else(|_| "26da5db79219f42b9d30965cbcf7805e8ba0d044dca624108d49236e678fd818".into());
    let token_hex = hex::encode(relay_token_for(kindle_pk.as_str()));
    let kindle_addr = format!("wsrelay://transferd-relay.limpidluci.workers.dev:443/{token_hex}");
    eprintln!("[diag] kindle relay token: {token_hex}");

a_state.lock().contacts.push(Contact {
        id: kindle_pk.to_string(),
        name: "Kindle".into(),
        last_seen_ts: 0,
        online: false,
        blocked: false,
        address: Some(kindle_addr),
        hybrid_public_key: None,
        limits: None,
    });

    // Directly attempt the relay handshake to the Kindle + print the outcome.
    {
        let s = a_state.lock();
        if let Some(hub) = &s.relay_hub {
            eprintln!("[diag] desktop self_token = {}", hex::encode(hub.self_token()));
            eprintln!("[diag] kindle token       = {}", hex::encode(relay_token_for(kindle_pk.as_str())));
            let id = s.hybrid_signing_key().expect("desktop identity");
            let spec = hub.relay_specs()[0];
            let result = hub.initiate(relay_token_for(kindle_pk.as_str()), &id, spec.0).await;
            eprintln!("[diag] hub.initiate(kindle) via {} = {:?}", spec.0, result.as_ref().map(|pk| format!("{}..", hex::encode(&pk[..4]))));
            // Probe-only: if the handshake didn't establish, skip the send/pump.
            if result.is_err() {
                eprintln!("[diag] handshake failed — skipping send/pump");
                return;
            }
        } else {
            eprintln!("[diag] no desktop hub");
        }
    }

    let mut a_msg = MessageServiceClient::connect(a_url.clone()).await.unwrap();
    a_msg
        .send_text(SendTextRequest { contact_id: kindle_pk.to_string(), text: "across the internet to the kindle via the cloudflare worker".into(), reply_to: String::new() })
        .await
        .expect("send must be accepted");
    for _ in 0..120 {
        pump_transport(&a_state).await;
        let sent = a_state.lock().messages.values().flatten()
            .any(|m| m.text == "across the internet to the kindle via the cloudflare worker" && m.status == "sent");
        if sent { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let s = a_state.lock();
    let m = s.messages.values().flatten()
        .find(|m| m.text == "across the internet to the kindle via the cloudflare worker")
        .expect("message must reach 'sent' (relay acked the forward)");
let hub = a_state.lock().relay_hub.clone();
    if let Some(hub) = hub {
        let tok = relay_token_for(kindle_pk.as_str());
        eprintln!("[diag] desktop hub has_session(kindle)={} root={:?}", hub.has_session(tok).await, hub.session_root(tok).await.map(|r| format!("{r:02x?}")));
    }
    assert_eq!(m.status, "sent", "relay must ack the forward to the Kindle: {:?}", m.status);
}

/// Compute relay tokens for a set of historical Kindle pks to identify a
/// mystery Worker registration.
#[tokio::test]
#[ignore]
async fn identify_mystery_token() {
    use transferd_lib::relay_hub::relay_token_for;
    let pks = [
        "26da5db79219f42b9d30965cbcf7805e8ba0d044dca624108d49236e678fd818",
        "2ae694d3b31e629aece3b4f07d3f31292951398b14188e2288cfaf3a5b2a8a47",
        "b4e2ac3e4d03e8e969fa3cad84364b00901893fca1fd06e46de662469d797fc3",
        "e2e507c37fd11feec3b7ddadfa065faeefd64402a8cdefea000cd55c7cb185a3",
        "db77920a2171926f295e11600cdf226da8e6b1729330f4b37b0667371a5ea0b9",
        "78dc9e9db7e19c62782e5f06b7974bdfe5011c50db487c52f4140ef4f9691916",
        "b5f107c0287cf31f341239d1dae38b8bc37519ea268a3d8cfb78eab188717a78",
        "f955dd810e7873cacf3579fabd8866cc4fab01f822053b2194ae4841e02e8789",
        "04a6ddefd9b5d2e15836d1fa105d918406d3d499e13627a64a55e95f98b1e451",
    ];
    for pk in pks {
        eprintln!("{} -> {}", &pk[..8], hex::encode(relay_token_for(pk)));
    }
}
