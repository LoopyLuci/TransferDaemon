//! Two daemons over real TCP, through the real gRPC handlers and the real transport tick: what happens when the
//! connection between them drops, when both sides send, and when a blocked contact sends a file.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use transferd_api::{MessageServiceClient, SendFileRequest, SendTextRequest, TransferServiceClient};
use transferd_lib::state::{Contact, DaemonState};
use transferd_lib::transport::{retry_pending_sessions, spawn_inbound_listener, tick_once};
use transferd_lib::{grpc::add_all_services, new_state};

const BOB_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ALICE_PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

type State = Arc<Mutex<DaemonState>>;

async fn start_grpc(state: State) -> SocketAddr {
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

/// Run the daemon's own transport pass and its session retry (the two loops `spawn_transport_tick` runs) until
/// `cond` holds or `timeout` passes.
async fn run_until(states: &[&State], timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        for s in states {
            tick_once(s).await;
            retry_pending_sessions(s).await;
        }
        if cond() {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn contact(id: &str, name: &str, address: Option<String>, blocked: bool) -> Contact {
    Contact {
        id: id.into(),
        name: name.into(),
        last_seen_ts: 0,
        online: false,
        blocked,
        address,
        hybrid_public_key: None,
        limits: None,
    }
}

/// Our own public key, as the daemon reports it.
fn public_key(state: &State) -> String {
    state.lock().identity.as_ref().unwrap().public_key.clone()
}

/// The status and text of every stored message in a thread, for assertions.
fn thread_of(state: &State, contact_id: &str) -> Vec<(String, String, String, bool)> {
    state
        .lock()
        .messages
        .get(contact_id)
        .map(|v| v.iter().map(|m| (m.id.clone(), m.text.clone(), m.status.clone(), m.outbound)).collect())
        .unwrap_or_default()
}

/// A TCP relay between two daemons that can cut every connection it carries, the way a dropped network does.
struct CuttableProxy {
    addr: SocketAddr,
    conns: Arc<Mutex<Vec<JoinHandle<()>>>>,
    accept: JoinHandle<()>,
}

async fn start_proxy(target: SocketAddr) -> CuttableProxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conns: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let conns_for_accept = conns.clone();
    let accept = tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else { continue };
            let conn = tokio::spawn(async move {
                if let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
            conns_for_accept.lock().push(conn);
        }
    });
    CuttableProxy { addr, conns, accept }
}

impl CuttableProxy {
    /// Drop every connection through the proxy. Both ends see the socket close.
    fn cut(&self) {
        for conn in self.conns.lock().drain(..) {
            conn.abort();
        }
    }
}

impl Drop for CuttableProxy {
    fn drop(&mut self) {
        self.accept.abort();
        self.cut();
    }
}

/// Bob's daemon: an identity and a peer listener on an ephemeral port.
async fn bob() -> (State, SocketAddr) {
    let state = new_state();
    state.lock().install_identity(BOB_PHRASE, "Bob");
    let addr = spawn_inbound_listener(state.clone(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    (state, addr)
}

/// Alice's daemon: an identity, a gRPC address to send through, and a peer listener of her own.
async fn alice() -> (State, SocketAddr, SocketAddr) {
    let state = new_state();
    state.lock().install_identity(ALICE_PHRASE, "Alice");
    let peer = spawn_inbound_listener(state.clone(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    let grpc = start_grpc(state.clone()).await;
    (state, grpc, peer)
}

async fn send_text(grpc: SocketAddr, to: &str, text: &str) -> String {
    let mut msg = MessageServiceClient::connect(format!("http://{grpc}")).await.unwrap();
    msg.send_text(SendTextRequest { contact_id: to.into(), text: text.into(), reply_to: String::new() })
        .await
        .unwrap()
        .into_inner()
        .id
}

#[tokio::test]
async fn messages_still_arrive_after_the_connection_drops() {
    let (bob_state, bob_addr) = bob().await;
    let proxy = start_proxy(bob_addr).await;
    let (alice_state, alice_grpc, _) = alice().await;
    let bob_pk = public_key(&bob_state);
    alice_state.lock().contacts.push(contact(&bob_pk, "Bob", Some(proxy.addr.to_string()), false));

    send_text(alice_grpc, &bob_pk, "one").await;
    assert!(
        run_until(&[&alice_state, &bob_state], Duration::from_secs(10), || {
            thread_of(&bob_state, &public_key(&alice_state)).iter().any(|m| m.1 == "one")
        })
        .await,
        "the first message is delivered over the connection"
    );

    // The network drops. Alice sends again straight away: that message must not be stranded on the dead connection.
    proxy.cut();
    let two = send_text(alice_grpc, &bob_pk, "two").await;

    let alice_pk = public_key(&alice_state);
    let delivered = run_until(&[&alice_state, &bob_state], Duration::from_secs(20), || {
        let at_bob = thread_of(&bob_state, &alice_pk);
        let at_alice = thread_of(&alice_state, &bob_pk);
        at_bob.iter().any(|m| m.1 == "two")
            && at_alice.iter().any(|m| m.0 == two && m.2 == "delivered")
    })
    .await;
    assert!(delivered, "a message sent across a dropped connection is delivered once a connection is up again");

    let at_bob = thread_of(&bob_state, &alice_pk);
    assert_eq!(at_bob.iter().filter(|m| m.1 == "one").count(), 1, "nothing is delivered twice");
    assert_eq!(at_bob.iter().filter(|m| m.1 == "two").count(), 1, "nothing is delivered twice");
}

#[tokio::test]
async fn both_sides_send_and_both_see_delivered() {
    let (bob_state, bob_addr) = bob().await;
    let (alice_state, alice_grpc, alice_addr) = alice().await;
    let bob_grpc = start_grpc(bob_state.clone()).await;

    let bob_pk = public_key(&bob_state);
    let alice_pk = public_key(&alice_state);
    alice_state.lock().contacts.push(contact(&bob_pk, "Bob", Some(bob_addr.to_string()), false));
    bob_state.lock().contacts.push(contact(&alice_pk, "Alice", Some(alice_addr.to_string()), false));

    // Both daemons have used their counters the same number of times: their first message ids would collide if
    // ids were counters.
    let from_alice = send_text(alice_grpc, &bob_pk, "hi Bob").await;
    let from_bob = send_text(bob_grpc, &alice_pk, "hi Alice").await;
    assert_ne!(from_alice, from_bob, "two daemons never hand out the same id");

    let done = run_until(&[&alice_state, &bob_state], Duration::from_secs(15), || {
        let a = thread_of(&alice_state, &bob_pk);
        let b = thread_of(&bob_state, &alice_pk);
        a.iter().any(|m| m.0 == from_alice && m.2 == "delivered")
            && b.iter().any(|m| m.0 == from_bob && m.2 == "delivered")
    })
    .await;
    assert!(done, "each side's own message reports delivered (not stuck pending behind the other's id)");
}

#[tokio::test]
async fn a_blocked_contacts_file_is_not_written_to_disk() {
    let downloads = tempfile::tempdir().unwrap();
    let source = downloads.path().join("secret-source.bin");
    std::fs::write(&source, b"do not keep").unwrap();
    let inbox = downloads.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    std::env::set_var("TRANSFERD_DOWNLOADS_DIR", &inbox);

    let (bob_state, bob_addr) = bob().await;
    let (alice_state, alice_grpc, _) = alice().await;
    let bob_pk = public_key(&bob_state);
    let alice_pk = public_key(&alice_state);
    alice_state.lock().contacts.push(contact(&bob_pk, "Bob", Some(bob_addr.to_string()), false));
    // Bob has blocked Alice.
    bob_state.lock().contacts.push(contact(&alice_pk, "Alice", None, true));

    let mut transfers = TransferServiceClient::connect(format!("http://{alice_grpc}")).await.unwrap();
    transfers
        .send_file(SendFileRequest {
            contact_id: bob_pk.clone(),
            file_path: source.to_string_lossy().into_owned(),
            file_name: "photo.jpg".into(),
            file_size: 11,
            mime_type: "image/jpeg".into(),
        })
        .await
        .unwrap();

    run_until(&[&alice_state, &bob_state], Duration::from_secs(4), || false).await;

    assert!(
        std::fs::read_dir(&inbox).unwrap().next().is_none(),
        "a blocked contact's file must not be written to the downloads folder"
    );
    assert!(
        !bob_state.lock().messages.values().flatten().any(|m| m.content_type == "file"),
        "nor stored as a message"
    );
}

