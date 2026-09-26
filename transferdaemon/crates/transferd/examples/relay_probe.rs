//! Desktop → Kindle relay E2E probe.
//!
//! Spawns a real desktop daemon in-process (relay + DHT enabled), creates an
//! identity on the Kindle's daemon (adb-forwarded gRPC), adds the Kindle as a
//! contact, and sends a message that is delivered over the relay via DHT
//! endpoint discovery. Requires the relay + Kindle already set up:
//!
//!   # relay (on the desktop)
//!   $env:RELAYD_PORT=5901; $env:RELAYD_DIFFICULTY=0; cargo run -p relayd
//!
//!   # relay (on the desktop, LAN-reachable)
//!   $env:RELAYD_PORT=5901; $env:RELAYD_DIFFICULTY=0; cargo run -p relayd
//!
//!   # Kindle config (desktop LAN IP; the device is on the same Wi-Fi subnet)
//!   adb shell "mkdir -p /sdcard/Android/data/com.transferdaemon.app/files/TransferDaemon"
//!   adb push daemon.config /sdcard/Android/data/com.transferdaemon.app/files/TransferDaemon/
//!   adb forward tcp:50051 tcp:50051    # only the gRPC control plane needs adb
//!
//!   daemon.config:
//!     TRANSFERD_RELAY_ADDR=192.168.69.204:5901
//!     TRANSFERD_DHT_BIND=127.0.0.1:7901
//!     TRANSFERD_DHT_BOOTSTRAP=192.168.69.204:7901
//!
//! Then launch the app on the Kindle and run:
//!   cargo run -p transferd --example relay_probe

use std::time::Duration;

use transferd_api::{
    AccountServiceClient, AddContactRequest, CreateIdentityRequest, Empty, FriendServiceClient,
    GetMessagesRequest, MessageServiceClient, SendTextRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,transferd=debug")),
        )
        .with_test_writer()
        .init();

    // Desktop daemon (in-process) with relay + DHT.
    std::env::set_var("TRANSFERD_ADDR", "127.0.0.1:55051");
    std::env::set_var("TRANSFERD_RELAY_ADDR", "192.168.69.204:5901");
    std::env::set_var("TRANSFERD_DHT_BIND", "192.168.69.204:7901");
    std::env::set_var("TRANSFERD_DHT_BOOTSTRAP", "127.0.0.1:7901");
    let state = transferd_lib::new_state();
    let s = state.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("desktop rt");
        rt.block_on(async move {
            let _ = transferd_lib::grpc::add_all_services(
                tonic::transport::Server::builder(),
                s,
            )
            .serve("127.0.0.1:55051".parse().unwrap())
            .await;
        });
    });
    // Background transport tick: flush queued messages over the relay lane.
    transferd_lib::transport::spawn_transport_tick(state.clone());
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Desktop identity (spawns the desktop relay_hub + DHT).
    let mut acct = AccountServiceClient::connect("http://127.0.0.1:55051").await?;
    acct.create_identity(CreateIdentityRequest { display_name: "Desktop".into() })
        .await?;
    let desktop_pk = acct.get_public_key_hex(Empty {}).await?.into_inner().hex;

    // Kindle identity via adb-forwarded gRPC (spawns the Kindle relay_hub + DHT).
    let mut kacct = AccountServiceClient::connect("http://127.0.0.1:50051").await?;
    kacct.create_identity(CreateIdentityRequest { display_name: "Kindle".into() })
        .await?;
    let kindle_pk = kacct.get_public_key_hex(Empty {}).await?.into_inner().hex;
    println!("[relay] desktop={desktop_pk:?}… kindle={kindle_pk:?}…");

    // Let both relay_hubs register + publish to the DHT.
    tokio::time::sleep(Duration::from_secs(4)).await;

    if let Some(dht) = state.lock().dht.clone() {
        let (peers, stored) = dht.debug_stats();
        println!("[relay] desktop DHT: peers={peers} stored={stored}");
    }
    let (pk, _) = {
        let s = state.lock();
        (s.identity.as_ref().map(|i| i.public_key.clone()).unwrap_or_default(), s.contacts.len())
    };
    println!("[relay] desktop pk={pk}…");

    // Desktop adds the Kindle (no address → DHT discovery fills it in) + sends.
    let mut fc = FriendServiceClient::connect("http://127.0.0.1:55051").await?;
    fc.add_contact(AddContactRequest { public_key: kindle_pk.clone(), name: "Kindle".into() })
        .await?;
    let mut mc = MessageServiceClient::connect("http://127.0.0.1:55051").await?;
    mc.send_text(SendTextRequest {
        contact_id: kindle_pk.clone(),
        text: "relay hello from the desktop".into(),
        reply_to: String::new(),
    })
    .await?;
    println!("[relay] sent; waiting for delivery…");

    // Diagnostic: poll the desktop for the message status.
    for i in 0..8 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let msgs = mc
            .get_messages(GetMessagesRequest { contact_id: kindle_pk.clone() })
            .await?
            .into_inner();
        let status = msgs.messages.iter().find(|m| m.text.contains("relay hello")).map(|m| m.status.clone()).unwrap_or_default();
        println!("[relay] t={i}s msg_status={status}");
        if status == "delivered" {
            println!("[relay] DELIVERED to the Kindle over the relay (DHT-discovered)!");
            break;
        }
        if i == 7 {
            return Err("message was not delivered over the relay".into());
        }
    }

    // ── Reverse leg: the Kindle replies back over the relay ──────────────────
    // Add the desktop as a contact on the Kindle (DHT will fill the address)
    // and send a reply. This exercises the mobile daemon's transport tick
    // (flush path) + the responder's outbound relay lane.
    let mut kfc = FriendServiceClient::connect("http://127.0.0.1:50051").await?;
    kfc.add_contact(AddContactRequest { public_key: desktop_pk.clone(), name: "Desktop".into() })
        .await?;
    let mut kmc = MessageServiceClient::connect("http://127.0.0.1:50051").await?;
    kmc.send_text(SendTextRequest {
        contact_id: desktop_pk.clone(),
        text: "reply from the kindle over the relay".into(),
        reply_to: String::new(),
    })
    .await?;
    println!("[relay] reply sent from Kindle; waiting…");

    // Poll the DESKTOP for the Kindle's reply.
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let msgs = mc
            .get_messages(GetMessagesRequest { contact_id: kindle_pk.clone() })
            .await?
            .into_inner();
        if msgs.messages.iter().any(|m| m.text.contains("reply from the kindle")) {
            println!("[relay] ROUND-TRIP COMPLETE: Kindle reply received on the desktop over the relay!");
            return Ok(());
        }
    }
    Err("the Kindle's reply was not received over the relay".into())
}