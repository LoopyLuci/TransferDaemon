//! On-device notification probe.
//!
//! Connects to a device's daemon over adb-forwarded ports, gives it an identity
//! (so its transport will accept a peer), then performs a full authenticated
//! hybrid handshake + ratcheted TcpLane and sends a real 1:1 text message.
//! The device should raise a system notification via `NotificationHelper`.
//!
//! Usage:
//!   adb forward tcp:50051 tcp:50051
//!   adb forward tcp:50052 tcp:50052
//!   cargo run -p transferd --example notify_probe -- http://127.0.0.1:50051 127.0.0.1:50052

use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use transferd_api::{AccountServiceClient, CreateIdentityRequest};
use transferd_core::lanes::tcp_lane::TcpLane;
use transferd_core::transport::TransportLane;
use transferd_core::transport::Chunk;
use transferd_core::types::{Gsn, SessionId};
use transferd_crypto::identity::HybridSigningKey;
use transferd_crypto::ratchet::DoubleRatchet;
use transferd_lib::handshake_manager::HandshakeManager;
use transferd_lib::peer_manager::directional_keys;
use transferd_lib::wire::WireMsg;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_grpc = std::env::args().nth(1).unwrap_or_else(|| "http://127.0.0.1:50051".into());
    let device_transport = std::env::args().nth(2).unwrap_or_else(|| "127.0.0.1:50052".into());

    // 1. Give the device daemon an identity so its transport accepts us.
    let mut acct = AccountServiceClient::connect(device_grpc).await?;
    acct.create_identity(CreateIdentityRequest { display_name: "Kindle".into() })
        .await?;
    println!("[probe] device identity created");

    // 2. Authenticated hybrid handshake to the device transport (initiator).
    let identity = HybridSigningKey::from_bip39_seed(&[9u8; 64]);
    let my_pk = hex::encode(&identity.verifying_key().to_bytes()[..32]);
    let mut stream = tokio::net::TcpStream::connect(&device_transport).await?;
    let handshake = HandshakeManager::new();
    let (session_key, _peer) = handshake.run_initiator_on(&mut stream, &identity).await?;
    let (send_key, recv_key) = directional_keys(&session_key.key);
    let lane = TcpLane::from_stream(0x54435020, stream, &send_key, &recv_key)?;
    println!("[probe] handshake complete, lane established");

    // 3. Ratchet + send a real 1:1 text message.
    let mut ratchet = DoubleRatchet::new(&session_key.key, true);
    let wire = WireMsg::Text {
        sender: my_pk,
        msg_id: "notify-probe-1".into(),
        text: "Hello from the desktop — notification probe!".into(),
        ts: now_secs(),
        group_id: None,
        reply_to: None,
    };
    let rm = ratchet.encrypt(&wire.encode()?)?;
    lane.send(Chunk {
        gsn: Gsn(0),
        session_id: SessionId([0u8; 16]),
        payload: Bytes::from(bincode::serialize(&rm)?),
        key_epoch: 0,
        qos_critical: false,
    })
    .await?;
    println!("[probe] message sent — check the device for a notification");

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    Ok(())
}