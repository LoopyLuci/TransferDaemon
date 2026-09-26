//! `dhtd` — standalone DHT bootstrap node for a hosted relay deployment.
//!
//! Runs a Kademlia DHT node that peers bootstrap against and that holds
//! published `PeerEndpoint` records so discovery works for NAT'd clients.
//! Pairs with `relayd` on a public VPS:
//!
//!   $env:DHTD_BIND="0.0.0.0:7901"
//!   $env:DHTD_ADVERTISE="203.0.113.10:7901"   # the VPS's public IP:port
//!   cargo run -p transferd-relay --bin dhtd
//!
//! Clients point `TRANSFERD_DHT_BOOTSTRAP` at `<public-ip>:7901`.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let bind = std::env::var("DHTD_BIND").unwrap_or_else(|_| "0.0.0.0:7901".to_owned());
    let advertised = std::env::var("DHTD_ADVERTISE").ok().and_then(|s| s.parse::<SocketAddr>().ok());

    let mut id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);

    let node = transferd_relay::DhtNode::start_with_advertised(&bind, id, advertised).await?;
    println!(
        "dhtd: listening on {bind} (advertised {})",
        advertised.map(|a| a.to_string()).unwrap_or_else(|| bind.clone())
    );
    println!("dhtd: node id {}", hex(&id[..4]));
    println!("dhtd: reachable at {}", node.addr());

    // Run forever; the receive loop + store pruner run on spawned tasks.
    std::future::pending::<()>().await;
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}