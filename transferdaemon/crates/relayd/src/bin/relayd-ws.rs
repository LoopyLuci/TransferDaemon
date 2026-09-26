//! `relayd-ws` — blind WebSocket relay.
//!
//! The same opaque, PoW-authenticated blob forwarding as `relayd`, but over
//! WebSocket frames instead of UDP datagrams. WebSocket traverses essentially
//! every NAT/firewall and Cloudflare's edge, so a `relayd-ws` endpoint (or the
//! Cloudflare Worker twin in `deploy/cloudflare-worker/`) is the relay path
//! when UDP is blocked.
//!
//!   RELAYD_WS_PORT=5902 RELAYD_WS_DIFFICULTY=20 cargo run -p relayd --bin relayd-ws

use std::sync::Arc;

use relayd::ws::{WsRelay, handle_connection, maintenance_loop};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port = std::env::var("RELAYD_WS_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(5902);
    let difficulty = std::env::var("RELAYD_WS_DIFFICULTY").ok().and_then(|v| v.parse().ok()).unwrap_or(20);
    let ttl_secs = std::env::var("RELAYD_WS_TTL").ok().and_then(|v| v.parse().ok()).unwrap_or(90);
    let bind = std::env::var("RELAYD_WS_BIND").unwrap_or_else(|_| "0.0.0.0".into());

    let listener = TcpListener::bind(format!("{bind}:{port}")).await?;
    println!("relayd-ws: listening on ws://{bind}:{port} (difficulty={difficulty}, ttl={ttl_secs}s)");
    let relay = Arc::new(Mutex::new(WsRelay::new(difficulty, ttl_secs)));

    tokio::spawn(maintenance_loop(relay.clone()));

    loop {
        let (stream, peer) = listener.accept().await?;
        let relay = relay.clone();
        tokio::spawn(async move {
            let Ok(ws) = tokio_tungstenite::accept_async(stream).await else { return };
            handle_connection(ws, peer, relay).await;
        });
    }
}