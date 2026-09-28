//! `relayd-ws` — TransferDaemon Blind Relay Server over WebSocket.
//!
//! Same opaque, PoW-authenticated wire format as `relayd` (see
//! `relayd::protocol`), transported over WebSocket frames so it traverses
//! NATs/firewalls that block UDP. This is the self-hosted twin of the
//! Cloudflare Worker relay (which runs the identical protocol on the edge).
//!
//! Configuration (env): `RELAYD_WS_BIND` (default `0.0.0.0:8081`),
//! `RELAYD_DIFFICULTY`, `RELAYD_TTL`, `RELAYD_WS_MAX_BLOB_BYTES` /
//! `RELAYD_WS_MAX_MB_PER_DAY|WEEK|MONTH`.

use relayd::ws::{WsRelay, handle_connection, maintenance_loop};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let bind = std::env::var("RELAYD_WS_BIND").unwrap_or_else(|_| "0.0.0.0:8081".into());
    let difficulty = env_u32("RELAYD_DIFFICULTY", 4);
    let ttl_secs = env_u64("RELAYD_TTL", 90);
    let limits = relayd::limits::RelayLimits::from_env("RELAYD_WS_");
    let addr: std::net::SocketAddr = bind.parse().expect("configured bind address is valid");

    let relay = Arc::new(Mutex::new(WsRelay::with_limits(difficulty, ttl_secs, limits)));
    tokio::spawn(maintenance_loop(relay.clone()));

    let listener = TcpListener::bind(addr).await?;
    println!(
        "relayd-ws: listening on {addr} (difficulty={difficulty}, ttl={ttl_secs}s, \
         max_blob={} day={} week={} month={})",
        limits.max_blob_bytes.map(relayd::limits::format_bytes).unwrap_or_else(|| "unlimited".into()),
        limits.daily_bytes.map(relayd::limits::format_bytes).unwrap_or_else(|| "unlimited".into()),
        limits.weekly_bytes.map(relayd::limits::format_bytes).unwrap_or_else(|| "unlimited".into()),
        limits.monthly_bytes.map(relayd::limits::format_bytes).unwrap_or_else(|| "unlimited".into()),
    );

    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let relay = relay.clone();
        tokio::spawn(async move {
            let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                return;
            };
            handle_connection(ws, peer, relay).await;
        });
    }
}