//! `relayd` — TransferDaemon Blind Relay Server.
//!
//! Listens on UDP (default port 7777) and routes encrypted payloads between peers
//! without ever seeing plaintext or linking sender to recipient.
//!
//! Startup sequence:
//!   1. Bind UDP socket.
//!   2. Enter the dispatch loop. Clients request the current PoW challenge with a
//!      `Challenge` datagram, solve it, and register/forward/keepalive.
//!
//! Configuration (env): `RELAYD_PORT`, `RELAYD_DIFFICULTY`, `RELAYD_TTL`; ghost key admission (relayd::ghost):
//! `RELAYD_GHOST_ISSUERS` (issuer files, separated like PATH), `RELAYD_REQUIRE_GHOST=1`, `RELAYD_GHOST_SESSIONS`;
//! `RELAYD_RATE_PER_30S` (datagrams per source address per 30 s, default 300).

use relayd::protocol::MAX_PAYLOAD;
use relayd::relay::Relay;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

fn env_u16(name: &str, default: u16) -> u16 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port = env_u16("RELAYD_PORT", 7777);
    let difficulty = env_u32("RELAYD_DIFFICULTY", 20);
    let ttl_secs = env_u64("RELAYD_TTL", 90);
    let addr: SocketAddr = format!("0.0.0.0:{port}").parse()
        .expect("configured address is valid");
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    let limits = relayd::limits::RelayLimits::from_env("RELAYD_");
    println!(
        "relayd: listening on {addr} (difficulty={difficulty}, ttl={ttl_secs}s, \
         max_blob={} day={} week={} month={})",
        limits.max_blob_bytes.map(relayd::limits::format_bytes).unwrap_or_else(|| "unlimited".into()),
        limits.daily_bytes.map(relayd::limits::format_bytes).unwrap_or_else(|| "unlimited".into()),
        limits.weekly_bytes.map(relayd::limits::format_bytes).unwrap_or_else(|| "unlimited".into()),
        limits.monthly_bytes.map(relayd::limits::format_bytes).unwrap_or_else(|| "unlimited".into()),
    );

    let mut core = Relay::with_limits(difficulty, ttl_secs, MAX_PAYLOAD, limits);
    // datagrams per source address per 30 s (the default 300 suits messages; raise it for streams such as `cat`)
    core.set_rate_limit(30, env_u32("RELAYD_RATE_PER_30S", 300));
    let issuers: Vec<String> = std::env::var_os("RELAYD_GHOST_ISSUERS")
        .map(|v| std::env::split_paths(&v).map(|p| p.display().to_string()).collect())
        .unwrap_or_default();
    let require_ghost = std::env::var("RELAYD_REQUIRE_GHOST").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    if !issuers.is_empty() || require_ghost {
        let policy = relayd::ghost::GhostPolicy::from_files(&issuers, require_ghost, env_u64("RELAYD_GHOST_SESSIONS", 8) as usize)
            .map_err(std::io::Error::other)?;
        println!("relayd: ghost keys from {} issuer(s) {}", policy.issuers.len(),
                 if policy.required { "required" } else { "accepted" });
        core.set_ghost_policy(policy);
    }
    let relay = Arc::new(Mutex::new(core));

    // Background task: prune expired entries.
    {
        let relay = relay.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                let pruned = relay.lock().await.prune_expired();
                if pruned > 0 {
                    let active = relay.lock().await.active_count();
                    println!("relayd: pruned {pruned} expired registrations; {active} active");
                }
            }
        });
    }

    // Background task: rotate PoW challenge periodically. Clients discover the
    // current challenge on demand via the `Challenge` request below.
    {
        let relay = relay.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
                relay.lock().await.rotate_challenge();
            }
        });
    }

    relayd::server::serve(socket, relay).await;
    Ok(())
}