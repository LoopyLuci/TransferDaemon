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
//! Configuration (env): `RELAYD_PORT`, `RELAYD_DIFFICULTY`, `RELAYD_TTL`.

use relayd::protocol::{
    AckMsg, ChallengeMsg, DeliveredMsg, ErrorMsg, ForwardMsg, KeepaliveMsg, RegisterMsg, Tag,
    encode, split, MAX_PAYLOAD,
};
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
    println!("relayd: listening on {addr} (difficulty={difficulty}, ttl={ttl_secs}s)");

    let relay = Arc::new(Mutex::new(Relay::new(difficulty, ttl_secs, MAX_PAYLOAD)));

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

    // Send the current PoW challenge to `src`.
    async fn send_challenge(relay: &Arc<Mutex<Relay>>, socket: &Arc<UdpSocket>, src: SocketAddr) {
        let (challenge, expires_at, difficulty) = {
            let mut r = relay.lock().await;
            let c = r.current_challenge();
            (c.bytes, c.expires_at, c.difficulty)
        };
        let frame = encode(Tag::Challenge, &ChallengeMsg { challenge, expires_at, difficulty })
            .unwrap_or_default();
        let _ = socket.send_to(&frame, src).await;
    }

    // Main dispatch loop.
    let mut buf = vec![0u8; MAX_PAYLOAD + 256];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(x) => x,
            // Windows surfaces ICMP errors (e.g. a client that already closed
            // its socket) as WSAECONNRESET on the next recv. Transient — never
            // kill the relay over a stale datagram.
            Err(e) => {
                eprintln!("relayd: recv_from: {e} (ignored)");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let frame = &buf[..len];

        let Some((tag, body)) = split(frame) else {
            continue; // malformed — silently drop
        };

        let socket = socket.clone();
        let relay = relay.clone();

        // Per-IP rate limiting: drop datagrams from addresses over their budget.
        if relay.lock().await.rate_limited(src.ip()) {
            continue;
        }

        match tag {
            Tag::Challenge => {
                // Bootstrap: any client may request the current PoW challenge.
                send_challenge(&relay, &socket, src).await;
            }

            Tag::Register => {
                if let Ok(msg) = bincode::deserialize::<RegisterMsg>(body) {
                    let seq = msg.seq;
                    let result = relay.lock().await.register(&msg, src);
                    match result {
                        Ok(()) => {
                            send_challenge(&relay, &socket, src).await;
                        }
                        Err(e) => {
                            let frame = encode(Tag::Error, &ErrorMsg {
                                code: e.code(),
                                seq,
                                detail: e.to_string(),
                            }).unwrap_or_default();
                            let _ = socket.send_to(&frame, src).await;
                        }
                    }
                }
            }

            Tag::Forward => {
                if let Ok(msg) = bincode::deserialize::<ForwardMsg>(body) {
                    let sender_seq = msg.sender_seq;
                    let ciphertext = msg.ciphertext.clone();
                    let result = relay.lock().await.forward(&msg);
                    match result {
                        Ok(dst) => {
                            // Blind forward: deliver ciphertext wrapped in DeliveredMsg (no src IP).
                            let delivered = encode(Tag::Ack, &DeliveredMsg {
                                sender_seq,
                                ciphertext,
                            }).unwrap_or_default();
                            let _ = socket.send_to(&delivered, dst).await;
                            // Ack to sender.
                            let ack = encode(Tag::Ack, &AckMsg { sender_seq }).unwrap_or_default();
                            let _ = socket.send_to(&ack, src).await;
                        }
                        Err(e) => {
                            let frame = encode(Tag::Error, &ErrorMsg {
                                code: e.code(),
                                seq: sender_seq as u32,
                                detail: e.to_string(),
                            }).unwrap_or_default();
                            let _ = socket.send_to(&frame, src).await;
                        }
                    }
                }
            }

            Tag::Keepalive => {
                if let Ok(msg) = bincode::deserialize::<KeepaliveMsg>(body) {
                    let _ = relay.lock().await.keepalive(&msg);
                }
            }

            Tag::Error | Tag::Ack => {
                // Relay never receives these; silently drop.
            }
        }
    }
}