//! `relayd` — TransferDaemon Blind Relay Server.
//!
//! Listens on UDP (default port 7777) and routes encrypted payloads between peers
//! without ever seeing plaintext or linking sender to recipient.
//!
//! Startup sequence:
//!   1. Bind UDP socket.
//!   2. Broadcast initial PoW challenge.
//!   3. Enter the dispatch loop (register / forward / keepalive / prune).

mod pow;
mod protocol;
mod relay;

use protocol::{
    AckMsg, ChallengeMsg, DeliveredMsg, ErrorMsg, ForwardMsg, KeepaliveMsg, RegisterMsg, Tag,
    encode, split,
};
use relay::Relay;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

/// UDP port the relay listens on.
const DEFAULT_PORT: u16 = 7777;
/// PoW difficulty (leading zero bits). Raise under load.
const DIFFICULTY: u32 = 20;
/// Registration TTL in seconds.
const TTL_SECS: u64 = 90;
/// Maximum forwarded ciphertext size.
const MAX_PAYLOAD: usize = 63 * 1024;
/// How often the pruner runs (seconds).
const PRUNE_INTERVAL_SECS: u64 = 30;
/// How often the challenge rotates (seconds).
const CHALLENGE_INTERVAL_SECS: u64 = 60;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{DEFAULT_PORT}").parse().unwrap();
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    println!("relayd: listening on {addr}");

    let relay = Arc::new(Mutex::new(Relay::new(DIFFICULTY, TTL_SECS, MAX_PAYLOAD)));

    // Background task: prune expired entries.
    {
        let relay = relay.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(PRUNE_INTERVAL_SECS));
            loop {
                ticker.tick().await;
                let pruned = relay.lock().await.prune_expired();
                if pruned > 0 {
                    println!("relayd: pruned {pruned} expired registrations");
                }
            }
        });
    }

    // Background task: rotate PoW challenge and broadcast to all registered peers.
    // (In production: maintain a subscriber list; here we just rotate silently.)
    {
        let relay = relay.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(CHALLENGE_INTERVAL_SECS));
            loop {
                ticker.tick().await;
                relay.lock().await.rotate_challenge();
            }
        });
    }

    // Main dispatch loop.
    let mut buf = vec![0u8; MAX_PAYLOAD + 256];
    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let frame = &buf[..len];

        let Some((tag, body)) = split(frame) else {
            continue; // malformed — silently drop
        };

        let socket = socket.clone();
        let relay  = relay.clone();

        match tag {
            Tag::Register => {
                if let Ok(msg) = bincode::deserialize::<RegisterMsg>(body) {
                    let seq = msg.seq;
                    let result = relay.lock().await.register(&msg, src);
                    match result {
                        Ok(()) => {
                            // Send back the current challenge so the client can prepare the next PoW.
                            let challenge_frame = {
                                let mut r = relay.lock().await;
                                let c = r.current_challenge();
                                encode(Tag::Challenge, &ChallengeMsg {
                                    challenge: c.bytes,
                                    expires_at: c.expires_at,
                                    difficulty: c.difficulty,
                                }).unwrap_or_default()
                            };
                            let _ = socket.send_to(&challenge_frame, src).await;
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

            Tag::Challenge | Tag::Error | Tag::Ack => {
                // Relay never receives these; silently drop.
            }
        }
    }
}
