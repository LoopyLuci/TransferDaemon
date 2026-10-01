//! The UDP relay's dispatch loop: challenge, register (plain or with a ghost key), forward, keepalive.
//! `relayd` (src/main.rs) runs it; tests and embedders run the same loop on their own socket.

use crate::protocol::{
    AckMsg, ChallengeMsg, DeliveredMsg, ErrorMsg, ForwardMsg, GhostRegisterMsg, KeepaliveMsg, RegisterMsg, Tag,
    encode, split, MAX_PAYLOAD,
};
use crate::relay::Relay;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::Duration;

/// Serve the relay protocol on `socket` until the process ends.
pub async fn serve(socket: Arc<UdpSocket>, relay: Arc<Mutex<Relay>>) {
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

            Tag::RegisterGhost => {
                if let Ok(msg) = bincode::deserialize::<GhostRegisterMsg>(body) {
                    let seq = msg.register.seq;
                    let result = relay.lock().await.register_ghost(&msg, src);
                    match result {
                        Ok(()) => send_challenge(&relay, &socket, src).await,
                        Err(e) => {
                            let frame = encode(Tag::Error, &ErrorMsg { code: e.code(), seq, detail: e.to_string() })
                                .unwrap_or_default();
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
