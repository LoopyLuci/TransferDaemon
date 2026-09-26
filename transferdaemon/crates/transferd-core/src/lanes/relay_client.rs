//! UDP relay client primitives: challenge fetch, PoW solving, registration,
//! keepalive, and raw forwarding. Shared by `RelayLane` and the daemon's
//! inbound relay handler.

use relayd::protocol::{
    ChallengeMsg, ForwardMsg, KeepaliveMsg, RegisterMsg, Tag, encode,
};
use relayd::pow::PowChallenge;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Marker prefix for handshake payloads carried through the relay.
pub const PREFIX_HANDSHAKE: u8 = 0x01;
/// Marker prefix for encrypted chunk payloads carried through the relay.
pub const PREFIX_CHUNK: u8 = 0x02;

/// A UDP socket that speaks the `relayd` protocol.
///
/// Owns a socket, caches the current PoW challenge, and solves/verifies PoW
/// for register/forward/keepalive so callers stay simple.
///
/// Read-model: the registered `socket` is used exclusively for **sending**
/// datagrams and (after the streaming reader starts) receiving relayed
/// messages. Challenge fetches use a throwaway socket so they never race the
/// streaming reader for replies.
pub struct RelayClient {
    socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    /// Cached challenge; refreshed on demand and by `keepalive_loop`.
    challenge: Mutex<Option<PowChallenge>>,
    /// Monotonic sequence for register/keepalive replay protection.
    reg_seq: AtomicU32,
}

impl RelayClient {
    /// Bind a UDP socket (ephemeral local port) and seed the PoW challenge cache.
    pub async fn bind(relay_addr: SocketAddr) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let client = Self {
            socket,
            relay_addr,
            challenge: Mutex::new(None),
            reg_seq: AtomicU32::new(0),
        };
        let _ = client.fetch_challenge().await; // seed cache (best-effort)
        Ok(client)
    }

    /// The underlying socket (for `recv_from` and cloning into background tasks).
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    pub fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    /// Request the current PoW challenge from the relay and return it.
    ///
    /// Uses a throwaway socket so it never competes with the streaming reader
    /// that owns `self.socket`.
    pub async fn fetch_challenge(&self) -> io::Result<PowChallenge> {
        let temp = UdpSocket::bind("0.0.0.0:0").await?;
        let req = encode(Tag::Challenge, &ChallengeMsg {
            challenge: [0u8; 16],
            expires_at: 0,
            difficulty: 0,
        })
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        temp.send_to(&req, self.relay_addr).await?;

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            temp.recv_from(&mut buf),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "challenge request timed out"))??;

        let Some((tag, body)) = relayd::protocol::split(&buf[..len]) else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad challenge frame"));
        };
        if tag != Tag::Challenge {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected Challenge, got tag {tag:?}"),
            ));
        }
        let msg: ChallengeMsg = bincode::deserialize(body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(PowChallenge {
            bytes: msg.challenge,
            expires_at: msg.expires_at,
            difficulty: msg.difficulty,
        })
    }

    /// Ensure the cached challenge is reasonably fresh, fetching if needed.
    pub async fn refresh_challenge(&self) -> io::Result<PowChallenge> {
        let now = now_secs();
        {
            let cached = self.challenge.lock().await;
            if let Some(c) = cached.as_ref() {
                if c.expires_at > now + 10 {
                    return Ok(c.clone());
                }
            }
        }
        let fresh = self.fetch_challenge().await?;
        *self.challenge.lock().await = Some(fresh.clone());
        Ok(fresh)
    }

    /// Register `token` with the relay (valid PoW for the current challenge).
    /// Returns the challenge seen in the reply (refreshes the cache).
    pub async fn register(&self, token: [u8; 32]) -> io::Result<PowChallenge> {
        let challenge = self.refresh_challenge().await?;
        let nonce = solve_pow(&challenge, &token);
        let msg = RegisterMsg {
            session_token: token,
            pow_nonce: nonce,
            seq: self.next_seq(),
        };
        let frame = encode(Tag::Register, &msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.socket.send_to(&frame, self.relay_addr).await?;

        // The relay replies with the current ChallengeMsg (or an ErrorMsg).
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.socket.recv_from(&mut buf),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "register timed out"))??;
        let frame = &buf[..len];
        let Some((tag, body)) = relayd::protocol::split(frame) else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad register reply"));
        };
        match tag {
            Tag::Challenge => {
                let msg: ChallengeMsg = bincode::deserialize(body)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                let c = PowChallenge {
                    bytes: msg.challenge,
                    expires_at: msg.expires_at,
                    difficulty: msg.difficulty,
                };
                *self.challenge.lock().await = Some(c.clone());
                Ok(c)
            }
            Tag::Error => {
                let msg: relayd::protocol::ErrorMsg = bincode::deserialize(body)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                Err(io::Error::new(io::ErrorKind::PermissionDenied, msg.detail))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected register reply",
            )),
        }
    }

    /// Send an opaque payload to the peer registered under `token`.
    pub async fn send_forward(&self, token: [u8; 32], payload: &[u8]) -> io::Result<()> {
        let challenge = self.refresh_challenge().await?;
        let nonce = solve_pow(&challenge, &token);
        let seq = (self.next_seq() & 0xFFFF) as u16;
        let msg = ForwardMsg {
            session_token: token,
            pow_nonce: nonce,
            sender_seq: seq,
            ciphertext: payload.to_vec(),
        };
        let frame = encode(Tag::Forward, &msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.socket.send_to(&frame, self.relay_addr).await?;
        Ok(())
    }

    /// Send a keepalive for `token` (refreshes the relay-side TTL).
    pub async fn send_keepalive(&self, token: [u8; 32]) -> io::Result<()> {
        let challenge = self.refresh_challenge().await?;
        let nonce = solve_pow(&challenge, &token);
        let msg = KeepaliveMsg {
            session_token: token,
            pow_nonce: nonce,
            seq: self.next_seq(),
        };
        let frame = encode(Tag::Keepalive, &msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.socket.send_to(&frame, self.relay_addr).await?;
        Ok(())
    }

    /// Spawn a background keepalive loop for `token` (every 45s, TTL is 90s).
    pub fn spawn_keepalive_loop(self: &Arc<Self>, token: [u8; 32]) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(45));
            ticker.tick().await; // first tick fires immediately; skip it
            loop {
                ticker.tick().await;
                if this.send_keepalive(token).await.is_err() {
                    // Transient UDP failure; retry next tick.
                }
            }
        });
    }

    fn next_seq(&self) -> u32 {
        self.reg_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    }
}

/// Solve hashcash PoW for `token` against `challenge` (iterative BLAKE3).
fn solve_pow(challenge: &PowChallenge, token: &[u8; 32]) -> u64 {
    if challenge.difficulty == 0 {
        return 0;
    }
    let mut nonce = 0u64;
    loop {
        if relayd::pow::leading_zeros(challenge.difficulty, &challenge.bytes, token, nonce) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}