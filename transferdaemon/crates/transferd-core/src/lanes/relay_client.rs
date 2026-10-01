//! UDP relay client primitives: challenge fetch, PoW solving, registration,
//! keepalive, and raw forwarding. Shared by `RelayLane` and the daemon's
//! inbound relay handler.

use relayd::protocol::{
    ChallengeMsg, ForwardMsg, KeepaliveMsg, RegisterMsg, Tag, encode,
};
use relayd::ghost::ghost_register;
use relayd::pow::PowChallenge;
use transferd_crypto::ghostkey::{GhostCertificate, GhostKey};
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
    /// A ghost key credential (certificate + the ghost key's secret): registrations then carry it, for relays that
    /// admit only vouched-for identities (relayd::ghost).
    ghost: std::sync::Mutex<Option<(GhostCertificate, [u8; 32])>>,
}

/// A ghost key credential from the file `transferd-cli ghostkey finish` writes (a certificate line and a secret
/// line).
pub fn read_ghost_file(path: &std::path::Path) -> io::Result<(GhostCertificate, [u8; 32])> {
    let text = std::fs::read_to_string(path)?;
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {m}", path.display()));
    let cert_line = text.lines().find(|l| l.starts_with("transferd-ghostcert-v1:")).ok_or_else(|| bad("no certificate"))?;
    let cert = GhostCertificate::from_text(cert_line).map_err(|e| bad(&e.to_string()))?;
    let secret_hex = text.lines().find_map(|l| l.strip_prefix("transferd-ghostsecret-v1:")).ok_or_else(|| bad("no ghost key secret"))?;
    let bytes = hex::decode(secret_hex.trim()).map_err(|e| bad(&e.to_string()))?;
    let secret: [u8; 32] = bytes.try_into().map_err(|_| bad("a ghost key secret is 32 bytes"))?;
    if GhostKey::from_secret(secret).public() != cert.ghost_public {
        return Err(bad("the secret is not the certified ghost key"));
    }
    Ok((cert, secret))
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
            ghost: std::sync::Mutex::new(None),
        };
        if let Some(path) = std::env::var_os("TRANSFERD_GHOST_FILE") {
            client.set_ghost(Some(read_ghost_file(std::path::Path::new(&path))?));
        }
        let _ = client.fetch_challenge().await; // seed cache (best-effort)
        Ok(client)
    }

    /// Register with a ghost key certificate from now on (`None`: plain registrations).
    pub fn set_ghost(&self, credential: Option<(GhostCertificate, [u8; 32])>) {
        if let Ok(mut g) = self.ghost.lock() {
            *g = credential;
        }
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
        let ghost = self.ghost.lock().ok().and_then(|g| g.clone());
        let frame = match ghost {
            Some((cert, secret)) => encode(Tag::RegisterGhost, &ghost_register(msg, &cert, &GhostKey::from_secret(secret))),
            None => encode(Tag::Register, &msg),
        }
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
use crate::lanes::relay_ws_client::RelayForward;

#[async_trait::async_trait]
impl RelayForward for RelayClient {
    async fn relay_send_forward(&self, token: [u8; 32], payload: &[u8]) -> std::io::Result<()> {
        self.send_forward(token, payload).await
    }
}



#[cfg(test)]
mod ghost_tests {
    use super::*;
    use relayd::ghost::GhostPolicy;
    use relayd::protocol::{split, ErrorMsg, GhostRegisterMsg};
    use relayd::relay::Relay;
    use transferd_crypto::ghostkey::Issuer;

    /// A relay running relayd's own logic on a local UDP socket: the challenge, plain and ghost registrations.
    async fn relay_with(policy: GhostPolicy) -> (SocketAddr, Arc<Mutex<Relay>>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = sock.local_addr().expect("addr");
        let mut r = Relay::new(0, 60, 1024);
        r.set_ghost_policy(policy);
        let relay = Arc::new(Mutex::new(r));
        let state = relay.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            while let Ok((n, src)) = sock.recv_from(&mut buf).await {
                let Some((tag, body)) = split(&buf[..n]) else { continue };
                let mut r = state.lock().await;
                let outcome = match tag {
                    Tag::Challenge => Ok(()),
                    Tag::Register => bincode::deserialize::<RegisterMsg>(body).map_err(|e| e.to_string())
                        .and_then(|m| r.register(&m, src).map_err(|e| e.to_string())),
                    Tag::RegisterGhost => bincode::deserialize::<GhostRegisterMsg>(body).map_err(|e| e.to_string())
                        .and_then(|m| r.register_ghost(&m, src).map_err(|e| e.to_string())),
                    _ => continue,
                };
                let reply = match outcome {
                    Ok(()) => {
                        let c = r.current_challenge();
                        encode(Tag::Challenge, &ChallengeMsg { challenge: c.bytes, expires_at: c.expires_at, difficulty: c.difficulty })
                    }
                    Err(detail) => encode(Tag::Error, &ErrorMsg { code: relayd::protocol::ErrorCode::GhostRejected, seq: 0, detail }),
                }
                .expect("encode");
                let _ = sock.send_to(&reply, src).await;
            }
        });
        (addr, relay)
    }

    #[tokio::test]
    async fn registers_with_a_ghost_key_where_one_is_required() {
        let issuer = Issuer::generate("test relay", "member", 2048).expect("issuer");
        let me = GhostKey::generate();
        let (blinded, state) = me.blind_request(&issuer.public).expect("blind");
        let cert = me.finish(&issuer.public, state, &issuer.sign_blinded(&blinded).expect("sign")).expect("finish");
        let policy = GhostPolicy { issuers: vec![issuer.public.clone()], required: true, max_sessions_per_key: 8 };
        let (addr, relay) = relay_with(policy).await;

        let plain = RelayClient::bind(addr).await.expect("client");
        let refused = plain.register([7; 32]).await.expect_err("a plain registration is refused");
        assert!(refused.to_string().contains("ghost"), "{refused}");

        let vouched = RelayClient::bind(addr).await.expect("client");
        vouched.set_ghost(Some((cert.clone(), me.secret())));
        vouched.register([8; 32]).await.expect("a ghost registration is admitted");
        assert_eq!(relay.lock().await.active_count(), 1);

        // the credential file `transferd-cli ghostkey finish` writes
        let dir = std::env::temp_dir().join(format!("tdghost-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let f = dir.join("me.ghost");
        std::fs::write(&f, format!("{}
transferd-ghostsecret-v1:{}
", cert.to_text(), hex::encode(me.secret()))).expect("write");
        let (c2, s2) = read_ghost_file(&f).expect("read");
        assert_eq!(c2, cert);
        assert_eq!(s2, me.secret());
        std::fs::write(&f, format!("{}
transferd-ghostsecret-v1:{}
", cert.to_text(), hex::encode(GhostKey::generate().secret()))).expect("write");
        assert!(read_ghost_file(&f).is_err(), "a secret that isn't the certified key");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
