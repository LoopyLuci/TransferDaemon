//! `transferd-cat`: netcat between two machines over TransferD (the capabilities of tailscale/tailcat).
//!
//! One side **listens** and prints a one-time *cat address*; the other **dials** it. Whatever either side writes comes
//! out on the other side, both ways at once, until both have closed their input.
//!
//! ```text
//! tdcat:<relay host:port | ->/<rendezvous token hex>/<address secret hex>/<direct endpoint>,<direct endpoint>...
//! ```
//!
//! * **Security.** TransferD's hybrid handshake (X25519 + ML-KEM-768, `transferd_crypto::handshake`) gives a fresh
//!   session key; it is then keyed with the address's 32-byte secret, so only someone holding the address can
//!   complete it, and a relay or anyone on the path can neither read nor impersonate either side. Each direction has
//!   its own AES-256-GCM key; nonces are sequence numbers, never reused. The address is the capability: share it the
//!   way you'd share a password, once.
//! * **Paths.** The dialer tries the listener's direct UDP endpoints and the relay at the same time and keeps the
//!   first path that answers (direct when the listener is reachable: same LAN, a public address, a forwarded port);
//!   the blind relay (`relayd`) is the path of last resort. Through a relay the data is opaque datagrams.
//! * **Reliability.** UDP either way: frames carry sequence numbers, the receiver acknowledges cumulatively, the
//!   sender keeps a window and retransmits what isn't acknowledged, and an end frame closes each direction.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use relayd::pow::PowChallenge;
use relayd::protocol::{
    encode, split, ChallengeMsg, DeliveredMsg, ForwardMsg, KeepaliveMsg, RegisterMsg, Tag,
};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use transferd_crypto::handshake::{Initiator, InitiatorHello, Responder, ResponderHello};

const MAGIC: u8 = 0xC7;
const K_HELLO: u8 = 1;
const K_HELLO_ACK: u8 = 2;
const K_DATA: u8 = 3;
const K_ACK: u8 = 4;
const K_END: u8 = 5;
const WINDOW: usize = 64;
const CHUNK_DIRECT: usize = 16 * 1024;
const CHUNK_RELAY: usize = 32 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CatError {
    #[error("not a cat address: {0}")]
    BadAddress(String),
    #[error("network: {0}")]
    Io(#[from] std::io::Error),
    #[error("relay: {0}")]
    Relay(String),
    #[error("no answer from the other side within {0:?} (is it still listening? is the address right?)")]
    Timeout(Duration),
    #[error("the other side's answer did not check out (a different address?)")]
    Auth,
}

/// A parsed cat address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatAddress {
    pub relay: Option<SocketAddr>,
    pub token: [u8; 32],
    pub secret: [u8; 32],
    pub direct: Vec<SocketAddr>,
}

impl CatAddress {
    pub fn to_text(&self) -> String {
        let relay = self.relay.map(|r| r.to_string()).unwrap_or_else(|| "-".into());
        let direct: Vec<String> = self.direct.iter().map(|a| a.to_string()).collect();
        format!("tdcat:{relay}/{}/{}/{}", hex::encode(self.token), hex::encode(self.secret), direct.join(","))
    }

    pub fn parse(s: &str) -> Result<Self, CatError> {
        let body = s.trim().strip_prefix("tdcat:").ok_or_else(|| CatError::BadAddress("it starts with tdcat:".into()))?;
        let parts: Vec<&str> = body.splitn(4, '/').collect();
        if parts.len() < 3 {
            return Err(CatError::BadAddress("tdcat:<relay>/<token>/<secret>/<endpoints>".into()));
        }
        let relay = if parts[0] == "-" || parts[0].is_empty() {
            None
        } else {
            Some(parts[0].parse().map_err(|_| CatError::BadAddress(format!("relay {:?}", parts[0])))?)
        };
        let h32 = |x: &str, what: &str| -> Result<[u8; 32], CatError> {
            hex::decode(x).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| CatError::BadAddress(format!("{what} is 64 hex digits")))
        };
        let direct = parts.get(3).map(|d| d.split(',').filter(|x| !x.is_empty()).filter_map(|x| x.parse().ok()).collect()).unwrap_or_default();
        Ok(Self { relay, token: h32(parts[1], "the token")?, secret: h32(parts[2], "the secret")?, direct })
    }
}

/// Where frames to the peer go.
#[derive(Clone, Debug)]
enum Path {
    Direct(SocketAddr),
    Relay(SocketAddr, [u8; 32]),
}

/// The PoW nonce solved for (challenge bytes, destination token).
type PowCache = ([u8; 16], [u8; 32], u64);

/// One UDP socket used for the direct path and for talking to the relay.
struct Link {
    sock: Arc<UdpSocket>,
    relay: Option<SocketAddr>,
    challenge: Mutex<Option<PowChallenge>>,
    pow: Mutex<Option<PowCache>>,
    seq: std::sync::atomic::AtomicU32,
}

impl Link {
    async fn send_raw(&self, path: &Path, frame: &[u8]) -> Result<(), CatError> {
        match path {
            Path::Direct(a) => {
                self.sock.send_to(frame, a).await?;
            }
            Path::Relay(relay, token) => {
                let nonce = self.pow_for(token).await?;
                let seq = (self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) & 0xFFFF) as u16;
                let msg = ForwardMsg { session_token: *token, pow_nonce: nonce, sender_seq: seq, ciphertext: frame.to_vec() };
                let f = encode(Tag::Forward, &msg).map_err(|e| CatError::Relay(e.to_string()))?;
                self.sock.send_to(&f, relay).await?;
            }
        }
        Ok(())
    }

    /// The PoW nonce for sending to `token` under the current challenge (solved once per challenge and token).
    async fn pow_for(&self, token: &[u8; 32]) -> Result<u64, CatError> {
        let ch = self.challenge.lock().await.clone().ok_or_else(|| CatError::Relay("no challenge from the relay yet".into()))?;
        let mut cache = self.pow.lock().await;
        if let Some((c, t, n)) = *cache {
            if c == ch.bytes && t == *token {
                return Ok(n);
            }
        }
        let n = solve(&ch, token);
        *cache = Some((ch.bytes, *token, n));
        Ok(n)
    }

    async fn ask_challenge(&self) -> Result<(), CatError> {
        if let Some(r) = self.relay {
            let f = encode(Tag::Challenge, &ChallengeMsg { challenge: [0; 16], expires_at: 0, difficulty: 0 })
                .map_err(|e| CatError::Relay(e.to_string()))?;
            self.sock.send_to(&f, r).await?;
        }
        Ok(())
    }

    async fn register(&self, token: [u8; 32], keepalive: bool) -> Result<(), CatError> {
        let Some(r) = self.relay else { return Ok(()) };
        let ch = self.challenge.lock().await.clone().ok_or_else(|| CatError::Relay("no challenge from the relay yet".into()))?;
        let nonce = solve(&ch, &token);
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let f = if keepalive {
            encode(Tag::Keepalive, &KeepaliveMsg { session_token: token, pow_nonce: nonce, seq })
        } else {
            encode(Tag::Register, &RegisterMsg { session_token: token, pow_nonce: nonce, seq })
        }
        .map_err(|e| CatError::Relay(e.to_string()))?;
        self.sock.send_to(&f, r).await?;
        Ok(())
    }
}

fn solve(ch: &PowChallenge, token: &[u8; 32]) -> u64 {
    let mut nonce = 0u64;
    while !relayd::pow::leading_zeros(ch.difficulty, &ch.bytes, token, nonce) {
        nonce += 1;
    }
    nonce
}

/// Our frames: MAGIC, kind, body.
fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(2 + body.len());
    f.push(MAGIC);
    f.push(kind);
    f.extend_from_slice(body);
    f
}

/// What arrived on the socket, already unwrapped from the relay's envelope.
enum Incoming {
    Ours { kind: u8, body: Vec<u8>, from: Path },
    Challenge(PowChallenge),
    RelayError(String),
}

fn classify(link: &Link, data: &[u8], src: SocketAddr, reply_token: Option<[u8; 32]>) -> Option<Incoming> {
    if Some(src) == link.relay {
        let (tag, body) = split(data)?;
        return match tag {
            Tag::Challenge => {
                let m: ChallengeMsg = bincode::deserialize(body).ok()?;
                Some(Incoming::Challenge(PowChallenge { bytes: m.challenge, expires_at: m.expires_at, difficulty: m.difficulty }))
            }
            Tag::Ack if body.len() > 2 => {
                let d: DeliveredMsg = bincode::deserialize(body).ok()?;
                let inner = d.ciphertext;
                if inner.len() >= 2 && inner[0] == MAGIC {
                    // a frame through the relay: answer through the relay, to the token the peer told us
                    let from = Path::Relay(src, reply_token.unwrap_or([0; 32]));
                    Some(Incoming::Ours { kind: inner[1], body: inner[2..].to_vec(), from })
                } else {
                    None
                }
            }
            Tag::Error => {
                let e: relayd::protocol::ErrorMsg = bincode::deserialize(body).ok()?;
                Some(Incoming::RelayError(e.detail))
            }
            _ => None,
        };
    }
    if data.len() >= 2 && data[0] == MAGIC {
        return Some(Incoming::Ours { kind: data[1], body: data[2..].to_vec(), from: Path::Direct(src) });
    }
    None
}

// ---- keys ------------------------------------------------------------------------------------------------------------- //

struct Keys {
    send: Aes256Gcm,
    recv: Aes256Gcm,
    auth: [u8; 32],
}

fn derive(session: &[u8; 32], secret: &[u8; 32], dialer: bool) -> Keys {
    let k = blake3::keyed_hash(secret, session);
    let d2l = blake3::derive_key("transferd-cat-v1 dialer to listener", k.as_bytes());
    let l2d = blake3::derive_key("transferd-cat-v1 listener to dialer", k.as_bytes());
    let auth = blake3::derive_key("transferd-cat-v1 handshake confirmation", k.as_bytes());
    let (s, r) = if dialer { (d2l, l2d) } else { (l2d, d2l) };
    Keys { send: Aes256Gcm::new(&s.into()), recv: Aes256Gcm::new(&r.into()), auth }
}

fn nonce(seq: u64, kind: u8) -> Nonce<aes_gcm::aead::consts::U12> {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&seq.to_le_bytes());
    n[8] = kind;
    n.into()
}

// ---- the session ------------------------------------------------------------------------------------------------------ //

/// A connected pipe between the two sides.
pub struct Session {
    link: Arc<Link>,
    path: Path,
    keys: Keys,
    rx: mpsc::Receiver<Incoming>,
    pub direct: bool,
    my_token: Option<[u8; 32]>,
}

/// What a listener has before anyone dials: its address and the means to accept.
pub struct Listener {
    pub address: CatAddress,
    link: Arc<Link>,
    rx: mpsc::Receiver<Incoming>,
}

async fn open_link(relay: Option<SocketAddr>, reply_token: Option<[u8; 32]>) -> Result<(Arc<Link>, mpsc::Receiver<Incoming>), CatError> {
    let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let link = Arc::new(Link {
        sock: sock.clone(),
        relay,
        challenge: Mutex::new(None),
        pow: Mutex::new(None),
        seq: std::sync::atomic::AtomicU32::new(1),
    });
    let (tx, rx) = mpsc::channel(1024);
    let l2 = link.clone();
    let token = Arc::new(Mutex::new(reply_token));
    tokio::spawn(async move {
        let mut buf = vec![0u8; 70 * 1024];
        loop {
            let Ok((n, src)) = l2.sock.recv_from(&mut buf).await else { continue };
            let rt = *token.lock().await;
            if let Some(inc) = classify(&l2, &buf[..n], src, rt) {
                if let Incoming::Challenge(c) = &inc {
                    *l2.challenge.lock().await = Some(c.clone());
                }
                if tx.send(inc).await.is_err() {
                    break;
                }
            }
        }
    });
    Ok((link, rx))
}

/// Wait for the relay's first challenge (it comes back to a Challenge request).
async fn get_challenge(link: &Link, rx: &mut mpsc::Receiver<Incoming>, early: &mut Vec<Incoming>) -> Result<(), CatError> {
    if link.relay.is_none() {
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    link.ask_challenge().await?;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(Incoming::Challenge(_))) => return Ok(()),
            Ok(Some(other)) => early.push(other),
            Ok(None) => break,
            Err(_) => link.ask_challenge().await?,
        }
    }
    Err(CatError::Relay("the relay did not answer".into()))
}

fn local_endpoints(port: u16) -> Vec<SocketAddr> {
    // the address we'd use to reach the internet, and loopback (same machine)
    let mut out = Vec::new();
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:53").is_ok() {
            if let Ok(a) = s.local_addr() {
                out.push(SocketAddr::new(a.ip(), port));
            }
        }
    }
    out.push(SocketAddr::from(([127, 0, 0, 1], port)));
    out
}

impl Listener {
    /// Start listening: a fresh token and secret, registered at the relay if there is one.
    pub async fn bind(relay: Option<SocketAddr>) -> Result<Self, CatError> {
        let mut token = [0u8; 32];
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token);
        rand::thread_rng().fill_bytes(&mut secret);
        let (link, mut rx) = open_link(relay, None).await?;
        let mut early = Vec::new();
        get_challenge(&link, &mut rx, &mut early).await?;
        link.register(token, false).await?;
        let port = link.sock.local_addr()?.port();
        let address = CatAddress { relay, token, secret, direct: local_endpoints(port) };
        let l2 = link.clone();
        if relay.is_some() {
            // keep the registration alive and the challenge fresh while we wait and while the session runs
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(25)).await;
                    if l2.ask_challenge().await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let _ = l2.register(token, true).await;
                }
            });
        }
        Ok(Self { address, link, rx })
    }

    /// Wait for the dialer's hello; answer it; the session.
    pub async fn accept(mut self, wait: Duration) -> Result<Session, CatError> {
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let inc = tokio::time::timeout(left, self.rx.recv()).await.map_err(|_| CatError::Timeout(wait))?;
            let Some(Incoming::Ours { kind: K_HELLO, body, from }) = inc else { continue };
            // HELLO: [dialer token 32][initiator hello]
            if body.len() < 32 {
                continue;
            }
            let mut dialer_token = [0u8; 32];
            dialer_token.copy_from_slice(&body[..32]);
            let Some(hello) = InitiatorHello::from_wire(&body[32..]) else { continue };
            let (resp, key) = Responder::new().respond(&hello);
            let keys = derive(key.as_bytes(), &self.address.secret, false);
            let path = match from {
                Path::Direct(a) => Path::Direct(a),
                Path::Relay(r, _) => Path::Relay(r, dialer_token),
            };
            let mut ack = resp.to_wire();
            ack.extend_from_slice(blake3::keyed_hash(&keys.auth, b"listener").as_bytes());
            self.link.send_raw(&path, &frame(K_HELLO_ACK, &ack)).await?;
            let direct = matches!(path, Path::Direct(_));
            return Ok(Session { link: self.link, path, keys, rx: self.rx, direct, my_token: None });
        }
    }
}

/// Dial a cat address.
pub async fn dial(address: &CatAddress, wait: Duration) -> Result<Session, CatError> {
    let mut my_token = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut my_token);
    let (link, mut rx) = open_link(address.relay, Some(my_token)).await?;
    let mut early = Vec::new();
    if address.relay.is_some() {
        get_challenge(&link, &mut rx, &mut early).await?;
        link.register(my_token, false).await?;
    }
    let init = Initiator::new();
    let mut hello = my_token.to_vec();
    hello.extend_from_slice(&init.hello().to_wire());
    let f = frame(K_HELLO, &hello);
    let mut paths: Vec<Path> = address.direct.iter().map(|a| Path::Direct(*a)).collect();
    if let Some(r) = address.relay {
        paths.push(Path::Relay(r, address.token));
    }
    let deadline = Instant::now() + wait;
    let mut next_send = Instant::now();
    let mut init = Some(init);
    loop {
        if Instant::now() >= next_send {
            for p in &paths {
                let _ = link.send_raw(p, &f).await;
            }
            next_send = Instant::now() + Duration::from_millis(700);
        }
        let left = deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(200));
        if deadline <= Instant::now() {
            return Err(CatError::Timeout(wait));
        }
        let inc = match tokio::time::timeout(left, rx.recv()).await {
            Ok(Some(i)) => i,
            Ok(None) => return Err(CatError::Relay("the socket closed".into())),
            Err(_) => continue,
        };
        match inc {
            Incoming::Ours { kind: K_HELLO_ACK, body, from } => {
                if body.len() != 32 + 1088 + 32 {
                    continue;
                }
                let Some(resp) = ResponderHello::from_wire(&body[..1120]) else { continue };
                let Some(i) = init.take() else { continue };
                let key = i.finalize(resp);
                let keys = derive(key.as_bytes(), &address.secret, true);
                if blake3::keyed_hash(&keys.auth, b"listener").as_bytes()[..] != body[1120..] {
                    return Err(CatError::Auth);
                }
                let path = match from {
                    Path::Direct(a) => Path::Direct(a),
                    Path::Relay(r, _) => Path::Relay(r, address.token),
                };
                let direct = matches!(path, Path::Direct(_));
                return Ok(Session { link, path, keys, rx, direct, my_token: Some(my_token) });
            }
            Incoming::RelayError(e) => return Err(CatError::Relay(e)),
            _ => continue,
        }
    }
}

impl Session {
    /// Pipe `input` to the other side and the other side to `output`, until both directions have ended.
    /// Returns (bytes sent, bytes received).
    pub async fn pipe<R, W>(mut self, mut input: R, mut output: W) -> Result<(u64, u64), CatError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin,
    {
        let chunk = if self.direct { CHUNK_DIRECT } else { CHUNK_RELAY };
        let rto = if self.direct { Duration::from_millis(250) } else { Duration::from_millis(1200) };
        if let (Some(tok), true) = (self.my_token, !self.direct) {
            // the dialer keeps its relay registration alive for the replies
            let l2 = self.link.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(25)).await;
                    if l2.ask_challenge().await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let _ = l2.register(tok, true).await;
                }
            });
        }
        // reading input happens on its own task so a slow pipe never stalls the protocol
        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(WINDOW);
        tokio::spawn(async move {
            let mut buf = vec![0u8; chunk];
            loop {
                match input.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if in_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let mut next_seq: u64 = 0;
        let mut unacked: VecDeque<(u64, Vec<u8>, Instant)> = VecDeque::new();
        let mut input_done = false;
        let mut end_sent: Option<(u64, Instant)> = None;
        let mut end_acked = false;
        let mut recv_next: u64 = 0;
        let mut pending: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut peer_end: Option<u64> = None;
        let (mut sent, mut received) = (0u64, 0u64);
        let mut last_heard = Instant::now();
        loop {
            // send new data while the window has room
            while !input_done && unacked.len() < WINDOW {
                match in_rx.try_recv() {
                    Ok(data) => {
                        let seq = next_seq;
                        next_seq += 1;
                        let ct = self.keys.send.encrypt(&nonce(seq, K_DATA), data.as_slice()).map_err(|_| CatError::Auth)?;
                        let mut body = seq.to_le_bytes().to_vec();
                        body.extend_from_slice(&ct);
                        let f = frame(K_DATA, &body);
                        self.link.send_raw(&self.path, &f).await?;
                        sent += data.len() as u64;
                        unacked.push_back((seq, f, Instant::now()));
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        input_done = true;
                    }
                }
            }
            if input_done && unacked.is_empty() && end_sent.is_none() {
                self.send_end(next_seq).await?;
                end_sent = Some((next_seq, Instant::now()));
            }
            // retransmit what has waited too long
            for (_, f, at) in unacked.iter_mut() {
                if at.elapsed() >= rto {
                    self.link.send_raw(&self.path, f).await?;
                    *at = Instant::now();
                }
            }
            if let Some((n, at)) = end_sent {
                if !end_acked && at.elapsed() >= rto {
                    self.send_end(n).await?;
                    end_sent = Some((n, Instant::now()));
                }
            }
            if end_acked && peer_end.is_some_and(|e| recv_next >= e) {
                // linger briefly so the peer's last ack-of-end retransmits are answered
                let linger = Instant::now() + rto * 2;
                while Instant::now() < linger {
                    if let Ok(Some(Incoming::Ours { kind: K_END, .. })) = tokio::time::timeout(rto, self.rx.recv()).await {
                        self.send_ack(recv_next, true).await?;
                    }
                }
                output.flush().await?;
                return Ok((sent, received));
            }
            if last_heard.elapsed() > Duration::from_secs(60) {
                return Err(CatError::Timeout(Duration::from_secs(60)));
            }
            // wait for something to arrive (or the next retransmit / new input)
            let wait = if !input_done && unacked.len() < WINDOW { Duration::from_millis(5) } else { Duration::from_millis(50) };
            let inc = match tokio::time::timeout(wait, self.rx.recv()).await {
                Ok(Some(i)) => i,
                Ok(None) => return Err(CatError::Relay("the socket closed".into())),
                Err(_) => continue,
            };
            let Incoming::Ours { kind, body, .. } = inc else {
                if let Incoming::RelayError(e) = inc {
                    return Err(CatError::Relay(e));
                }
                continue;
            };
            last_heard = Instant::now();
            match kind {
                K_DATA if body.len() >= 8 => {
                    let mut s = [0u8; 8];
                    s.copy_from_slice(&body[..8]);
                    let seq = u64::from_le_bytes(s);
                    if seq >= recv_next && seq < recv_next + 4 * WINDOW as u64 && !pending.contains_key(&seq) {
                        if let Ok(pt) = self.keys.recv.decrypt(&nonce(seq, K_DATA), &body[8..]) {
                            pending.insert(seq, pt);
                        }
                    }
                    while let Some(pt) = pending.remove(&recv_next) {
                        output.write_all(&pt).await?;
                        received += pt.len() as u64;
                        recv_next += 1;
                    }
                    self.send_ack(recv_next, false).await?;
                }
                K_ACK if body.len() >= 9 => {
                    let mut s = [0u8; 8];
                    s.copy_from_slice(&body[..8]);
                    let upto = u64::from_le_bytes(s);
                    // an ack's GCM tag (an empty payload) covers its number and end flag: only the peer can make one
                    if self.keys.recv.decrypt(&nonce(upto | ((body[8] as u64) << 63), K_ACK), &body[9..]).is_err() {
                        continue;
                    }
                    while unacked.front().is_some_and(|(s, _, _)| *s < upto) {
                        unacked.pop_front();
                    }
                    if body[8] == 1 {
                        end_acked = true;
                    }
                }
                K_END if body.len() >= 8 => {
                    let mut s = [0u8; 8];
                    s.copy_from_slice(&body[..8]);
                    let n = u64::from_le_bytes(s);
                    if self.keys.recv.decrypt(&nonce(n, K_END), &body[8..]).is_ok() {
                        peer_end = Some(n);
                    }
                    let complete = peer_end.is_some_and(|e| recv_next >= e);
                    self.send_ack(recv_next, complete).await?;
                }
                _ => {}
            }
        }
    }

    async fn send_end(&self, n: u64) -> Result<(), CatError> {
        let tag = self.keys.send.encrypt(&nonce(n, K_END), &[][..]).map_err(|_| CatError::Auth)?;
        let mut body = n.to_le_bytes().to_vec();
        body.extend_from_slice(&tag);
        self.link.send_raw(&self.path, &frame(K_END, &body)).await
    }

    /// A cumulative ack: everything below `upto` arrived; `end` when their end frame was seen and all data with it.
    async fn send_ack(&self, upto: u64, end: bool) -> Result<(), CatError> {
        let tag = self.keys.send.encrypt(&nonce(upto | ((end as u64) << 63), K_ACK), &[][..]).map_err(|_| CatError::Auth)?;
        let mut body = upto.to_le_bytes().to_vec();
        body.push(end as u8);
        body.extend_from_slice(&tag);
        self.link.send_raw(&self.path, &frame(K_ACK, &body)).await
    }
}
