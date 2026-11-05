//! Mesh DNS: this machine's names answered by a paired node's resolver, over the overlay.
//!
//! A node shares its resolver like any other service: `overlay.expose` with the service name
//! [`SERVICE`] (`dns`) and the resolver's address (a filtering resolver, a validating one, any
//! DNS server that speaks TCP). Another node points its mesh DNS at it with `overlay.dns_set`:
//!
//! ```text
//! app ── UDP/TCP ──► 127.0.0.1:53053 (this module) ══ overlay stream ══► peer's resolver
//! ```
//!
//! * **Upstreams** are node ids or service groups, tried in order. One that fails is set aside
//!   for [`HOLD_DOWN`] and the next is asked, so a peer going away costs one timeout, not every
//!   query; when all of them fail the client gets SERVFAIL rather than silence.
//! * **One connection per upstream**, DNS over TCP (RFC 7766) with queries pipelined on it and
//!   matched by id. The ids are rewritten on the way out, so two clients that picked the same id
//!   never see each other's answers.
//! * **UDP clients** get a truncated answer (TC set) when the response does not fit what they
//!   can take, and ask again over TCP, as RFC 1035 has it.
//! * **Counters** per upstream: queries, answers, NXDOMAIN, SERVFAIL, timeouts, errors, the
//!   average round trip, and *blocked* — answers whose addresses are all `0.0.0.0` or `::`, the
//!   way filtering resolvers answer a name they block. `overlay.dns_status` reports them.
//!
//! Nothing here knows what the upstream resolver is: the overlay carries DNS, the resolver at
//! the other end decides the answers.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::error::{OverlayError, Result};
use crate::node::OverlayNode;

/// The service name a node shares its resolver under.
pub const SERVICE: &str = "dns";
/// Where the forwarder listens unless told otherwise. Not 53 (that needs privileges and is
/// usually taken) and not 5353 (mDNS).
pub const DEFAULT_LISTEN: &str = "127.0.0.1:53053";
/// How long one upstream may take to answer one query.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(4);
/// How long an upstream that failed is skipped before it is tried again.
pub const HOLD_DOWN: Duration = Duration::from_secs(30);
/// The largest DNS message over TCP.
const MAX_MESSAGE: usize = 65_535;
/// What a UDP client without EDNS can take (RFC 1035 §4.2.1).
const PLAIN_UDP: usize = 512;
/// What a UDP client with EDNS gets at most: the DNS Flag Day 2020 size, never more.
const EDNS_UDP: usize = 1232;

const RCODE_NXDOMAIN: u8 = 3;
const RCODE_SERVFAIL: u8 = 2;

/// The forwarder's settings, as stored and as `overlay.dns_set` takes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshDnsConfig {
    /// Node ids or group names, tried in order.
    pub upstreams: Vec<String>,
    /// The local address to answer on (UDP and TCP).
    #[serde(default = "default_listen")]
    pub listen: String,
    /// The service name the upstreams share their resolver under.
    #[serde(default = "default_service")]
    pub service: String,
    /// How long one upstream may take, in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
}
fn default_service() -> String {
    SERVICE.to_string()
}
fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT.as_millis() as u64
}

impl MeshDnsConfig {
    /// Settings with the defaults and these upstreams.
    pub fn new(upstreams: Vec<String>) -> Self {
        Self {
            upstreams,
            listen: default_listen(),
            service: default_service(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

/// What one upstream has done since the forwarder started.
#[derive(Debug, Default, Clone, Serialize)]
pub struct UpstreamStats {
    pub queries: u64,
    pub answered: u64,
    pub nxdomain: u64,
    pub servfail: u64,
    /// Answers whose addresses were all `0.0.0.0` / `::`: a filtering resolver's "blocked".
    pub blocked: u64,
    pub timeouts: u64,
    pub errors: u64,
    /// Exponential average of the round trip, in milliseconds.
    pub avg_ms: f64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_error: String,
}

/// One upstream: its connection, its counters, and whether it is being skipped.
struct Upstream {
    target: String,
    conn: tokio::sync::Mutex<Option<Arc<Conn>>>,
    stats: Mutex<UpstreamStats>,
    down_until: Mutex<Option<Instant>>,
}

/// A pipelined DNS-over-TCP connection to an upstream's overlay endpoint.
struct Conn {
    writer: tokio::sync::Mutex<OwnedWriteHalf>,
    pending: Arc<Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>>,
    next_id: AtomicU16,
    alive: Arc<AtomicBool>,
    reader: JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// The running forwarder.
pub struct MeshDns {
    config: MeshDnsConfig,
    node: Arc<OverlayNode>,
    upstreams: Vec<Arc<Upstream>>,
    timeout: Duration,
    listen: SocketAddr,
    failed: Mutex<u64>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for MeshDns {
    fn drop(&mut self) {
        for task in self.tasks.lock().drain(..) {
            task.abort();
        }
    }
}

impl MeshDns {
    /// Bind the listeners and start answering.
    pub async fn start(node: Arc<OverlayNode>, config: MeshDnsConfig) -> Result<Arc<Self>> {
        if config.upstreams.is_empty() {
            return Err(OverlayError::protocol(
                "mesh DNS needs at least one upstream (a node id or a group)",
            ));
        }
        let wanted: SocketAddr = config
            .listen
            .parse()
            .map_err(|_| OverlayError::protocol(format!("{} is not host:port", config.listen)))?;
        let (udp, tcp, listen) = bind_both(wanted).await?;
        let dns = Arc::new(Self {
            upstreams: config
                .upstreams
                .iter()
                .map(|t| {
                    Arc::new(Upstream {
                        target: t.clone(),
                        conn: tokio::sync::Mutex::new(None),
                        stats: Mutex::new(UpstreamStats::default()),
                        down_until: Mutex::new(None),
                    })
                })
                .collect(),
            timeout: Duration::from_millis(config.timeout_ms.clamp(200, 30_000)),
            config,
            node,
            listen,
            failed: Mutex::new(0),
            tasks: Mutex::new(Vec::new()),
        });
        let udp = Arc::new(udp);
        let weak = Arc::downgrade(&dns);
        let serve_udp = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_MESSAGE];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                let Some(dns) = weak.upgrade() else { break };
                let query = buf[..n].to_vec();
                let socket = udp.clone();
                tokio::spawn(async move {
                    if let Some(answer) = dns.answer(&query).await {
                        let _ = socket.send_to(&fit_for_udp(&query, answer), from).await;
                    }
                });
            }
        });
        let weak = Arc::downgrade(&dns);
        let serve_tcp = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = tcp.accept().await else {
                    continue;
                };
                let Some(dns) = weak.upgrade() else { break };
                tokio::spawn(async move { dns.serve_tcp_client(socket).await });
            }
        });
        dns.tasks.lock().extend([serve_udp, serve_tcp]);
        tracing::info!(
            "[mesh dns] answering on {listen} through {:?}",
            dns.config.upstreams
        );
        Ok(dns)
    }

    /// Stop answering. Returns once the listeners have dropped their sockets, so the address
    /// can be bound again straight away.
    pub async fn stop(&self) {
        let tasks: Vec<JoinHandle<()>> = self.tasks.lock().drain(..).collect();
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }

    /// The settings it runs with.
    pub fn config(&self) -> &MeshDnsConfig {
        &self.config
    }

    /// Where it answers (UDP and TCP).
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen
    }

    /// Everything `overlay.dns_status` reports.
    pub fn status(&self) -> Value {
        let now = Instant::now();
        let upstreams: Vec<Value> = self
            .upstreams
            .iter()
            .map(|u| {
                let held = u.down_until.lock().map(|t| t > now).unwrap_or(false);
                let mut v = serde_json::to_value(&*u.stats.lock()).unwrap_or_default();
                v["target"] = json!(u.target);
                v["healthy"] = json!(!held);
                v
            })
            .collect();
        let sum = |key: &str| {
            upstreams
                .iter()
                .map(|u| u[key].as_u64().unwrap_or(0))
                .sum::<u64>()
        };
        json!({
            "enabled": true,
            "listen": self.listen.to_string(),
            "service": self.config.service,
            "timeout_ms": self.timeout.as_millis() as u64,
            "upstreams": upstreams,
            "totals": {
                "queries": sum("queries"),
                "answered": sum("answered"),
                "blocked": sum("blocked"),
                "nxdomain": sum("nxdomain"),
                "failed": *self.failed.lock(),
            },
        })
    }

    async fn serve_tcp_client(self: Arc<Self>, socket: TcpStream) {
        let (mut reader, writer) = socket.into_split();
        let writer = Arc::new(tokio::sync::Mutex::new(writer));
        loop {
            let Ok(query) = read_message(&mut reader).await else {
                break;
            };
            let dns = self.clone();
            let writer = writer.clone();
            // Pipelined: answers go back as they arrive, each framed whole under the lock.
            tokio::spawn(async move {
                if let Some(answer) = dns.answer(&query).await {
                    let _ = write_message(&mut *writer.lock().await, &answer).await;
                }
            });
        }
    }

    /// The answer to one query: from the first upstream that gives one, else SERVFAIL. `None`
    /// for something that is not a DNS query at all (it is dropped, as a resolver would).
    pub async fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 || query[2] & 0x80 != 0 {
            return None;
        }
        let now = Instant::now();
        let healthy: Vec<&Arc<Upstream>> = self
            .upstreams
            .iter()
            .filter(|u| u.down_until.lock().map(|t| t <= now).unwrap_or(true))
            .collect();
        // Every upstream held down: ask them all anyway rather than fail without trying.
        let order: Vec<&Arc<Upstream>> = if healthy.is_empty() {
            self.upstreams.iter().collect()
        } else {
            healthy
        };
        for upstream in order {
            match self.exchange(upstream, query).await {
                Ok(answer) => {
                    *upstream.down_until.lock() = None;
                    return Some(answer);
                }
                Err(e) => {
                    tracing::debug!("[mesh dns] {}: {e}", upstream.target);
                    *upstream.down_until.lock() = Some(Instant::now() + HOLD_DOWN);
                }
            }
        }
        *self.failed.lock() += 1;
        Some(servfail(query))
    }

    /// Ask one upstream, over its pipelined connection, with the id rewritten.
    async fn exchange(&self, upstream: &Upstream, query: &[u8]) -> Result<Vec<u8>> {
        upstream.stats.lock().queries += 1;
        let started = Instant::now();
        let result = self.exchange_inner(upstream, query).await;
        let mut stats = upstream.stats.lock();
        match &result {
            Ok(answer) => {
                let ms = started.elapsed().as_secs_f64() * 1000.0;
                stats.avg_ms = if stats.answered == 0 {
                    ms
                } else {
                    stats.avg_ms * 0.8 + ms * 0.2
                };
                stats.answered += 1;
                match answer[3] & 0x0f {
                    RCODE_NXDOMAIN => stats.nxdomain += 1,
                    RCODE_SERVFAIL => stats.servfail += 1,
                    _ if is_null_answer(answer) => stats.blocked += 1,
                    _ => {}
                }
            }
            Err(OverlayError::Closed(why)) if why == "timed out" => {
                stats.timeouts += 1;
                stats.last_error = format!("no answer within {} ms", self.timeout.as_millis());
            }
            Err(e) => {
                stats.errors += 1;
                stats.last_error = e.to_string();
            }
        }
        result
    }

    async fn exchange_inner(&self, upstream: &Upstream, query: &[u8]) -> Result<Vec<u8>> {
        let conn = self.connection(upstream).await?;
        let (id, rx) = {
            let mut pending = conn.pending.lock();
            let mut id = conn.next_id.fetch_add(1, Ordering::Relaxed);
            while pending.contains_key(&id) {
                id = conn.next_id.fetch_add(1, Ordering::Relaxed);
            }
            let (tx, rx) = oneshot::channel();
            pending.insert(id, tx);
            (id, rx)
        };
        let mut outgoing = query.to_vec();
        outgoing[..2].copy_from_slice(&id.to_be_bytes());
        let sent = write_message(&mut *conn.writer.lock().await, &outgoing).await;
        if let Err(e) = sent {
            conn.pending.lock().remove(&id);
            self.drop_connection(upstream, &conn).await;
            return Err(e.into());
        }
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(mut answer)) => {
                answer[..2].copy_from_slice(&query[..2]);
                Ok(answer)
            }
            Ok(Err(_)) => {
                self.drop_connection(upstream, &conn).await;
                Err(OverlayError::Closed(
                    "the upstream closed the connection".into(),
                ))
            }
            Err(_) => {
                conn.pending.lock().remove(&id);
                Err(OverlayError::Closed("timed out".into()))
            }
        }
    }

    /// The upstream's live connection, opened (through the overlay) when there is none.
    async fn connection(&self, upstream: &Upstream) -> Result<Arc<Conn>> {
        let mut slot = upstream.conn.lock().await;
        if let Some(conn) = slot.as_ref() {
            if conn.alive.load(Ordering::Relaxed) {
                return Ok(conn.clone());
            }
        }
        let (endpoint, _route) = self
            .node
            .connect(&upstream.target, &self.config.service)
            .await?;
        let stream = tokio::time::timeout(self.timeout, TcpStream::connect(endpoint))
            .await
            .map_err(|_| OverlayError::Closed("timed out".into()))??;
        let _ = stream.set_nodelay(true);
        let (mut reader, writer) = stream.into_split();
        let pending: Arc<Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>> = Arc::default();
        let alive = Arc::new(AtomicBool::new(true));
        let (task_pending, task_alive) = (pending.clone(), alive.clone());
        let reader = tokio::spawn(async move {
            while let Ok(answer) = read_message(&mut reader).await {
                if answer.len() < 12 {
                    continue;
                }
                let id = u16::from_be_bytes([answer[0], answer[1]]);
                if let Some(tx) = task_pending.lock().remove(&id) {
                    let _ = tx.send(answer);
                }
            }
            task_alive.store(false, Ordering::Relaxed);
            // Whoever is still waiting learns now, not at their timeout.
            task_pending.lock().clear();
        });
        let conn = Arc::new(Conn {
            writer: tokio::sync::Mutex::new(writer),
            pending,
            next_id: AtomicU16::new(rand::random()),
            alive,
            reader,
        });
        *slot = Some(conn.clone());
        Ok(conn)
    }

    async fn drop_connection(&self, upstream: &Upstream, conn: &Arc<Conn>) {
        conn.alive.store(false, Ordering::Relaxed);
        let mut slot = upstream.conn.lock().await;
        if slot.as_ref().map(|c| Arc::ptr_eq(c, conn)).unwrap_or(false) {
            *slot = None;
        }
    }
}

/// UDP and TCP on one port, so a client retrying a truncated answer over TCP finds it. With
/// port 0 the system picks a UDP port, which may not be free for TCP (on Windows a port can be in
/// an excluded range for one and not the other), so a few are tried.
async fn bind_both(wanted: SocketAddr) -> Result<(UdpSocket, TcpListener, SocketAddr)> {
    let tries = if wanted.port() == 0 { 20 } else { 1 };
    let mut last = None;
    for _ in 0..tries {
        let udp = UdpSocket::bind(wanted)
            .await
            .map_err(|source| OverlayError::Listen {
                addr: wanted,
                source,
            })?;
        let listen = udp.local_addr()?;
        match TcpListener::bind(listen).await {
            Ok(tcp) => return Ok((udp, tcp, listen)),
            Err(source) => {
                last = Some(OverlayError::Listen {
                    addr: listen,
                    source,
                })
            }
        }
    }
    Err(last.unwrap_or_else(|| OverlayError::protocol("no port")))
}

async fn read_message<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut msg).await?;
    Ok(msg)
}

async fn write_message<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(msg.len())
        .map_err(|_| std::io::Error::other("a DNS message over 65535 bytes"))?;
    let mut framed = Vec::with_capacity(2 + msg.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(msg);
    w.write_all(&framed).await?;
    w.flush().await
}

/// Where the question section ends, if the message has exactly the questions it says.
fn question_end(msg: &[u8]) -> Option<usize> {
    let qdcount = u16::from_be_bytes([*msg.get(4)?, *msg.get(5)?]);
    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, after) = transferd_dns::wire::decode_name(msg, pos).ok()?;
        pos = after + 4;
        if pos > msg.len() {
            return None;
        }
    }
    Some(pos)
}

/// A SERVFAIL for `query`: its id and question, no records.
pub fn servfail(query: &[u8]) -> Vec<u8> {
    let end = question_end(query).unwrap_or(12).min(query.len());
    let mut out = query[..end].to_vec();
    out[2] = 0x80 | (query[2] & 0x01); // QR, and RD as asked
    out[3] = 0x80 | RCODE_SERVFAIL; // RA
    if end == 12 {
        out[4..6].copy_from_slice(&[0, 0]);
    }
    out[6..12].fill(0);
    out
}

/// The answer as a UDP client may receive it: whole when it fits, otherwise the header and
/// question with TC set, which tells the client to ask again over TCP.
pub fn fit_for_udp(query: &[u8], answer: Vec<u8>) -> Vec<u8> {
    let has_edns = query.len() >= 12 && u16::from_be_bytes([query[10], query[11]]) > 0;
    let limit = if has_edns { EDNS_UDP } else { PLAIN_UDP };
    if answer.len() <= limit {
        return answer;
    }
    let end = question_end(&answer).unwrap_or(12).min(answer.len());
    let mut out = answer[..end].to_vec();
    out[2] |= 0x02; // TC
    out[6..12].fill(0);
    out
}

/// Whether every address in the answer is `0.0.0.0` or `::` (and there is at least one): how a
/// filtering resolver answers a name it blocks.
pub fn is_null_answer(answer: &[u8]) -> bool {
    let Some(mut pos) = question_end(answer) else {
        return false;
    };
    let ancount = u16::from_be_bytes([answer[6], answer[7]]);
    let mut seen = 0;
    for _ in 0..ancount {
        let Ok((_, after)) = transferd_dns::wire::decode_name(answer, pos) else {
            return false;
        };
        let Some(head) = answer.get(after..after + 10) else {
            return false;
        };
        let rtype = u16::from_be_bytes([head[0], head[1]]);
        let rdlen = u16::from_be_bytes([head[8], head[9]]) as usize;
        let Some(rdata) = answer.get(after + 10..after + 10 + rdlen) else {
            return false;
        };
        let addr = match (rtype, rdlen) {
            (1, 4) => Some(IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]])),
            (28, 16) => <[u8; 16]>::try_from(rdata).ok().map(IpAddr::from),
            _ => None,
        };
        if let Some(addr) = addr {
            if !addr.is_unspecified() {
                return false;
            }
            seen += 1;
        }
        pos = after + 10 + rdlen;
    }
    seen > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, name: &str, qtype: u16, edns: bool) -> Vec<u8> {
        let mut q = transferd_dns::wire::encode_query(id, name, qtype).expect("query");
        if !edns {
            q[10..12].fill(0);
            let end = question_end(&q).expect("question");
            q.truncate(end);
        }
        q
    }

    /// A response to `q` carrying these A/AAAA addresses.
    fn response(q: &[u8], addrs: &[IpAddr], rcode: u8) -> Vec<u8> {
        let end = question_end(q).expect("question");
        let mut r = q[..end].to_vec();
        r[2] = 0x81;
        r[3] = 0x80 | rcode;
        r[6..8].copy_from_slice(&(addrs.len() as u16).to_be_bytes());
        r[8..12].fill(0);
        for a in addrs {
            r.extend_from_slice(&[0xc0, 0x0c]);
            let (rtype, data): (u16, Vec<u8>) = match a {
                IpAddr::V4(v) => (1, v.octets().to_vec()),
                IpAddr::V6(v) => (28, v.octets().to_vec()),
            };
            r.extend_from_slice(&rtype.to_be_bytes());
            r.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            r.extend_from_slice(&(data.len() as u16).to_be_bytes());
            r.extend_from_slice(&data);
        }
        r
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn a_blocked_answer_is_told_apart_from_a_real_one() {
        let q = query(7, "ads.example", 1, false);
        let null = response(&q, &[ip("0.0.0.0"), ip("::")], 0);
        let real = response(&q, &[ip("93.184.216.34")], 0);
        let mixed = response(&q, &[ip("0.0.0.0"), ip("10.0.0.1")], 0);
        assert!(is_null_answer(&null));
        assert!(!is_null_answer(&real));
        assert!(
            !is_null_answer(&mixed),
            "one real address means it was not blocked"
        );
        assert!(
            !is_null_answer(&response(&q, &[], 0)),
            "no addresses is not a block"
        );
    }

    #[test]
    fn servfail_keeps_the_id_and_the_question() {
        let q = query(0xbeef, "example.com", 1, true);
        let f = servfail(&q);
        assert_eq!(&f[..2], &[0xbe, 0xef]);
        assert_eq!(f[2] & 0x80, 0x80, "a response");
        assert_eq!(f[3] & 0x0f, RCODE_SERVFAIL);
        assert_eq!(u16::from_be_bytes([f[4], f[5]]), 1, "the question is kept");
        assert_eq!(&f[6..12], &[0; 6], "and nothing else");
        assert_eq!(question_end(&f), Some(f.len()));
    }

    #[test]
    fn a_big_answer_is_truncated_for_udp_with_tc_set() {
        let q = query(1, "big.example", 1, false);
        let many: Vec<IpAddr> = (0..60).map(|i| IpAddr::from([10, 0, 0, i as u8])).collect();
        let big = response(&q, &many, 0);
        assert!(big.len() > PLAIN_UDP);
        let cut = fit_for_udp(&q, big.clone());
        assert_eq!(cut[2] & 0x02, 0x02, "TC");
        assert_eq!(u16::from_be_bytes([cut[6], cut[7]]), 0);
        assert_eq!(question_end(&cut), Some(cut.len()));
        let edns = query(1, "big.example", 1, true);
        assert_eq!(
            fit_for_udp(&edns, big.clone()),
            big,
            "an EDNS client takes up to 1232 bytes"
        );
    }
}
