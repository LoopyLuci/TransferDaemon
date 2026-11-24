//! A real DNS server on real sockets for the tests: it reads the query off the wire and answers with
//! bytes it builds itself, so a test can force truncation over UDP, AD on and off, and SERVFAIL without
//! mocking any of the code under test.
//!
//! UDP and TCP are served on the same port, because a truncated UDP answer must be retried over TCP at
//! the address that answer named (RFC 1035 §4.1.1) — a second port would describe a different situation
//! than the one in production.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use transferd_dns::wire;

/// What the server does with a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Answer normally with the AD bit set: a validating resolver that signed off.
    Validated,
    /// Answer normally, AD clear: a resolver that did not check the data.
    Unvalidated,
    /// SERVFAIL: a validating resolver reporting the data as bogus (RFC 4035 §3.2.3).
    Servfail,
    /// Set TC on the UDP answer, give the full answer over TCP.
    TruncateUdp,
    /// Answer with a TTL of 0: a valid answer the cache must not keep (RFC 1035 §2.3.4).
    ZeroTtl,
    /// NXDOMAIN: the name does not exist.
    Nxdomain,
    /// Read the query and never answer, so the client times out and moves on.
    Silent,
    /// Nothing is listening: a resolver that is not running.
    Down,
}

/// One running (or deliberately absent) test server.
pub struct Server {
    addr: SocketAddr,
    /// How many queries arrived over UDP.
    pub udp_seen: Arc<AtomicUsize>,
    /// How many queries arrived over TCP.
    pub tcp_seen: Arc<AtomicUsize>,
}

impl Server {
    /// The address to point a resolver at.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// A port both UDP and TCP can use. Windows reserves ranges for outbound use and a `bind` on one of them
/// fails whatever transport asked for it, so a port is only accepted once both have bound it.
fn shared_port() -> Option<u16> {
    for _ in 0..80 {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let port = tcp.local_addr().ok()?.port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_err() {
            continue;
        }
        return Some(port);
    }
    None
}

/// Start a server in `mode` on a free loopback port. `None` means no port could be found, which has
/// nothing to do with DNS: the caller reports it rather than failing.
pub async fn start(mode: Mode) -> Option<Server> {
    let port = shared_port()?;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().ok()?;
    let udp_seen = Arc::new(AtomicUsize::new(0));
    let tcp_seen = Arc::new(AtomicUsize::new(0));

    if mode == Mode::Down {
        // The port was bound and released above: nothing holds it now, which is what a resolver that is
        // not running looks like from here.
        return Some(Server {
            addr,
            udp_seen,
            tcp_seen,
        });
    }

    let udp = UdpSocket::bind(addr).await.ok()?;
    let tcp = TcpListener::bind(addr).await.ok()?;
    let counted = udp_seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                return;
            };
            counted.fetch_add(1, Ordering::Relaxed);
            if mode == Mode::Silent {
                continue;
            }
            if let Some(reply) = respond(&buf[..n], mode, false) {
                let _ = udp.send_to(&reply, from).await;
            }
        }
    });
    let counted = tcp_seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = tcp.accept().await else {
                return;
            };
            let counted = counted.clone();
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if sock.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
                    if sock.read_exact(&mut msg).await.is_err() {
                        return;
                    }
                    counted.fetch_add(1, Ordering::Relaxed);
                    // TCP answers are never truncated (RFC 1035 §4.2.2), whatever UDP did with them.
                    let Some(reply) = respond(&msg, mode, true) else {
                        return;
                    };
                    let mut framed = Vec::with_capacity(reply.len() + 2);
                    framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
                    framed.extend_from_slice(&reply);
                    if sock.write_all(&framed).await.is_err() {
                        return;
                    }
                    let _ = sock.flush().await;
                }
            });
        }
    });
    Some(Server {
        addr,
        udp_seen,
        tcp_seen,
    })
}

/// The A record this server serves for `a.test`, in the TEST-NET-3 range (RFC 5737).
pub const ADDRESS: [u8; 4] = [203, 0, 113, 9];
/// The AAAA record, documentation range (RFC 3849).
pub const ADDRESS_V6: [u8; 16] = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// The name the test server knows.
pub const NAME: &str = "a.test";

/// Build the answer to `query`, or `None` for a query we do not answer.
///
/// Every field comes from the query: the id, and the question's name and type. Echoing the question is
/// what a real server does, and this crate's decoder refuses a response whose question is not the one it
/// asked, so a reply that did not would be rejected — which is the point.
fn respond(query: &[u8], mode: Mode, over_tcp: bool) -> Option<Vec<u8>> {
    let question = read_question(query)?;
    let truncated = mode == Mode::TruncateUdp && !over_tcp;

    let mut flags = wire::FLAG_RESPONSE;
    if truncated {
        flags |= wire::FLAG_TC;
    }
    match mode {
        Mode::Servfail => flags |= wire::RCODE_SERVFAIL as u16,
        Mode::Nxdomain => flags |= wire::RCODE_NXDOMAIN as u16,
        // A validating resolver sets AD on an answer it checked (RFC 4035 §3.2.3); this one is only
        // validating in `Mode::Validated`.
        Mode::Validated => flags |= wire::FLAG_AD,
        _ => {}
    }

    let ttl = if mode == Mode::ZeroTtl { 0 } else { 300 };
    let rdata: Vec<(u16, u32, Vec<u8>)> =
        if truncated || matches!(mode, Mode::Servfail | Mode::Nxdomain) {
            Vec::new()
        } else if question.qtype == wire::TYPE_A {
            vec![(wire::TYPE_A, ttl, ADDRESS.to_vec())]
        } else if question.qtype == wire::TYPE_AAAA {
            vec![(wire::TYPE_AAAA, ttl, ADDRESS_V6.to_vec())]
        } else {
            return None;
        };

    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&question.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT: a reply need not carry OPT
                                                // The question, echoed byte for byte.
    out.extend_from_slice(query.get(12..question.end)?);
    for (rtype, ttl, rdata) in rdata {
        encode_name(NAME, &mut out);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    Some(out)
}

fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// The question read off the wire. A query carries no compression, so the name ends at its zero byte.
struct Question {
    id: u16,
    qtype: u16,
    end: usize,
}

fn read_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([*msg.first()?, *msg.get(1)?]);
    if u16::from_be_bytes([*msg.get(4)?, *msg.get(5)?]) != 1 {
        return None;
    }
    let mut p = 12;
    while *msg.get(p)? != 0 {
        p += 1;
    }
    p += 1; // past the root label
    let qtype = u16::from_be_bytes([*msg.get(p)?, *msg.get(p + 1)?]);
    Some(Question {
        id,
        qtype,
        end: p + 4,
    })
}
