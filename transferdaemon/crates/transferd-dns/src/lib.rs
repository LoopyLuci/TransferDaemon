//! `transferd-dns`: host names turned into addresses by a resolver that checks DNSSEC.
//!
//! A relay's address decides who carries a person's traffic, so where that address comes from matters as
//! much as the encryption around it. The operating system's resolver answers whatever the network's path
//! says — an on-path resolver can rewrite it — and never tells you whether it checked. This crate asks,
//! in order:
//!
//! 1. **`ironroot`** — a local Ironroot validating resolver over plain DNS on UDP, TCP when the answer is
//!    truncated (`TRANSFERD_DNS_IRONROOT`, default `127.0.0.1:5350`).
//! 2. **`quad9`** — Quad9 over DNS-over-TLS (RFC 7858), one TLS connection reused across queries.
//! 3. **`system`** — the operating system's resolver, never counted as validated.
//!
//! Not in the default order, and there only when asked for: **`mesh`**, the overlay's mesh DNS
//! forwarder (`TRANSFERD_DNS_MESH`, default `127.0.0.1:53053`), which answers through a paired
//! node's resolver. Plain DNS like `ironroot`; validated only when that resolver set AD.
//!
//! The order comes from `TRANSFERD_DNS` (comma-separated, default `ironroot,quad9,system`). With
//! `TRANSFERD_DNS_REQUIRE_VALIDATED=1` only answers carrying the AD bit count; an unvalidated answer, a
//! SERVFAIL from a validating resolver ("bogus", RFC 4035 §3.2.3) and the system resolver itself are all
//! errors rather than something to fall through to.
//!
//! ```no_run
//! # async fn f() -> Result<(), transferd_dns::DnsError> {
//! let addrs = transferd_dns::resolve("relay.example", 443).await?; // fail closed if required
//! let r = transferd_dns::lookup("relay.example", 443).await?;       // and says who answered
//! assert_eq!(r.addrs, addrs);
//! # Ok(()) }
//! ```
//!
//! The wire format is [`wire`]; it is written here rather than taken as a dependency.

pub mod wire;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use wire::{decode_answer, encode_query, Answer, DecodeError, TYPE_A, TYPE_AAAA};

/// The DNS name of Quad9's DoT service (the certificate, not either anycast IP).
pub const QUAD9_SERVER_NAME: &str = "dns.quad9.net";
/// Quad9's anycast addresses, tried in order (RFC 7858 §3.2 says a DoT client may use anycast directly).
pub const QUAD9_ADDRS: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 853),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)), 853),
];
/// The default address of a local Ironroot resolver.
pub const IRONROOT_DEFAULT_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5350);
/// The default address of the overlay's mesh DNS forwarder (`transferd-overlay`'s `dns` module).
pub const MESH_DEFAULT_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53053);
/// The resolver order used when `TRANSFERD_DNS` says nothing.
pub const DEFAULT_ORDER: &str = "ironroot,quad9,system";

/// How long one query to one resolver may take before we move on.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// A TTL longer than this is clamped: a resolver claiming an answer is good for a week is either wrong or
/// about to be wrong, and a relay address is worth re-checking.
pub const MAX_TTL: Duration = Duration::from_secs(600);
/// How many names the cache holds. A daemon resolves a handful (its relays, its contacts' relays),
/// and a long-lived process should not keep entries for names it will never ask again.
const MAX_CACHED_NAMES: usize = 256;

/// Anything that can go wrong between a host name and a `SocketAddr`.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// The name has no place on the wire (empty label, label over 63 bytes, name over 255).
    #[error("{0}")]
    InvalidName(String),
    /// Nobody we asked has an address for this name.
    #[error("{0}: no address")]
    NoAddress(String),
    /// The name does not exist (NXDOMAIN).
    #[error("{0}: NXDOMAIN")]
    NxDomain(String),
    /// A validating resolver said the data is bogus (SERVFAIL with validation on, RFC 4035 §3.2.3).
    #[error("{host}: {resolver} reports the data as bogus (SERVFAIL)")]
    Bogus {
        host: String,
        resolver: &'static str,
    },
    /// `TRANSFERD_DNS_REQUIRE_VALIDATED=1` and the answer did not carry AD.
    #[error("{host}: {resolver} did not validate the answer (no AD bit)")]
    NotValidated {
        host: String,
        resolver: &'static str,
    },
    /// Nothing usable was configured, so nothing was asked.
    #[error("no resolver can answer with DNSSEC validation ({0})")]
    NoValidatedResolver(&'static str),
    /// The resolver did not answer in time.
    #[error("{resolver}: timed out after {after:?}")]
    Timeout {
        resolver: &'static str,
        after: Duration,
    },
    /// The resolver could not be reached.
    #[error("{resolver}: {source}")]
    Transport {
        resolver: &'static str,
        source: std::io::Error,
    },
    /// The TLS session with the DoT resolver failed.
    #[error("{resolver}: TLS failed: {what}")]
    Tls {
        resolver: &'static str,
        what: String,
    },
    /// The response was not a DNS message we can use.
    #[error("{resolver}: {source}")]
    Malformed {
        resolver: &'static str,
        source: DecodeError,
    },
    /// A name came back with a configuration error.
    #[error("{what}")]
    Config { what: String },
}

/// Which resolver answered, and whether it stood behind the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The host name that was asked for.
    pub host: String,
    /// Its addresses, each with the port asked for.
    pub addrs: Vec<SocketAddr>,
    /// The name of the resolver that answered: `ironroot`, `quad9` or `system`.
    pub resolver: &'static str,
    /// True only when the answer carried the AD bit: the resolver checked it against a trust anchor.
    pub validated: bool,
    /// True when the answer came out of this crate's cache rather than off the wire.
    pub cached: bool,
}

/// One way of asking for an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolver {
    /// Plain DNS (UDP, TCP when truncated) to a validating resolver on this machine.
    Ironroot { addr: SocketAddr },
    /// Plain DNS to the overlay's mesh DNS forwarder, which asks a paired node's resolver.
    Mesh { addr: SocketAddr },
    /// DNS-over-TLS (RFC 7858): TCP, TLS, then length-prefixed messages.
    Quad9 {
        addrs: Vec<SocketAddr>,
        server_name: String,
    },
    /// The operating system's resolver. It never validates anything, so it never counts as validated.
    System,
}

impl Resolver {
    /// The local Ironroot resolver at `addr`.
    pub fn ironroot(addr: SocketAddr) -> Self {
        Self::Ironroot { addr }
    }

    /// Quad9 over DoT at `addrs`, presenting the certificate of `server_name`.
    pub fn quad9<I: IntoIterator<Item = SocketAddr>>(addrs: I, server_name: &str) -> Self {
        Self::Quad9 {
            addrs: addrs.into_iter().collect(),
            server_name: server_name.to_string(),
        }
    }

    /// The name used in `TRANSFERD_DNS` and in [`Resolution::resolver`].
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ironroot { .. } => "ironroot",
            Self::Mesh { .. } => "mesh",
            Self::Quad9 { .. } => "quad9",
            Self::System => "system",
        }
    }

    /// Parse one entry of `TRANSFERD_DNS`.
    pub fn from_name(name: &str, ironroot: SocketAddr) -> Result<Self, DnsError> {
        Self::from_name_with(name, ironroot, MESH_DEFAULT_ADDR)
    }

    /// Parse one entry of `TRANSFERD_DNS`, with the mesh forwarder's address too.
    pub fn from_name_with(
        name: &str,
        ironroot: SocketAddr,
        mesh: SocketAddr,
    ) -> Result<Self, DnsError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "ironroot" => Ok(Self::ironroot(ironroot)),
            "mesh" => Ok(Self::Mesh { addr: mesh }),
            "quad9" => Ok(Self::quad9(QUAD9_ADDRS, QUAD9_SERVER_NAME)),
            "system" => Ok(Self::System),
            other => Err(DnsError::Config {
                what: format!("unknown resolver {other:?} (ironroot, quad9, system, mesh)"),
            }),
        }
    }
}

/// How to resolve: which resolvers, in which order, and whether an unvalidated answer is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The resolvers to try, in order.
    pub resolvers: Vec<Resolver>,
    /// `TRANSFERD_DNS_REQUIRE_VALIDATED=1`: only an answer with the AD bit counts.
    pub require_validated: bool,
    /// How long one query to one resolver may take.
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Config {
    /// Read `TRANSFERD_DNS`, `TRANSFERD_DNS_IRONROOT`, `TRANSFERD_DNS_MESH` and
    /// `TRANSFERD_DNS_REQUIRE_VALIDATED`.
    pub fn from_env() -> Self {
        let mut config = Self::from_vars(
            std::env::var("TRANSFERD_DNS").ok().as_deref(),
            std::env::var("TRANSFERD_DNS_IRONROOT").ok().as_deref(),
            std::env::var("TRANSFERD_DNS_REQUIRE_VALIDATED")
                .ok()
                .as_deref(),
        );
        config.set_mesh_addr(std::env::var("TRANSFERD_DNS_MESH").ok().as_deref());
        config
    }

    /// Point a `mesh` entry at another address (`None` or unparsable: leave the default).
    pub fn set_mesh_addr(&mut self, addr: Option<&str>) {
        let Some(addr) = addr
            .map(str::trim)
            .and_then(|s| s.parse::<SocketAddr>().ok())
        else {
            return;
        };
        for resolver in &mut self.resolvers {
            if let Resolver::Mesh { addr: at } = resolver {
                *at = addr;
            }
        }
    }

    /// The same, from values already read — so the parsing can be tested without touching the process's
    /// environment (which is shared by every test running at once).
    pub fn from_vars(
        order: Option<&str>,
        ironroot: Option<&str>,
        require_validated: Option<&str>,
    ) -> Self {
        let ironroot = ironroot
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse().ok())
            .unwrap_or(IRONROOT_DEFAULT_ADDR);
        let list = order
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_ORDER);
        let resolvers: Vec<Resolver> = list
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .filter_map(|s| Resolver::from_name(s, ironroot).ok())
            .collect();
        Self {
            resolvers,
            require_validated: matches!(require_validated.map(str::trim), Some("1")),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// What the cache remembers about one name.
#[derive(Debug, Clone)]
struct Cached {
    addrs: Vec<IpAddr>,
    resolver: &'static str,
    validated: bool,
    until: Instant,
}

/// The resolver: the configured chain, a TTL cache, and the DoT connection we reuse.
pub struct Client {
    config: Config,
    cache: Mutex<HashMap<String, Cached>>,
    dot: tokio::sync::Mutex<Option<Dot>>,
}

/// One live DoT connection, reused across queries (RFC 7858 §3.2: a client may send several queries on a
/// session).
struct Dot {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
}

impl Client {
    /// A client with an explicit configuration — what the tests use to point at a local server.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            cache: Mutex::new(HashMap::new()),
            dot: tokio::sync::Mutex::new(None),
        }
    }

    /// The chain this client will try, with the system resolver dropped when validation is required: it
    /// cannot produce an AD bit, and falling through to it would undo the fail-closed policy.
    pub fn chain(&self) -> Vec<&Resolver> {
        self.config
            .resolvers
            .iter()
            .filter(|r| !(self.config.require_validated && matches!(r, Resolver::System)))
            .collect()
    }

    /// Resolve `host`, returning the addresses with `port` attached.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
        Ok(self.lookup(host, port).await?.addrs)
    }

    /// Resolve `host`, and say which resolver answered and whether it validated the answer.
    pub async fn lookup(&self, host: &str, port: u16) -> Result<Resolution, DnsError> {
        let name = host.trim_end_matches('.');
        if name.is_empty() {
            return Err(DnsError::InvalidName(host.to_string()));
        }
        if let Ok(ip) = name.parse::<IpAddr>() {
            // A literal address needs no resolver; it is not validated by anyone, and pretending
            // otherwise would be the one case where we say "yes" without having asked.
            return Ok(Resolution {
                host: name.to_string(),
                addrs: vec![SocketAddr::new(ip, port)],
                resolver: "literal",
                validated: false,
                cached: false,
            });
        }
        let key = name.to_ascii_lowercase();
        if let Some(c) = self.cached(&key, name, port) {
            return Ok(c);
        }

        let chain = self.chain();
        if chain.is_empty() {
            return Err(DnsError::NoValidatedResolver(
                if self.config.require_validated {
                    "TRANSFERD_DNS_REQUIRE_VALIDATED=1 leaves no resolver that can set AD"
                } else {
                    "TRANSFERD_DNS is empty"
                },
            ));
        }

        let mut last: Option<DnsError> = None;
        for resolver in chain {
            match self.ask(resolver, name).await {
                // A resolver that answered with an rcode has spoken for the name; another one will say the
                // same thing, and for SERVFAIL that is the whole point (fail closed).
                Ok(answer) => match (answer.rcode, answer.addrs.is_empty()) {
                    (wire::RCODE_SERVFAIL, _) => {
                        return Err(DnsError::Bogus {
                            host: name.to_string(),
                            resolver: resolver.name(),
                        });
                    }
                    (wire::RCODE_NXDOMAIN, _) => return Err(DnsError::NxDomain(name.to_string())),
                    (_, true) => last = Some(DnsError::NoAddress(name.to_string())),
                    (_, false) => {
                        if self.config.require_validated && !answer.authenticated_data {
                            // Not validated: keep looking, but never use it.
                            last = Some(DnsError::NotValidated {
                                host: name.to_string(),
                                resolver: resolver.name(),
                            });
                            continue;
                        }
                        let addrs: Vec<IpAddr> = answer.addrs.iter().map(|r| r.addr).collect();
                        self.remember(
                            &key,
                            &addrs,
                            resolver.name(),
                            answer.authenticated_data,
                            &answer,
                        );
                        return Ok(Resolution {
                            host: name.to_string(),
                            addrs: addrs
                                .into_iter()
                                .map(|ip| SocketAddr::new(ip, port))
                                .collect(),
                            resolver: resolver.name(),
                            validated: answer.authenticated_data,
                            cached: false,
                        });
                    }
                },
                // A resolver we could not reach or reach in time may be down; the next one may not be.
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or(DnsError::NoAddress(name.to_string())))
    }

    /// Ask one resolver, whatever kind it is.
    async fn ask(&self, resolver: &Resolver, name: &str) -> Result<Answer, DnsError> {
        let timeout = self.config.timeout;
        match resolver {
            Resolver::Ironroot { addr } | Resolver::Mesh { addr } => {
                let who = resolver.name();
                let answer = self.query_udp(who, *addr, name, timeout).await?;
                // Truncated: RFC 1035 §4.1.1 says ask again over TCP.
                if answer.truncated {
                    return self.query_tcp(who, *addr, name, timeout).await;
                }
                Ok(answer)
            }
            Resolver::Quad9 { addrs, server_name } => {
                self.query_dot(addrs, server_name, name).await
            }
            Resolver::System => self.query_system(name).await,
        }
    }

    /// Plain DNS over UDP: A and AAAA in one exchange.
    async fn query_udp(
        &self,
        resolver: &'static str,
        addr: SocketAddr,
        name: &str,
        timeout: Duration,
    ) -> Result<Answer, DnsError> {
        let bind: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap_or(addr)
        } else {
            "[::]:0".parse().unwrap_or(addr)
        };
        let sock = UdpSocket::bind(bind)
            .await
            .map_err(|source| DnsError::Transport { resolver, source })?;
        sock.connect(addr)
            .await
            .map_err(|source| DnsError::Transport { resolver, source })?;
        let mut out: Vec<Answer> = Vec::new();
        for qtype in [TYPE_A, TYPE_AAAA] {
            let id = next_id();
            let query = encode_query(id, name, qtype).map_err(|e| DnsError::InvalidName(e.0))?;
            sock.send(&query)
                .await
                .map_err(|source| DnsError::Transport { resolver, source })?;
            let mut buf = [0u8; wire::EDNS_UDP_PAYLOAD as usize];
            let n = match tokio::time::timeout(timeout, sock.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(source)) => return Err(DnsError::Transport { resolver, source }),
                Err(_) => {
                    return Err(DnsError::Timeout {
                        resolver,
                        after: timeout,
                    })
                }
            };
            out.push(
                decode_answer(&buf[..n], id, name, qtype)
                    .map_err(|source| DnsError::Malformed { resolver, source })?,
            );
        }
        Ok(merge(out))
    }

    /// Plain DNS over TCP: 2-byte length prefix, then the message (RFC 1035 §4.2.2).
    async fn query_tcp(
        &self,
        resolver: &'static str,
        addr: SocketAddr,
        name: &str,
        timeout: Duration,
    ) -> Result<Answer, DnsError> {
        let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(source)) => return Err(DnsError::Transport { resolver, source }),
            Err(_) => {
                return Err(DnsError::Timeout {
                    resolver,
                    after: timeout,
                })
            }
        };
        let mut out: Vec<Answer> = Vec::new();
        for qtype in [TYPE_A, TYPE_AAAA] {
            let id = next_id();
            let query = encode_query(id, name, qtype).map_err(|e| DnsError::InvalidName(e.0))?;
            let mut framed = Vec::with_capacity(query.len() + 2);
            framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
            framed.extend_from_slice(&query);
            stream
                .write_all(&framed)
                .await
                .map_err(|source| DnsError::Transport { resolver, source })?;
            let mut len = [0u8; 2];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|source| DnsError::Transport { resolver, source })?;
            let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
            stream
                .read_exact(&mut msg)
                .await
                .map_err(|source| DnsError::Transport { resolver, source })?;
            out.push(
                decode_answer(&msg, id, name, qtype)
                    .map_err(|source| DnsError::Malformed { resolver, source })?,
            );
        }
        Ok(merge(out))
    }

    /// DNS-over-TLS to Quad9 (RFC 7858): TCP to port 853, TLS against `dns.quad9.net`, then 2-byte
    /// length-prefixed messages on one connection reused across queries.
    ///
    /// A reused connection the server has since closed is a normal event, not a failure: the session is
    /// dropped and a fresh one opened before the query is retried. The retry happens once — a second
    /// failure on a brand-new connection is the error to report.
    async fn query_dot(
        &self,
        addrs: &[SocketAddr],
        server_name: &str,
        name: &str,
    ) -> Result<Answer, DnsError> {
        let mut guard = self.dot.lock().await;
        let reused = guard.is_some();
        self.dot_ensure(&mut guard, addrs, server_name).await?;
        let first = match guard.as_mut() {
            Some(d) => d.query(name, self.config.timeout).await,
            None => {
                return Err(DnsError::Timeout {
                    resolver: "quad9",
                    after: self.config.timeout,
                })
            }
        };
        match first {
            Ok(a) => Ok(a),
            Err(_) if reused => {
                // The connection was not ours to keep: forget it, open a new one, ask again. The first
                // error is the stale connection's, not the caller's answer, so it is not reported.
                *guard = None;
                self.dot_ensure(&mut guard, addrs, server_name).await?;
                let second = match guard.as_mut() {
                    Some(d) => d.query(name, self.config.timeout).await,
                    None => {
                        return Err(DnsError::Timeout {
                            resolver: "quad9",
                            after: self.config.timeout,
                        })
                    }
                };
                if second.is_err() {
                    *guard = None;
                }
                second
            }
            Err(e) => {
                *guard = None;
                Err(e)
            }
        }
    }

    /// Open a DoT session over the first address that answers, unless one is already open.
    async fn dot_ensure(
        &self,
        guard: &mut Option<Dot>,
        addrs: &[SocketAddr],
        server_name: &str,
    ) -> Result<(), DnsError> {
        if guard.is_some() {
            return Ok(());
        }
        let mut last: Option<DnsError> = None;
        for addr in addrs {
            match Dot::connect(*addr, server_name, self.config.timeout).await {
                Ok(d) => {
                    *guard = Some(d);
                    return Ok(());
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or(DnsError::Timeout {
            resolver: "quad9",
            after: self.config.timeout,
        }))
    }

    /// The operating system's resolver, through `getaddrinfo`. Never validated, so with
    /// `TRANSFERD_DNS_REQUIRE_VALIDATED=1` this is never reached.
    async fn query_system(&self, name: &str) -> Result<Answer, DnsError> {
        let mut sorted = tokio::net::lookup_host(format!("{name}:0"))
            .await
            .map_err(|_| DnsError::NoAddress(name.to_string()))?
            .collect::<Vec<_>>();
        sorted.sort();
        sorted.dedup();
        Ok(Answer {
            addrs: sorted
                .into_iter()
                .map(|a| wire::AddressRecord {
                    addr: a.ip(),
                    ttl: 0,
                })
                .collect(),
            rcode: wire::RCODE_NOERROR,
            authenticated_data: false,
            truncated: false,
        })
    }

    /// A fresh answer from the cache, if it is still good and still good enough.
    fn cached(&self, key: &str, host: &str, port: u16) -> Option<Resolution> {
        let mut cache = self.cache.lock().ok()?;
        let hit = cache.get(key).filter(|c| c.until > Instant::now())?;
        if self.config.require_validated && !hit.validated {
            return None;
        }
        let c = hit.clone();
        cache.retain(|_, v| v.until > Instant::now());
        Some(Resolution {
            // The name as it was asked for, not the lowercased key it is filed under.
            host: host.to_string(),
            addrs: c
                .addrs
                .iter()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect(),
            resolver: c.resolver,
            validated: c.validated,
            cached: true,
        })
    }

    /// Store an answer for as long as its shortest TTL allows.
    fn remember(
        &self,
        key: &str,
        addrs: &[IpAddr],
        resolver: &'static str,
        validated: bool,
        answer: &Answer,
    ) {
        let ttl = wire::min_ttl(answer)
            .map_or(Duration::ZERO, |s| Duration::from_secs(s as u64))
            .min(MAX_TTL);
        if ttl.is_zero() || addrs.is_empty() {
            return;
        }
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        cache.retain(|_, v| v.until > Instant::now());
        if cache.len() >= MAX_CACHED_NAMES {
            return;
        }
        cache.insert(
            key.to_string(),
            Cached {
                addrs: addrs.to_vec(),
                resolver,
                validated,
                until: Instant::now() + ttl,
            },
        );
    }
}

impl Dot {
    /// Open a DoT session: TCP, then TLS with the root store from webpki-roots.
    async fn connect(
        addr: SocketAddr,
        server_name: &str,
        timeout: Duration,
    ) -> Result<Self, DnsError> {
        let tcp = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(source)) => {
                return Err(DnsError::Transport {
                    resolver: "quad9",
                    source,
                })
            }
            Err(_) => {
                return Err(DnsError::Timeout {
                    resolver: "quad9",
                    after: timeout,
                })
            }
        };
        let name =
            rustls::pki_types::ServerName::try_from(server_name.to_string()).map_err(|e| {
                DnsError::Config {
                    what: format!("bad TLS server name {server_name:?}: {e}"),
                }
            })?;
        let stream = tokio_rustls::TlsConnector::from(client_config()?)
            .connect(name, tcp)
            .await
            .map_err(|e| DnsError::Tls {
                resolver: "quad9",
                what: e.to_string(),
            })?;
        Ok(Self { stream })
    }

    /// A and AAAA on this one connection, each a 2-byte-prefixed message.
    async fn query(&mut self, name: &str, timeout: Duration) -> Result<Answer, DnsError> {
        let mut out: Vec<Answer> = Vec::new();
        for qtype in [TYPE_A, TYPE_AAAA] {
            let id = next_id();
            let query = encode_query(id, name, qtype).map_err(|e| DnsError::InvalidName(e.0))?;
            let mut framed = Vec::with_capacity(query.len() + 2);
            framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
            framed.extend_from_slice(&query);
            let io_err = |e| DnsError::Transport {
                resolver: "quad9",
                source: e,
            };
            let read = async {
                self.stream.write_all(&framed).await.map_err(io_err)?;
                self.stream.flush().await.map_err(io_err)?;
                let mut len = [0u8; 2];
                self.stream.read_exact(&mut len).await.map_err(io_err)?;
                let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
                self.stream.read_exact(&mut msg).await.map_err(io_err)?;
                decode_answer(&msg, id, name, qtype).map_err(|source| DnsError::Malformed {
                    resolver: "quad9",
                    source,
                })
            };
            match tokio::time::timeout(timeout, read).await {
                Ok(r) => out.push(r?),
                Err(_) => {
                    return Err(DnsError::Timeout {
                        resolver: "quad9",
                        after: timeout,
                    })
                }
            }
        }
        Ok(merge(out))
    }
}

/// One DoT client configuration, built once: webpki-roots (the same store tokio-tungstenite already
/// pulls in for the relay's WebSockets), ring for the crypto primitives.
fn client_config() -> Result<Arc<rustls::ClientConfig>, DnsError> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let built = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_root_certificates(roots)
                .with_no_client_auth();
            Ok(Arc::new(built))
        })
        .clone()
        .map_err(|what| DnsError::Config {
            what: format!("cannot build a TLS client for the DoT resolver: {what}"),
        })
}

/// Combine the A and AAAA answers into one: an empty (or failed) AAAA leaves the A records alone, and the
/// rcode is the first one that was not NOERROR.
fn merge(answers: Vec<Answer>) -> Answer {
    let mut out = Answer {
        addrs: Vec::new(),
        rcode: wire::RCODE_NOERROR,
        authenticated_data: true,
        truncated: false,
    };
    for a in answers {
        if a.rcode != wire::RCODE_NOERROR {
            out.rcode = a.rcode;
        }
        // AD is per-response; two responses both have to have signed off for the set to be trusted.
        out.authenticated_data &= a.authenticated_data;
        out.truncated |= a.truncated;
        out.addrs.extend(a.addrs);
    }
    out
}

/// Transaction ids, unique within this process (a query and its answer only have to be matched to each
/// other, and a wrap would collide with a query still in flight only if we cycled all 65536).
fn next_id() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn shared() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(|| Client::new(Config::from_env()))
}

/// Resolve `host` with the shared client: the addresses with `port` attached.
pub async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
    shared().resolve(host, port).await
}

/// Resolve `host` with the shared client, and report which resolver answered and whether it validated.
pub async fn lookup(host: &str, port: u16) -> Result<Resolution, DnsError> {
    shared().lookup(host, port).await
}

/// [`lookup`] for a synchronous caller. Runs the query on its own thread with its own runtime, so this is
/// safe to call from inside a tokio worker as well as from plain synchronous code.
pub fn lookup_blocking(host: &str, port: u16) -> Result<Resolution, DnsError> {
    block_on(shared().lookup(host, port))
}

/// [`resolve`] for a synchronous caller.
pub fn resolve_blocking(host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
    block_on(shared().resolve(host, port))
}

/// Run a DNS future from synchronous code, whatever we are called on.
///
/// On a multi-threaded runtime `block_in_place` moves the work off the worker we are blocking. Anywhere
/// else — no runtime at all, or a current-thread runtime where `block_in_place` is not allowed — the
/// future runs on a short-lived thread with a runtime of its own, so the caller's thread simply waits.
fn block_on<F>(fut: F) -> F::Output
where
    F: Future + Send,
    F::Output: Send,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| handle.block_on(fut));
        }
        // A current-thread runtime cannot block on its own future, but it can run one on another thread,
        // which is what the fallback below does.
    }
    // Built here rather than on the worker, so the worker only has to run the future. A Runtime is Send.
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        // Only if the OS refuses to give us an event loop; there is nothing to resolve with then.
        eprintln!("transferd-dns: no runtime available to resolve a host name");
        std::process::exit(70);
    };
    std::thread::scope(|s| match s.spawn(move || rt.block_on(fut)).join() {
        Ok(out) => out,
        Err(e) => std::panic::resume_unwind(e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_order_is_ironroot_then_quad9_then_system() {
        let c = Config::from_vars(None, None, None);
        assert_eq!(
            c.resolvers.iter().map(Resolver::name).collect::<Vec<_>>(),
            vec!["ironroot", "quad9", "system"]
        );
        assert!(!c.require_validated);
        assert_eq!(c.resolvers[0], Resolver::ironroot(IRONROOT_DEFAULT_ADDR));
        assert_eq!(
            c.resolvers[1],
            Resolver::quad9(QUAD9_ADDRS, QUAD9_SERVER_NAME)
        );
    }

    #[test]
    fn the_order_and_the_ironroot_address_are_configurable() {
        let c = Config::from_vars(Some(" quad9 , system "), Some("127.0.0.1:15411"), None);
        assert_eq!(
            c.resolvers.iter().map(Resolver::name).collect::<Vec<_>>(),
            vec!["quad9", "system"]
        );
        assert!(!c
            .resolvers
            .iter()
            .any(|r| matches!(r, Resolver::Ironroot { .. })));

        let c = Config::from_vars(Some("ironroot"), Some("127.0.0.1:15411"), None);
        let want: SocketAddr = "127.0.0.1:15411".parse().expect("that is an address");
        assert_eq!(c.resolvers[0], Resolver::ironroot(want));
    }

    #[test]
    fn mesh_is_only_in_the_chain_when_asked_for_and_its_address_is_configurable() {
        assert!(!Config::from_vars(None, None, None)
            .resolvers
            .iter()
            .any(|r| matches!(r, Resolver::Mesh { .. })));
        let mut c = Config::from_vars(Some("mesh,quad9"), None, None);
        assert_eq!(
            c.resolvers[0],
            Resolver::Mesh {
                addr: MESH_DEFAULT_ADDR
            }
        );
        c.set_mesh_addr(Some("127.0.0.1:15353"));
        assert_eq!(
            c.resolvers[0],
            Resolver::Mesh {
                addr: "127.0.0.1:15353".parse().unwrap()
            }
        );
        c.set_mesh_addr(Some("not an address"));
        assert_eq!(
            c.resolvers[0].name(),
            "mesh",
            "a bad address leaves the last good one"
        );
    }

    #[test]
    fn require_validated_is_only_on_for_exactly_1() {
        assert!(Config::from_vars(None, None, Some("1")).require_validated);
        for off in ["", "0", "true", "yes"] {
            assert!(
                !Config::from_vars(None, None, Some(off)).require_validated,
                "{off:?} should not require validation"
            );
        }
        assert!(!Config::from_vars(None, None, None).require_validated);
    }

    #[test]
    fn an_unknown_resolver_is_dropped_and_an_empty_chain_is_reported() {
        // A name we do not know must not silently become "resolve nothing and succeed".
        let c = Config::from_vars(Some("nonsense"), None, None);
        assert!(c.resolvers.is_empty());
        let client = Client::new(c);
        assert!(client.chain().is_empty());
    }

    #[test]
    fn requiring_validation_removes_the_system_resolver() {
        let client = Client::new(Config::from_vars(Some("ironroot,system"), None, Some("1")));
        let names: Vec<&str> = client.chain().iter().map(|r| r.name()).collect();
        assert_eq!(
            names,
            vec!["ironroot"],
            "the system resolver can never set AD"
        );
    }

    #[tokio::test]
    async fn a_literal_address_needs_no_resolver() {
        let client = Client::new(Config::from_vars(Some("ironroot"), None, Some("1")));
        let r = client
            .lookup("192.0.2.7", 443)
            .await
            .expect("a literal always resolves");
        assert_eq!(
            r.addrs,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                443
            )]
        );
        assert!(!r.validated, "a literal is nobody's validated answer");
        assert_eq!(r.resolver, "literal");
    }

    #[test]
    fn merging_needs_both_answers_to_be_authenticated() {
        let signed = |addr: &str, ad: bool| Answer {
            addrs: vec![wire::AddressRecord {
                addr: addr.parse().expect("a test address parses"),
                ttl: 60,
            }],
            rcode: wire::RCODE_NOERROR,
            authenticated_data: ad,
            truncated: false,
        };
        assert!(merge(vec![signed("1.1.1.1", true), signed("::1", true)]).authenticated_data);
        assert!(!merge(vec![signed("1.1.1.1", true), signed("::1", false)]).authenticated_data);
        assert!(!merge(vec![signed("1.1.1.1", false), signed("::1", true)]).authenticated_data);
        // An AAAA that simply does not exist (NOERROR, no records) is not a failure, and it does not
        // clear AD on the A answer — AD is set on every response the resolver sent.
        let empty = Answer {
            addrs: vec![],
            rcode: wire::RCODE_NOERROR,
            authenticated_data: true,
            truncated: false,
        };
        let merged = merge(vec![signed("1.1.1.1", true), empty]);
        assert!(merged.authenticated_data);
        assert_eq!(merged.addrs.len(), 1);
        // A SERVFAIL anywhere in the pair is the pair's rcode.
        let fail = Answer {
            addrs: vec![],
            rcode: wire::RCODE_SERVFAIL,
            authenticated_data: false,
            truncated: false,
        };
        assert_eq!(
            merge(vec![signed("1.1.1.1", true), fail]).rcode,
            wire::RCODE_SERVFAIL
        );
    }

    #[test]
    fn an_empty_name_is_refused() {
        let c = Config::from_vars(Some("ironroot"), None, None);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let client = Client::new(c);
        let Ok(rt) = rt else {
            eprintln!("no runtime to run the lookup on");
            return;
        };
        assert!(matches!(
            rt.block_on(client.lookup("", 1)),
            Err(DnsError::InvalidName(_))
        ));
    }
}
