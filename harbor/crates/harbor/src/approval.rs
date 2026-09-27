//! The human-in-the-loop approval channel.
//!
//! When policy says `Ask`, the MCP server parks the call and hands the human a
//! loopback URL. The URL contains a 128-bit random token — the token IS the
//! bearer secret, so only whoever can read the operator's terminal can
//! approve. Approvals are TTL-bounded and audited. The agent can never approve
//! its own requests: this endpoint is not exposed as a capability.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Result of an approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Granted,
    Denied,
    Expired,
}

struct Pending {
    capability: String,
    /// URL-safe short description shown to the operator.
    resource: String,
    sender: oneshot::Sender<ApprovalOutcome>,
}

/// Loopback-only approval server.
#[derive(Clone)]
pub struct ApprovalServer {
    inner: Arc<ApprovalInner>,
}

struct ApprovalInner {
    pending: Mutex<HashMap<String, Pending>>,
    /// The port the server bound (0 = not started).
    port: u16,
    ttl_secs: u64,
}

impl ApprovalServer {
    /// Bind and spawn the listener on 127.0.0.1 (never on a routable addr).
    pub async fn start(port: u16, ttl_secs: u64) -> std::io::Result<Self> {
        let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
        let bound = listener.local_addr()?.port();
        let inner = Arc::new(ApprovalInner {
            pending: Mutex::new(HashMap::new()),
            port: bound,
            ttl_secs,
        });
        let server = Self { inner: inner.clone() };
        tokio::spawn(accept_loop(listener, inner));
        Ok(server)
    }

    pub fn port(&self) -> u16 {
        self.inner.port
    }

    pub fn ttl(&self) -> u64 {
        self.inner.ttl_secs
    }

    /// Create a pending approval for a call; returns the URL the operator must
    /// open. The call awaits `wait`.
    pub fn request(&self, capability: &str, resource: Option<&str>) -> (String, oneshot::Receiver<ApprovalOutcome>) {
        let token: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        let (tx, rx) = oneshot::channel();
        self.inner.pending.lock().unwrap_or_else(|e| e.into_inner()).insert(
            token.clone(),
            Pending {
                capability: capability.to_string(),
                resource: resource.unwrap_or("(no resource)").chars().take(200).collect(),
                sender: tx,
            },
        );
        let url = format!("http://127.0.0.1:{}/approve/{}", self.inner.port, token);
        (url, rx)
    }
}

/// Wait for the operator's decision with a TTL. Returns `Expired` if the TTL
/// elapses (or the channel drops, e.g. server shutdown).
pub async fn await_decision(rx: oneshot::Receiver<ApprovalOutcome>, ttl_secs: u64) -> ApprovalOutcome {
    match tokio::time::timeout(std::time::Duration::from_secs(ttl_secs), rx).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => ApprovalOutcome::Denied,
        Err(_) => ApprovalOutcome::Expired,
    }
}

async fn accept_loop(listener: TcpListener, inner: Arc<ApprovalInner>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let inner = inner.clone();
        tokio::spawn(async move {
            let _ = handle_conn(stream, inner).await;
        });
    }
}

async fn handle_conn(mut stream: TcpStream, inner: Arc<ApprovalInner>) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
    let (status, body) = route(&req, &inner).await;
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn route(req: &str, inner: &Arc<ApprovalInner>) -> (&'static str, String) {
    // GET /approve/<token>   → grant
    // GET /deny/<token>      → deny
    // GET /                  → status
    let path = req.split_whitespace().nth(1).unwrap_or("/");
    match path {
        "/" => ("200 OK", format!("harbor approval server on 127.0.0.1:{}", inner.port)),
        _ => {
            let (verb, token) = match path.strip_prefix("/approve/") {
                Some(t) => ("approve", t),
                None => match path.strip_prefix("/deny/") {
                    Some(t) => ("deny", t),
                    None => return ("404 Not Found", "unknown route".into()),
                },
            };
            let outcome = if verb == "approve" { ApprovalOutcome::Granted } else { ApprovalOutcome::Denied };
            let p = inner.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(token);
            match p {
                Some(p) => {
                    let _ = p.sender.send(outcome.clone());
                    let msg = format!("{verb}d: {} ({})", p.capability, p.resource);
                    ("200 OK", msg)
                }
                None => ("404 Not Found", "no such pending approval (expired or already decided)".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_then_expiry() {
        let srv = ApprovalServer::start(0, 60).await.unwrap();
        let (url, rx) = srv.request("pwsh.run", Some("whoami"));
        assert!(url.contains(&srv.port().to_string()));
        // Nobody approves → the TTL elapses → Expired. Use a short wait.
        let outcome = await_decision(rx, 1).await;
        assert_eq!(outcome, ApprovalOutcome::Expired, "no one approved → expired");
    }

    #[tokio::test]
    async fn approve_route_grants() {
        let srv = ApprovalServer::start(0, 60).await.unwrap();
        let (url, rx) = srv.request("fs.write", Some("Z:/x"));
        let token = url.rsplit('/').next().unwrap().to_string();
        // Simulate the operator hitting the URL.
        let resp = req(&format!("GET /approve/{token} HTTP/1.1\r\nHost: localhost\r\n\r\n"), srv.port()).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(await_decision(rx, 60).await, ApprovalOutcome::Granted);
        // A second hit is a 404 (single-use).
        let resp = req(&format!("GET /approve/{token} HTTP/1.1\r\nHost: localhost\r\n\r\n"), srv.port()).await;
        assert!(resp.starts_with("HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn deny_route_denies() {
        let srv = ApprovalServer::start(0, 60).await.unwrap();
        let (url, rx) = srv.request("pwsh.run", None);
        let token = url.rsplit('/').next().unwrap().to_string();
        let resp = req(&format!("GET /deny/{token} HTTP/1.1\r\nHost: localhost\r\n\r\n"), srv.port()).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(await_decision(rx, 60).await, ApprovalOutcome::Denied);
    }

    async fn req(raw: &str, port: u16) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(raw.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out).await;
        drop(s);
        String::from_utf8_lossy(&out).into_owned()
    }
}