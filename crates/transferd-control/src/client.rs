//! Finding the running daemon's control hub, and talking to it.
//!
//! The hub writes `<data dir>/transferdaemon/control.json` (`{url, token, pid, version, grpc}`) when it starts, the
//! same folder as the daemon's gRPC token (`TRANSFERD_DATA_DIR` moves both). Anything on this machine running as the
//! same user can read it: the CLI, the GUI and TUI (to attach), ABP, scripts.
//!
//! The HTTP client here is deliberately tiny and blocking (std only: HTTP/1.1 to 127.0.0.1, `Content-Length`
//! bodies), so the GUI and TUI can attach without pulling in an HTTP stack.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discovery {
    pub url: String,
    pub token: String,
    pub pid: u32,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub grpc: String,
    #[serde(default)]
    pub started_at: u64,
}

/// `<data-local>/transferdaemon`, or `$TRANSFERD_DATA_DIR/transferdaemon`.
pub fn data_dir() -> PathBuf {
    std::env::var_os("TRANSFERD_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| dirs::data_local_dir().unwrap_or_else(|| PathBuf::from(".")))
        .join("transferdaemon")
}

pub fn discovery_path() -> PathBuf {
    data_dir().join("control.json")
}

/// The hub's address and token, if a daemon wrote them. `TRANSFERD_CONTROL_URL` + `TRANSFERD_CONTROL_TOKEN` override
/// (a hub on another machine, through a tunnel).
pub fn discover() -> Option<Discovery> {
    if let (Ok(url), Ok(token)) = (std::env::var("TRANSFERD_CONTROL_URL"), std::env::var("TRANSFERD_CONTROL_TOKEN")) {
        return Some(Discovery { url, token, pid: 0, version: String::new(), grpc: String::new(), started_at: 0 });
    }
    let text = std::fs::read_to_string(discovery_path()).ok()?;
    serde_json::from_str(&text).ok()
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("TransferDaemon is not running (no {0}); start it with `transferd` or `transferd-cli daemon start`")]
    NotRunning(String),
    #[error("cannot reach TransferDaemon's control hub at {0}: {1}")]
    Unreachable(String, String),
    #[error("{code}: {message}")]
    Failed { code: String, message: String, status: u16 },
    #[error("bad reply from the control hub: {0}")]
    BadReply(String),
}

/// A connection to the hub (one request per TCP connection; the hub is local).
#[derive(Debug, Clone)]
pub struct Client {
    pub url: String,
    pub token: String,
    pub timeout: Duration,
}

fn host_port(url: &str) -> Result<(String, String), ClientError> {
    let rest = url.trim_start_matches("http://");
    let (hp, _) = rest.split_once('/').unwrap_or((rest, ""));
    if url.starts_with("https://") {
        return Err(ClientError::Unreachable(url.into(), "https is not supported by this client".into()));
    }
    Ok((hp.to_string(), hp.to_string()))
}

impl Client {
    pub fn new(d: &Discovery) -> Self {
        Self { url: d.url.trim_end_matches('/').to_string(), token: d.token.clone(), timeout: Duration::from_secs(900) }
    }

    /// The running hub, or a clear error.
    pub fn connect() -> Result<Self, ClientError> {
        let d = discover().ok_or_else(|| ClientError::NotRunning(discovery_path().display().to_string()))?;
        Ok(Self::new(&d))
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// One request. Returns (status, JSON body; `null` for an empty body).
    pub fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Value), ClientError> {
        let (addr, host) = host_port(&self.url)?;
        let unreachable = |e: std::io::Error| ClientError::Unreachable(self.url.clone(), e.to_string());
        let sock = addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| ClientError::Unreachable(self.url.clone(), e.to_string()))?;
        let mut s = TcpStream::connect_timeout(&sock, Duration::from_secs(5)).map_err(unreachable)?;
        s.set_read_timeout(Some(self.timeout)).ok();
        s.set_write_timeout(Some(Duration::from_secs(30))).ok();
        let payload = body.map(|b| b.to_string()).unwrap_or_default();
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\n\
             Accept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            self.token,
            payload.len()
        );
        s.write_all(head.as_bytes()).map_err(unreachable)?;
        s.write_all(payload.as_bytes()).map_err(unreachable)?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).map_err(unreachable)?;
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| ClientError::BadReply("no header end".into()))?;
        let head = String::from_utf8_lossy(&raw[..split]).to_string();
        let mut body = raw[split + 4..].to_vec();
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ClientError::BadReply(head.lines().next().unwrap_or_default().into()))?;
        if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            body = dechunk(&body);
        }
        let value = if body.iter().all(|b| b.is_ascii_whitespace()) {
            Value::Null
        } else {
            serde_json::from_slice(&body).map_err(|e| ClientError::BadReply(format!("{e}: {}", String::from_utf8_lossy(&body[..body.len().min(200)]))))?
        };
        Ok((status, value))
    }

    fn check(&self, (status, v): (u16, Value)) -> Result<Value, ClientError> {
        if status < 400 {
            return Ok(v);
        }
        let err = v.get("error").cloned().unwrap_or(v.clone());
        Err(ClientError::Failed {
            code: err.get("code").and_then(Value::as_str).unwrap_or("error").to_string(),
            message: err.get("message").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| err.to_string()),
            status,
        })
    }

    pub fn get(&self, path: &str) -> Result<Value, ClientError> {
        let r = self.request("GET", path, None)?;
        self.check(r)
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Value, ClientError> {
        let r = self.request("POST", path, Some(body))?;
        self.check(r)
    }

    /// Run an operation by id; returns its result.
    pub fn call(&self, op: &str, args: Value) -> Result<Value, ClientError> {
        let v = self.post(&format!("/v1/call/{op}"), &args)?;
        Ok(v.get("result").cloned().unwrap_or(v))
    }

    pub fn operations(&self) -> Result<Vec<Value>, ClientError> {
        match self.get("/v1/operations")? {
            Value::Array(a) => Ok(a),
            other => Err(ClientError::BadReply(other.to_string())),
        }
    }

    pub fn health(&self) -> Result<Value, ClientError> {
        self.get("/v1/health")
    }
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let Some(nl) = body[i..].windows(2).position(|w| w == b"\r\n") else { break };
        let size = usize::from_str_radix(String::from_utf8_lossy(&body[i..i + nl]).trim(), 16).unwrap_or(0);
        i += nl + 2;
        if size == 0 || i + size > body.len() {
            break;
        }
        out.extend_from_slice(&body[i..i + size]);
        i += size + 2;
    }
    out
}

// ---- attaching a user interface -------------------------------------------------------------------------------------

/// A command the hub forwards to an attached GUI or TUI.
#[derive(Debug, Clone, Deserialize)]
pub struct UiCommand {
    pub id: String,
    pub action: String,
    #[serde(default)]
    pub args: Value,
}

fn sessions() -> &'static std::sync::Mutex<std::collections::HashMap<&'static str, String>> {
    static S: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<&'static str, String>>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

/// Tell the hub this user interface is going away (call when the window or terminal UI exits), so the next
/// `gui.launch` / `tui.launch` starts a fresh one instead of talking to one that is closing.
pub fn detach(kind: &'static str) {
    let session = sessions().lock().ok().and_then(|mut m| m.remove(kind));
    if let (Some(session), Some(d)) = (session, discover()) {
        let c = Client::new(&d).with_timeout(Duration::from_secs(2));
        let _ = c.request("POST", &format!("/v1/attach/{kind}/detach"), Some(&json!({"session": session})));
    }
}

/// Attach a user interface (`kind` = "gui" or "tui") to the hub, on a background thread, for as long as the process
/// lives. Every command the hub forwards is handed to `handle`, whose `Ok` value or `Err` message goes back as the
/// reply. `handle` runs on the attach thread and must not block for long (UIs queue work for their next frame and wait
/// on a channel, bounded by the command's own timeout). Survives the daemon restarting: it re-reads the discovery file
/// and attaches again.
pub fn attach<F>(kind: &'static str, info: Value, handle: F) -> std::thread::JoinHandle<()>
where
    F: Fn(UiCommand) -> Result<Value, String> + Send + 'static,
{
    std::thread::Builder::new()
        .name(format!("transferd-{kind}-attach"))
        .spawn(move || loop {
            let Some(d) = discover() else {
                std::thread::sleep(Duration::from_secs(3));
                continue;
            };
            let c = Client::new(&d).with_timeout(Duration::from_secs(40));
            let hello = json!({"pid": std::process::id(), "info": info});
            let session = match c.post(&format!("/v1/attach/{kind}"), &hello) {
                Ok(v) => {
                    let session = v.get("session").and_then(Value::as_str).unwrap_or_default().to_string();
                    if let Ok(mut m) = sessions().lock() {
                        m.insert(kind, session.clone());
                    }
                    session
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_secs(3));
                    continue;
                }
            };
            loop {
                match c.request("GET", &format!("/v1/attach/{kind}/next?session={session}"), None) {
                    Ok((200, v)) => {
                        let Ok(cmd) = serde_json::from_value::<UiCommand>(v) else { continue };
                        let id = cmd.id.clone();
                        let reply = match handle(cmd) {
                            Ok(result) => json!({"session": session, "id": id, "ok": true, "result": result}),
                            Err(e) => json!({"session": session, "id": id, "ok": false, "error": e}),
                        };
                        let _ = c.request("POST", &format!("/v1/attach/{kind}/reply"), Some(&reply));
                    }
                    Ok((204, _)) => {}
                    _ => break, // hub gone or replaced (410): attach again
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        })
        .unwrap_or_else(|_| std::thread::spawn(|| {}))
}
