//! The control hub: one local HTTP endpoint for everything TransferDaemon can do.
//!
//! It runs inside the daemon (`transferd`), on `127.0.0.1:50060` by default (`TRANSFERD_CONTROL_ADDR`), and writes
//! `control.json` (address and token) next to the daemon's gRPC token so local tools find it.
//!
//! ```text
//! GET  /v1/health                  {ok, pid, version}                       (no token)
//! GET  /v1/operations              the catalog: id, group, summary, mutating, destructive, input/output schemas
//! GET  /v1/operations/{id}
//! POST /v1/call/{id}               run one: body = its arguments -> {result} | {error: {code, message}}
//! GET  /v1/openapi.json
//! POST /mcp                        Model Context Protocol (Streamable HTTP, JSON replies); ?tools=compact
//! POST /v1/attach/{gui|tui}        a user interface attaches; then long-polls:
//! GET  /v1/attach/{kind}/next      the next command for it (waits up to 25 s; 204 when none)
//! POST /v1/attach/{kind}/reply     its answer
//! GET  /v1/audit?limit=            the calls that changed something
//! ```
//!
//! Every route but `/v1/health` needs the token (`Authorization: Bearer <token>` or `X-TD-Token`). Requests that carry
//! a browser `Origin` are refused, so a web page cannot drive the daemon through the user's browser.

use crate::catalog::{self, CallError, Operation};
use crate::client::{data_dir, discovery_path, Discovery};
use crate::mcp;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot, Mutex};
use transferd_api::auth::AuthChannel;

/// How the hub reaches the daemon it belongs to.
#[derive(Clone, Debug)]
pub struct HubConfig {
    /// `http://127.0.0.1:50051`
    pub grpc_url: String,
    pub grpc_token: Option<String>,
    pub bind: SocketAddr,
    pub version: String,
    /// Extra facts for `daemon.status` (peer listener address...), filled in by the daemon.
    pub facts: Arc<std::sync::Mutex<serde_json::Map<String, Value>>>,
}

struct Attachment {
    session: String,
    pid: u32,
    info: Value,
    queue_tx: mpsc::UnboundedSender<Value>,
    queue_rx: Arc<Mutex<mpsc::UnboundedReceiver<Value>>>,
    pending: HashMap<String, oneshot::Sender<Result<Value, String>>>,
    last_seen: Instant,
}

struct LocalRelay {
    child: std::process::Child,
    bind: String,
    started_at: u64,
}

pub struct Hub {
    pub cfg: HubConfig,
    pub token: String,
    started: Instant,
    started_at: u64,
    channel: Mutex<Option<AuthChannel>>,
    attached: Mutex<HashMap<String, Attachment>>,
    relays: std::sync::Mutex<HashMap<String, LocalRelay>>,
    audit_lock: std::sync::Mutex<()>,
    /// Fired by `daemon.stop`; the daemon exits when it is.
    pub stop: Arc<tokio::sync::Notify>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn new_token() -> String {
    use rand::RngCore as _;
    let mut b = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Constant-time comparison, so the token cannot be guessed byte by byte from timings.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        Self { status, code: code.into(), message: message.into() }
    }
}

impl From<CallError> for ApiError {
    fn from(e: CallError) -> Self {
        let status = match e {
            CallError::BadArgs(_) => StatusCode::BAD_REQUEST,
            CallError::Unreachable(_) => StatusCode::SERVICE_UNAVAILABLE,
            CallError::Status(_) => StatusCode::BAD_GATEWAY,
        };
        Self::new(status, e.code(), e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": {"code": self.code, "message": self.message}}))).into_response()
    }
}

type Shared = Arc<Hub>;

impl Hub {
    pub fn new(cfg: HubConfig) -> Arc<Self> {
        let token = std::env::var("TRANSFERD_CONTROL_TOKEN").ok().filter(|t| t.len() >= 16).unwrap_or_else(new_token);
        Arc::new(Self {
            cfg,
            token,
            started: Instant::now(),
            started_at: now(),
            channel: Mutex::new(None),
            attached: Mutex::new(HashMap::new()),
            relays: std::sync::Mutex::new(HashMap::new()),
            audit_lock: std::sync::Mutex::new(()),
            stop: Arc::new(tokio::sync::Notify::new()),
        })
    }

    async fn channel(&self) -> Result<AuthChannel, CallError> {
        let mut guard = self.channel.lock().await;
        if let Some(ch) = guard.as_ref() {
            return Ok(ch.clone());
        }
        let endpoint = tonic::transport::Endpoint::from_shared(self.cfg.grpc_url.clone())
            .map_err(|e| CallError::Unreachable(e.to_string()))?
            .connect_timeout(Duration::from_secs(5));
        // Lazy: the first call connects (the hub starts before the gRPC server is listening).
        let ch = endpoint.connect_lazy();
        let token = self.cfg.grpc_token.clone().unwrap_or_default();
        let auth = AuthChannel::new(ch, &token);
        *guard = Some(auth.clone());
        Ok(auth)
    }

    fn audit(&self, op: &str, args: &Value, ok: bool, error: Option<&str>) {
        let _g = self.audit_lock.lock();
        let path = data_dir().join("control-audit.jsonl");
        let mut args = args.clone();
        redact(&mut args);
        let line = json!({"ts": now(), "operation": op, "args": args, "ok": ok, "error": error});
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Run one operation (what `/v1/call`, MCP and every client use).
    pub async fn call(self: &Arc<Self>, op_id: &str, args: Value) -> Result<Value, ApiError> {
        let op = catalog::find(op_id).ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, "unknown_operation", format!("no operation {op_id:?} (GET /v1/operations lists them)"))
        })?;
        let args = if args.is_null() { json!({}) } else { args };
        if !args.is_object() {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "bad_arguments", "arguments must be a JSON object"));
        }
        let result = self.run(&op, args.clone()).await;
        if op.mutating {
            match &result {
                Ok(_) => self.audit(op_id, &args, true, None),
                Err(e) => self.audit(op_id, &args, false, Some(&e.message)),
            }
        }
        result
    }

    async fn run(self: &Arc<Self>, op: &Operation, args: Value) -> Result<Value, ApiError> {
        if let Some((service, rpc)) = op.rpc {
            let args = if op.id == "transfers.send_file" { catalog::complete_send_file(args)? } else { args };
            let ch = self.channel().await?;
            return Ok(catalog::call_rpc(ch, service, rpc, args).await?);
        }
        match op.id.as_str() {
            "daemon.status" => Ok(self.status().await),
            "daemon.env" => Ok(daemon_env()),
            "daemon.stop" => {
                let stop = self.stop.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    stop.notify_waiters();
                });
                Ok(json!({"stopping": true}))
            }
            "gui.launch" => self.launch_gui(&args).await,
            "tui.launch" => self.launch_tui(&args).await,
            "relay.status" => Ok(self.relay_status()),
            "relay.start" => self.relay_start(&args),
            "relay.stop" => self.relay_stop(&args),
            "relay.probe" => relay_probe(args.get("addr").and_then(Value::as_str).unwrap_or_default()).await,
            id if id.starts_with("gui.") || id.starts_with("tui.") => {
                let (kind, action) = id.split_once('.').unwrap_or(("", ""));
                let timeout = args.get("timeout_s").and_then(Value::as_f64).unwrap_or(60.0).clamp(1.0, 600.0) + 5.0;
                let closing = (id == "gui.window" && args.get("action").and_then(Value::as_str) == Some("close")) || id == "tui.quit";
                let r = self.forward(kind, action, args, Duration::from_secs_f64(timeout)).await;
                if closing && r.is_ok() {
                    // It is going away: the next launch must start a new one, not wait for this one to time out.
                    self.attached.lock().await.remove(kind);
                }
                r
            }
            other => Err(ApiError::new(StatusCode::NOT_FOUND, "unknown_operation", format!("no handler for {other}"))),
        }
    }

    async fn status(self: &Arc<Self>) -> Value {
        let identity = match self.channel().await {
            Ok(ch) => catalog::call_rpc(ch.clone(), "AccountService", "GetIdentity", json!({})).await.ok(),
            Err(_) => None,
        };
        let count = |svc: &'static str, rpc: &'static str, field: &'static str| {
            let me = self.clone();
            async move {
                let ch = me.channel().await.ok()?;
                let v = catalog::call_rpc(ch, svc, rpc, json!({})).await.ok()?;
                Some(v.get(field).and_then(Value::as_array).map(|a| a.len()).unwrap_or(0))
            }
        };
        let (contacts, transfers, groups) = tokio::join!(
            count("FriendService", "GetContacts", "contacts"),
            count("TransferService", "GetTransfers", "transfers"),
            count("GroupService", "GetGroups", "groups"),
        );
        let attached = self.attached.lock().await;
        let ui = |k: &str| {
            attached.get(k).filter(|a| a.last_seen.elapsed() < Duration::from_secs(60)).map(|a| json!({"pid": a.pid, "info": a.info}))
        };
        let facts = self.cfg.facts.lock().map(|f| Value::Object(f.clone())).unwrap_or(json!({}));
        json!({
            "version": self.cfg.version,
            "pid": std::process::id(),
            "uptime_s": self.started.elapsed().as_secs(),
            "started_at": self.started_at,
            "grpc": self.cfg.grpc_url,
            "control": format!("http://{}", self.cfg.bind),
            "daemon_reachable": identity.is_some(),
            "identity": identity.map(|i| json!({"has_identity": i["has_identity"], "display_name": i["display_name"],
                                                "public_key": i["public_key"]})),
            "contacts": contacts, "transfers": transfers, "groups": groups,
            "gui": ui("gui"), "tui": ui("tui"),
            "relays": self.relay_status(),
            "facts": facts,
            "data_dir": data_dir(),
        })
    }

    // ---- user interfaces ----------------------------------------------------------------------------------------
    async fn forward(&self, kind: &str, action: &str, args: Value, timeout: Duration) -> Result<Value, ApiError> {
        let (id, rx) = {
            let mut map = self.attached.lock().await;
            let a = map.get_mut(kind).filter(|a| a.last_seen.elapsed() < Duration::from_secs(60)).ok_or_else(|| {
                ApiError::new(StatusCode::CONFLICT, "not_attached",
                              format!("the {} is not open (start it with {kind}.launch)", if kind == "gui" { "window" } else { "terminal UI" }))
            })?;
            let id = new_token()[..12].to_string();
            let (tx, rx) = oneshot::channel();
            a.pending.insert(id.clone(), tx);
            let _ = a.queue_tx.send(json!({"id": id, "action": action, "args": args}));
            (id, rx)
        };
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(v))) => Ok(v),
            Ok(Ok(Err(e))) => Err(ApiError::new(StatusCode::BAD_REQUEST, "ui_error", e)),
            Ok(Err(_)) => Err(ApiError::new(StatusCode::BAD_GATEWAY, "ui_gone", format!("the {kind} closed before answering"))),
            Err(_) => {
                if let Some(a) = self.attached.lock().await.get_mut(kind) {
                    a.pending.remove(&id);
                }
                Err(ApiError::new(StatusCode::GATEWAY_TIMEOUT, "timeout", format!("the {kind} did not answer in {}s", timeout.as_secs())))
            }
        }
    }

    async fn is_attached(&self, kind: &str) -> bool {
        self.attached.lock().await.get(kind).map(|a| a.last_seen.elapsed() < Duration::from_secs(60)).unwrap_or(false)
    }

    async fn wait_attached(&self, kind: &str, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if self.is_attached(kind).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        false
    }

    async fn launch_gui(self: &Arc<Self>, args: &Value) -> Result<Value, ApiError> {
        let wait = Duration::from_secs_f64(args.get("wait_s").and_then(Value::as_f64).unwrap_or(30.0).clamp(1.0, 300.0));
        if self.is_attached("gui").await {
            let _ = self.forward("gui", "window", json!({"action": "focus"}), Duration::from_secs(10)).await;
            return Ok(json!({"already_open": true, "state": self.forward("gui", "state", json!({}), Duration::from_secs(10)).await.ok()}));
        }
        let exe = sibling("transferd-ui").ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_built", "transferd-ui is not next to transferd (build it: cargo build --release -p transferd-ui)"))?;
        let mut cmd = std::process::Command::new(&exe);
        cmd.env("TRANSFERD_ADDR", &self.cfg.grpc_url).env("RUST_BACKTRACE", "1").stdin(std::process::Stdio::null());
        log_to(&mut cmd, "transferd-ui.log");
        let child = spawn_detached(&mut cmd, false).map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "launch_failed", e.to_string()))?;
        if !self.wait_attached("gui", wait).await {
            return Err(ApiError::new(StatusCode::GATEWAY_TIMEOUT, "timeout", format!("the window (pid {child}) did not attach in {}s", wait.as_secs())));
        }
        Ok(json!({"pid": child, "state": self.forward("gui", "state", json!({}), Duration::from_secs(10)).await.ok()}))
    }

    async fn launch_tui(self: &Arc<Self>, args: &Value) -> Result<Value, ApiError> {
        let headless = args.get("headless").and_then(Value::as_bool).unwrap_or(true);
        let wait = Duration::from_secs_f64(args.get("wait_s").and_then(Value::as_f64).unwrap_or(30.0).clamp(1.0, 300.0));
        if self.is_attached("tui").await {
            return Ok(json!({"already_open": true}));
        }
        let exe = sibling("transferd-tui").ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_built", "transferd-tui is not next to transferd"))?;
        let mut cmd = std::process::Command::new(&exe);
        cmd.env("TRANSFERD_ADDR", &self.cfg.grpc_url);
        if headless {
            let w = args.get("width").and_then(Value::as_u64).unwrap_or(120);
            let h = args.get("height").and_then(Value::as_u64).unwrap_or(40);
            cmd.arg("--headless").arg("--size").arg(format!("{w}x{h}"));
            cmd.stdin(std::process::Stdio::null());
            log_to(&mut cmd, "transferd-tui.log");
        } else if !cfg!(windows) {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "unsupported", "a visible terminal UI can only be opened from here on Windows; run transferd-tui in a terminal, or use headless"));
        }
        let pid = spawn_detached(&mut cmd, !headless).map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "launch_failed", e.to_string()))?;
        if !self.wait_attached("tui", wait).await {
            return Err(ApiError::new(StatusCode::GATEWAY_TIMEOUT, "timeout", format!("the terminal UI (pid {pid}) did not attach in {}s", wait.as_secs())));
        }
        Ok(json!({"pid": pid, "headless": headless, "state": self.forward("tui", "state", json!({}), Duration::from_secs(10)).await.ok()}))
    }

    // ---- local relays -------------------------------------------------------------------------------------------
    fn relay_status(&self) -> Value {
        let mut local = serde_json::Map::new();
        if let Ok(mut map) = self.relays.lock() {
            map.retain(|_, r| matches!(r.child.try_wait(), Ok(None)));
            for (k, r) in map.iter() {
                local.insert(k.clone(), json!({"pid": r.child.id(), "bind": r.bind, "started_at": r.started_at}));
            }
        }
        let configured: Vec<String> = std::env::var("TRANSFERD_RELAY_ADDR")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let available: Vec<&str> = ["relayd", "relayd-ws", "dhtd"].into_iter().filter(|k| sibling(k).is_some()).collect();
        json!({"configured": configured, "dht_bootstrap": std::env::var("TRANSFERD_DHT_BOOTSTRAP").ok(), "local": local,
               "available": available})
    }

    fn relay_start(&self, args: &Value) -> Result<Value, ApiError> {
        let kind = args.get("kind").and_then(Value::as_str).unwrap_or_default();
        if !["relayd", "relayd-ws", "dhtd"].contains(&kind) {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "bad_arguments", "kind is relayd, relayd-ws or dhtd"));
        }
        let mut map = self.relays.lock().map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "lock", "relay table poisoned"))?;
        if let Some(r) = map.get_mut(kind) {
            if matches!(r.child.try_wait(), Ok(None)) {
                return Ok(json!({"already_running": true, "pid": r.child.id(), "bind": r.bind}));
            }
        }
        let exe = sibling(kind).ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_built", format!("{kind} is not next to transferd")))?;
        let default = match kind { "relayd" => "0.0.0.0:7777", "relayd-ws" => "0.0.0.0:8081", _ => "0.0.0.0:7901" };
        let bind = args.get("bind").and_then(Value::as_str).unwrap_or(default).to_string();
        let mut cmd = std::process::Command::new(&exe);
        match kind {
            "relayd" => {
                let port = bind.rsplit(':').next().unwrap_or("7777").to_string();
                cmd.env("RELAYD_PORT", port);
            }
            "relayd-ws" => {
                cmd.env("RELAYD_WS_BIND", &bind);
            }
            _ => {
                cmd.env("DHTD_BIND", &bind);
            }
        }
        if let Some(env) = args.get("env").and_then(Value::as_object) {
            for (k, v) in env {
                let v = v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string());
                cmd.env(k, v);
            }
        }
        let log = std::fs::File::create(data_dir().join(format!("{kind}.log"))).ok();
        cmd.stdin(std::process::Stdio::null());
        match log {
            Some(f) => {
                let f2 = f.try_clone().ok();
                cmd.stdout(f);
                if let Some(f2) = f2 {
                    cmd.stderr(f2);
                }
            }
            None => {
                cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let child = cmd.spawn().map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "launch_failed", e.to_string()))?;
        let pid = child.id();
        map.insert(kind.into(), LocalRelay { child, bind: bind.clone(), started_at: now() });
        Ok(json!({"started": kind, "pid": pid, "bind": bind, "log": data_dir().join(format!("{kind}.log"))}))
    }

    fn relay_stop(&self, args: &Value) -> Result<Value, ApiError> {
        let kind = args.get("kind").and_then(Value::as_str).unwrap_or_default();
        let mut map = self.relays.lock().map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "lock", "relay table poisoned"))?;
        match map.remove(kind) {
            Some(mut r) => {
                let _ = r.child.kill();
                let _ = r.child.wait();
                Ok(json!({"stopped": kind}))
            }
            None => Err(ApiError::new(StatusCode::NOT_FOUND, "not_running", format!("no local {kind} was started from here"))),
        }
    }

    /// Stop the local relays (when the daemon exits).
    pub fn shutdown(&self) {
        if let Ok(mut map) = self.relays.lock() {
            for (_, mut r) in map.drain() {
                let _ = r.child.kill();
            }
        }
        // Only our own discovery file: a daemon started since may already have written its own.
        if crate::client::discover().map(|d| d.pid == std::process::id()).unwrap_or(false) {
            let _ = std::fs::remove_file(discovery_path());
        }
    }
}

/// Send a child's stdout and stderr to a log file in the data folder (so a crash leaves its reason behind).
fn log_to(cmd: &mut std::process::Command, name: &str) {
    match std::fs::File::create(data_dir().join(name)) {
        Ok(f) => {
            if let Ok(f2) = f.try_clone() {
                cmd.stderr(f2);
            }
            cmd.stdout(f);
        }
        Err(_) => {
            cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        }
    }
}

fn redact(v: &mut Value) {
    if let Some(o) = v.as_object_mut() {
        for (k, val) in o.iter_mut() {
            let k = k.to_lowercase();
            if k.contains("phrase") || k.contains("pin") || k.contains("token") || k.contains("secret") || k.contains("password") {
                *val = json!("***");
            } else {
                redact(val);
            }
        }
    }
}

fn daemon_env() -> Value {
    let mut out = serde_json::Map::new();
    for (k, v) in std::env::vars() {
        if (k.starts_with("TRANSFERD_") || k.starts_with("RELAYD_") || k.starts_with("DHTD_")) && !k.contains("TOKEN") {
            out.insert(k, json!(v));
        }
    }
    Value::Object(out)
}

/// A binary installed next to this one (or, in a cargo target folder, next to it).
pub fn sibling(name: &str) -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let p = dir.join(&file);
    p.is_file().then_some(p)
}

/// Start a program that outlives the request (and, on Windows, has no console unless `console`).
pub fn spawn_detached(cmd: &mut std::process::Command, console: bool) -> std::io::Result<u32> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | if console { CREATE_NEW_CONSOLE } else { CREATE_NO_WINDOW });
    }
    let _ = console;
    let child = cmd.spawn()?;
    Ok(child.id())
}

async fn relay_probe(addr: &str) -> Result<Value, ApiError> {
    let bad = |m: String| ApiError::new(StatusCode::BAD_REQUEST, "bad_arguments", m);
    let started = Instant::now();
    if let Some(hp) = addr.strip_prefix("udp://").or_else(|| (!addr.contains("://")).then_some(addr)) {
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(|e| bad(e.to_string()))?;
        sock.connect(hp).await.map_err(|e| bad(format!("{hp}: {e}")))?;
        sock.send(&[0x04]).await.map_err(|e| bad(e.to_string()))?; // a bare Challenge request
        let mut buf = [0u8; 2048];
        return Ok(match tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 && buf[0] == 0x04 => json!({"addr": addr, "ok": true, "kind": "udp relay", "rtt_ms": started.elapsed().as_millis()}),
            Ok(Ok(n)) => json!({"addr": addr, "ok": false, "note": format!("answered with {n} bytes that are not a relay challenge")}),
            Ok(Err(e)) => json!({"addr": addr, "ok": false, "error": e.to_string()}),
            Err(_) => json!({"addr": addr, "ok": false, "error": "no answer in 3 s"}),
        });
    }
    let (tls, rest) = if let Some(r) = addr.strip_prefix("wss://") { (true, r) } else if let Some(r) = addr.strip_prefix("ws://") { (false, r) } else {
        return Err(bad("addr is udp://host:port, ws://host:port or wss://host".into()));
    };
    let hostport = rest.split('/').next().unwrap_or(rest);
    let target = if hostport.contains(':') { hostport.to_string() } else { format!("{hostport}:{}", if tls { 443 } else { 80 }) };
    if !tls {
        return Ok(match tokio::time::timeout(Duration::from_secs(5), tokio_tungstenite::connect_async(addr)).await {
            Ok(Ok(_)) => json!({"addr": addr, "ok": true, "kind": "websocket relay", "rtt_ms": started.elapsed().as_millis()}),
            Ok(Err(e)) => json!({"addr": addr, "ok": false, "error": e.to_string()}),
            Err(_) => json!({"addr": addr, "ok": false, "error": "no answer in 5 s"}),
        });
    }
    Ok(match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(&target)).await {
        Ok(Ok(_)) => json!({"addr": addr, "ok": true, "kind": "wss (TCP reachable; TLS and the WebSocket upgrade are checked by the daemon when it connects)", "rtt_ms": started.elapsed().as_millis()}),
        Ok(Err(e)) => json!({"addr": addr, "ok": false, "error": e.to_string()}),
        Err(_) => json!({"addr": addr, "ok": false, "error": "no answer in 5 s"}),
    })
}

// ---- HTTP ----------------------------------------------------------------------------------------------------------

fn authorize(hub: &Hub, headers: &HeaderMap) -> Result<(), ApiError> {
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        if origin != "null" && !origin.is_empty() {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden", "requests from web pages are not accepted"));
        }
    }
    let given = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-td-token").and_then(|v| v.to_str().ok()))
        .unwrap_or_default();
    if same(given, &hub.token) {
        Ok(())
    } else {
        Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", "missing or wrong token (see control.json)"))
    }
}

fn ops_json() -> Vec<Value> {
    catalog::all().iter().map(|o| serde_json::to_value(o).unwrap_or_default()).collect()
}

async fn health(State(hub): State<Shared>) -> Json<Value> {
    Json(json!({"ok": true, "pid": std::process::id(), "version": hub.cfg.version, "service": "transferdaemon"}))
}

async fn operations(State(hub): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    authorize(&hub, &headers)?;
    Ok(Json(Value::Array(ops_json())))
}

async fn operation(State(hub): State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    authorize(&hub, &headers)?;
    let op = catalog::find(&id).ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "unknown_operation", format!("no operation {id:?}")))?;
    Ok(Json(serde_json::to_value(op).unwrap_or_default()))
}

async fn call(State(hub): State<Shared>, headers: HeaderMap, Path(id): Path<String>, body: Option<Json<Value>>) -> Result<Json<Value>, ApiError> {
    authorize(&hub, &headers)?;
    let args = body.map(|Json(v)| v).unwrap_or(json!({}));
    Ok(Json(json!({"result": hub.call(&id, args).await?})))
}

async fn openapi(State(hub): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    authorize(&hub, &headers)?;
    let mut paths = serde_json::Map::new();
    for o in catalog::all() {
        paths.insert(format!("/v1/call/{}", o.id), json!({"post": {
            "operationId": o.id.replace('.', "_"), "summary": o.summary, "tags": [o.group],
            "requestBody": {"content": {"application/json": {"schema": o.input}}},
            "responses": {"200": {"description": "done", "content": {"application/json": {"schema": {"type": "object", "properties": {"result": o.output}}}}},
                          "4XX": {"description": "error: {error: {code, message}}"}},
        }}));
    }
    Ok(Json(json!({
        "openapi": "3.1.0",
        "info": {"title": "TransferDaemon control", "version": hub.cfg.version},
        "components": {"securitySchemes": {"token": {"type": "http", "scheme": "bearer"}}},
        "security": [{"token": []}],
        "paths": paths,
    })))
}

#[derive(serde::Deserialize, Default)]
struct McpQuery {
    tools: Option<String>,
}

async fn mcp_post(State(hub): State<Shared>, headers: HeaderMap, Query(q): Query<McpQuery>, Json(body): Json<Value>) -> Result<Response, ApiError> {
    authorize(&hub, &headers)?;
    let mode = mcp::Mode::parse(q.tools.as_deref().unwrap_or("all"));
    let ops = ops_json();
    let one = |msg: Value| {
        let hub = hub.clone();
        let ops = ops.clone();
        async move {
            let call = |op: String, args: Value| {
                let hub = hub.clone();
                async move { hub.call(&op, args).await.map_err(|e| format!("{}: {}", e.code, e.message)) }
            };
            mcp::handle(&msg, &ops, mode, call).await
        }
    };
    match body {
        Value::Array(batch) => {
            let mut out = vec![];
            for m in batch {
                if let Some(r) = one(m).await {
                    out.push(r);
                }
            }
            Ok(if out.is_empty() { StatusCode::ACCEPTED.into_response() } else { Json(Value::Array(out)).into_response() })
        }
        msg => Ok(match one(msg).await {
            Some(r) => Json(r).into_response(),
            None => StatusCode::ACCEPTED.into_response(),
        }),
    }
}

async fn attach(State(hub): State<Shared>, headers: HeaderMap, Path(kind): Path<String>, Json(body): Json<Value>) -> Result<Json<Value>, ApiError> {
    authorize(&hub, &headers)?;
    if kind != "gui" && kind != "tui" {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "unknown_kind", "gui or tui"));
    }
    let (tx, rx) = mpsc::unbounded_channel();
    let session = new_token()[..16].to_string();
    let mut map = hub.attached.lock().await;
    map.insert(kind.clone(), Attachment {
        session: session.clone(),
        pid: body.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32,
        info: body.get("info").cloned().unwrap_or(json!({})),
        queue_tx: tx,
        queue_rx: Arc::new(Mutex::new(rx)),
        pending: HashMap::new(),
        last_seen: Instant::now(),
    });
    Ok(Json(json!({"session": session})))
}

#[derive(serde::Deserialize)]
struct SessionQuery {
    session: String,
}

async fn attach_next(State(hub): State<Shared>, headers: HeaderMap, Path(kind): Path<String>, Query(q): Query<SessionQuery>) -> Result<Response, ApiError> {
    authorize(&hub, &headers)?;
    let rx = {
        let mut map = hub.attached.lock().await;
        match map.get_mut(&kind) {
            Some(a) if a.session == q.session => {
                a.last_seen = Instant::now();
                a.queue_rx.clone()
            }
            _ => return Ok(StatusCode::GONE.into_response()),
        }
    };
    let mut rx = rx.lock().await;
    match tokio::time::timeout(Duration::from_secs(25), rx.recv()).await {
        Ok(Some(cmd)) => Ok(Json(cmd).into_response()),
        Ok(None) => Ok(StatusCode::GONE.into_response()),
        Err(_) => {
            if let Some(a) = hub.attached.lock().await.get_mut(&kind) {
                if a.session == q.session {
                    a.last_seen = Instant::now();
                }
            }
            Ok(StatusCode::NO_CONTENT.into_response())
        }
    }
}

async fn attach_reply(State(hub): State<Shared>, headers: HeaderMap, Path(kind): Path<String>, Json(body): Json<Value>) -> Result<StatusCode, ApiError> {
    authorize(&hub, &headers)?;
    let mut map = hub.attached.lock().await;
    let Some(a) = map.get_mut(&kind) else { return Ok(StatusCode::GONE) };
    if body.get("session").and_then(Value::as_str) != Some(a.session.as_str()) {
        return Ok(StatusCode::GONE);
    }
    a.last_seen = Instant::now();
    let id = body.get("id").and_then(Value::as_str).unwrap_or_default();
    if let Some(tx) = a.pending.remove(id) {
        let r = if body.get("ok").and_then(Value::as_bool) == Some(true) {
            Ok(body.get("result").cloned().unwrap_or(Value::Null))
        } else {
            Err(body.get("error").and_then(Value::as_str).unwrap_or("failed").to_string())
        };
        let _ = tx.send(r);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn attach_detach(State(hub): State<Shared>, headers: HeaderMap, Path(kind): Path<String>, Json(body): Json<Value>) -> Result<StatusCode, ApiError> {
    authorize(&hub, &headers)?;
    let mut map = hub.attached.lock().await;
    if map.get(&kind).map(|a| body.get("session").and_then(Value::as_str) == Some(a.session.as_str())).unwrap_or(false) {
        map.remove(&kind);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

async fn audit(State(hub): State<Shared>, headers: HeaderMap, Query(q): Query<AuditQuery>) -> Result<Json<Value>, ApiError> {
    authorize(&hub, &headers)?;
    let text = std::fs::read_to_string(data_dir().join("control-audit.jsonl")).unwrap_or_default();
    let limit = q.limit.unwrap_or(100).min(2000);
    let rows: Vec<Value> = text.lines().rev().take(limit).filter_map(|l| serde_json::from_str(l).ok()).collect();
    Ok(Json(Value::Array(rows)))
}

pub fn router(hub: Shared) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/operations", get(operations))
        .route("/v1/operations/:id", get(operation))
        .route("/v1/call/:id", post(call))
        .route("/v1/openapi.json", get(openapi))
        .route("/v1/audit", get(audit))
        .route("/mcp", post(mcp_post))
        .route("/v1/attach/:kind", post(attach))
        .route("/v1/attach/:kind/next", get(attach_next))
        .route("/v1/attach/:kind/reply", post(attach_reply))
        .route("/v1/attach/:kind/detach", post(attach_detach))
        .with_state(hub)
}

/// Bind, write `control.json`, and serve until `hub.stop` fires. Returns the address it bound (port 0 = any).
pub async fn serve(hub: Shared) -> std::io::Result<SocketAddr> {
    let listener = std::net::TcpListener::bind(hub.cfg.bind)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let server = axum::Server::from_tcp(listener)
        .map_err(std::io::Error::other)?
        .serve(router(hub.clone()).into_make_service());
    let d = Discovery {
        url: format!("http://{addr}"),
        token: hub.token.clone(),
        pid: std::process::id(),
        version: hub.cfg.version.clone(),
        grpc: hub.cfg.grpc_url.clone(),
        started_at: now(),
    };
    write_discovery(&d)?;
    let stop = hub.stop.clone();
    tokio::spawn(async move {
        let graceful = server.with_graceful_shutdown(async move { stop.notified().await });
        if let Err(e) = graceful.await {
            tracing::error!("[control] hub stopped: {e}");
        }
    });
    Ok(addr)
}

fn write_discovery(d: &Discovery) -> std::io::Result<()> {
    let path = discovery_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(d).unwrap_or_default())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, &path)
}
