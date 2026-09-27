//! The MCP boundary: spec-strict JSON-RPC 2.0 over stdio, newline-delimited.
//!
//! Deliberately hand-rolled (no SDK) so the protocol layer never rots with
//! dependency churn — this is the "100-year" compat story. We speak a RANGE of
//! MCP protocol versions (initialize negotiates the newest common one) and
//! answer unknown methods with proper JSON-RPC errors instead of crashing.

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::AsyncBufReadExt;

use crate::approval::{await_decision, ApprovalOutcome, ApprovalServer};
use crate::config::HarborRuntime;
use harbor_core::capability::{Capability, CapabilityContext};
use harbor_core::policy::Decision;
use harbor_core::redact::Redactor;
use harbor_core::session::Session;

/// MCP protocol versions this server supports, newest first. An old client
/// that only speaks an ancient subset still works (we answer with the newest
/// common version).
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2024-11-05"];

const JSONRPC_VERSION: &str = "2.0";
const SERVER_NAME: &str = "harbor";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A capability registered for the MCP tool surface.
struct ToolCap {
    name: String,
    cap: Arc<dyn Capability>,
}

/// Run the MCP server: read newline-delimited JSON-RPC from stdin, write
/// responses to stdout. Returns when stdin closes (the parent exited).
pub async fn run(runtime: Arc<HarborRuntime>, approval: Option<Arc<ApprovalServer>>) -> std::io::Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut line = String::new();
    let session = Session::new(&runtime.scratch_dir);
    let mut tools = build_tools(&runtime);

    tracing::info!(session = %session.id, "harbor MCP server ready");
    // First-class signal the parent can wait on before speaking to us.
    println!("{}", json!({ "harbor": "ready", "session": session.id, "version": SERVER_VERSION }));

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // Parent closed stdin → shut down cleanly.
            tracing::info!(session = %session.id, "stdin closed, shutting down");
            return Ok(());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed: Result<Value, _> = serde_json::from_str(trimmed);
        let msg = match parsed {
            Ok(v) => v,
            Err(_) => {
                respond_error(None, -32700, "Parse error".into(), None);
                continue;
            }
        };
        handle(&msg, &runtime, &approval, &session, &mut tools).await;
    }
}

fn build_tools(runtime: &HarborRuntime) -> Vec<ToolCap> {
    let mut tools: Vec<ToolCap> = Vec::new();
    // pwsh.run
    let pwsh = runtime.pwsh.clone();
    tools.push(ToolCap { name: tool_name(pwsh.manifest().id), cap: pwsh });
    // fs.*
    for cap in &runtime.fs {
        tools.push(ToolCap { name: tool_name(cap.manifest().id), cap: cap.clone() });
    }
    tools
}

fn tool_name(id: &str) -> String {
    id.replace('.', "_")
}

/// A single request/notification/response message.
async fn handle(msg: &Value, runtime: &Arc<HarborRuntime>, approval: &Option<Arc<ApprovalServer>>, session: &Session, tools: &mut [ToolCap]) {
    let method = msg.get("method").and_then(Value::as_str);
    let id = msg.get("id").cloned();
    match method {
        Some("initialize") => {
            // Version negotiation: pick the newest version both sides support.
            let client_v = msg.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or("");
            let negotiated = PROTOCOL_VERSIONS
                .iter()
                .find(|v| **v == client_v)
                .copied()
                .unwrap_or(PROTOCOL_VERSIONS[0]);
            respond(
                id,
                json!({
                    "protocolVersion": negotiated,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                }),
            );
        }
        Some("notifications/initialized") => {
            // Fire-and-forget; nothing to do (no notifications/ping cadence yet).
            respond(id, json!({}));
        }
        Some("ping") => {
            respond(id, json!({}));
        }
        Some("tools/list") => {
            let list: Vec<Value> = tools
                .iter()
                .map(|t| {
                    let m = t.cap.manifest();
                    json!({
                        "name": t.name,
                        "description": m.description,
                        "inputSchema": m.input_schema,
                    })
                })
                .collect();
            respond(id, json!({ "tools": list }));
        }
        Some("tools/call") => {
            let params = msg.get("params").cloned().unwrap_or(json!({}));
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let mut args = params.get("arguments").cloned().unwrap_or(json!({}));
    // Inject the configured default working directory when a call omits `cwd`.
    if let (Some(cwd), Value::Object(_)) = (&runtime.default_cwd, &args) {
        if args.get("cwd").is_none() {
            args["cwd"] = json!(cwd);
        }
    }
            let req_id = params
                .get("_meta")
                .and_then(|m| m.get("request_id"))
                .and_then(Value::as_str)
                .unwrap_or("?");
            let out = call_tool(tools, name, args, runtime, approval, session, req_id).await;
            respond(id, out);
        }
        Some("shutdown") => {
            respond(id, json!({}));
        }
        Some(m) if m.starts_with("notifications/") => {
            // Notifications have no id; nothing to respond.
        }
        Some(m) => {
            respond_error(id, -32601, format!("Method not found: {m}"), None);
        }
        None => {
            respond_error(id, -32600, "Invalid Request".into(), None);
        }
    }
}

/// Dispatch a tools/call through: policy → (approval) → capability → redaction → audit.
async fn call_tool(
    tools: &[ToolCap],
    name: &str,
    args: Value,
    runtime: &Arc<HarborRuntime>,
    approval: &Option<Arc<ApprovalServer>>,
    session: &Session,
    req_id: &str,
) -> Value {
    let Some(tool) = tools.iter().find(|t| t.name == name) else {
        return call_result_error(format!("unknown tool: {name}"));
    };
    let cap = &tool.cap;
    let manifest = cap.manifest();
    let resource = cap.resource(&args);

    let (decision, matched_rule) = runtime.policy.decide_with_rule(manifest.id, resource.as_deref());

    // ── Approval path ─────────────────────────────────────────────────────
    let approver = match decision {
        Decision::Deny => {
            let rule = matched_rule.map(|r| r.pattern.clone()).unwrap_or_else(|| "default".into());
            audit(runtime, session, req_id, manifest.id, resource.clone(), Decision::Deny, None, None, None, None, Some(format!("denied by rule '{rule}'")));
            return call_result_error(format!("denied by policy (rule '{rule}') — add an allow rule to harbor.toml to permit `{}`", manifest.id));
        }
        Decision::Ask => {
            match approval {
                Some(server) => {
                    let (url, rx) = server.request(manifest.id, resource.as_deref());
                    let hint = format!(
                        "APPROVAL REQUIRED for {} — open {url} within {}s to allow, or close to deny",
                        manifest.id, server_port(server)
                    );
                    // The URL is the secret; surface it on stderr, not in the MCP payload.
                    eprintln!("harbor: {hint}");
                    match await_decision(rx, approval_ttl(server)).await {
                        ApprovalOutcome::Granted => "human".to_string(),
                        ApprovalOutcome::Denied => {
                            audit(runtime, session, req_id, manifest.id, resource.clone(), Decision::Ask, Some("human"), None, None, None, Some("denied by human".into()));
                            return call_result_error("denied by the operator");
                        }
                        ApprovalOutcome::Expired => {
                            audit(runtime, session, req_id, manifest.id, resource.clone(), Decision::Ask, Some("timeout"), None, None, None, Some("approval timed out".into()));
                            return call_result_error("approval timed out");
                        }
                    }
                }
                None => {
                    audit(runtime, session, req_id, manifest.id, resource.clone(), Decision::Ask, None, None, None, None, Some("approval required but disabled".into()));
                    return call_result_error("policy requires approval but the approval server is disabled");
                }
            }
        }
        Decision::Allow => "policy".to_string(),
    };

    // ── Execute ───────────────────────────────────────────────────────────
    let budget = manifest.budget;
    let redactor = runtime.redactor.clone();
    let ctx = CapabilityContext { session: session.clone(), redactor };
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(budget.timeout, cap.invoke(&ctx, args.clone())).await;

    let (payload, error, exit) = match result {
        Ok(Ok(mut v)) => {
            if manifest.secret_sensitive {
                redact_value(&mut v, &runtime.redactor);
            }
            (v, None, None)
        }
        Ok(Err(e)) => {
            let envelope = harbor_core::errors::ErrorEnvelope::from(&e);
            (json!({ "error": envelope }), Some(e.to_string()), None)
        }
        Err(_) => {
            (json!({ "error": { "code": "timeout", "message": format!("capability timed out after {:?}", budget.timeout) } }), Some("timeout".into()), None)
        }
    };
    let duration_ms = started.elapsed().as_millis() as u64;
    let out_sha = harbor_core::redact::sha256(&serde_json::to_vec(&payload).unwrap_or_default());

    audit(runtime, session, req_id, manifest.id, resource.clone(), decision_audit(&decision), Some(&approver), exit, Some(duration_ms), Some(out_sha), error.clone());

    if error.is_some() {
        call_result_error(error.unwrap_or_else(|| "capability failed".into()))
    } else {
        call_result(payload)
    }
}

fn decision_audit(d: &Decision) -> Decision {
    match d {
        Decision::Ask => Decision::Allow, // approved by a human → recorded as allow
        other => *other,
    }
}

#[allow(clippy::too_many_arguments)]
fn audit(
    runtime: &Arc<HarborRuntime>,
    session: &Session,
    req_id: &str,
    capability: &str,
    resource: Option<String>,
    decision: Decision,
    approver: Option<&str>,
    exit: Option<i32>,
    duration_ms: Option<u64>,
    out_sha: Option<String>,
    error: Option<String>,
) {
    let b = harbor_core::audit::EntryBuilder { session_id: session.id.clone(), request_id: req_id.to_string() };
    let entry = b.build(capability, resource, decision, approver, exit, duration_ms, out_sha, error);
    let _ = runtime.audit.append(entry);
}

fn approval_ttl(server: &ApprovalServer) -> u64 {
    server.ttl()
}

fn server_port(server: &ApprovalServer) -> u16 {
    server.port()
}

/// Redact every string field in a result JSON (recursively).
fn redact_value(v: &mut Value, redactor: &Redactor) {
    match v {
        Value::String(s) => *s = redactor.redact(s),
        Value::Array(arr) => {
            for item in arr {
                redact_value(item, redactor);
            }
        }
        Value::Object(map) => {
            for (_, item) in map {
                redact_value(item, redactor);
            }
        }
        _ => {}
    }
}

fn call_result(payload: Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": payload.to_string() }],
        "isError": false,
    })
}

fn call_result_error(message: impl Into<String>) -> Value {
    json!({
        "content": [{ "type": "text", "text": message.into() }],
        "isError": true,
    })
}

fn rpc_error(code: i64, message: String, data: Option<Value>) -> Value {
    let mut e = json!({ "code": code, "message": message });
    if let Some(d) = data {
        e["data"] = d;
    }
    e
}

fn respond(id: Option<Value>, result: Value) {
    write_json(json!({ "jsonrpc": JSONRPC_VERSION, "id": id.unwrap_or(Value::Null), "result": result }));
}

/// JSON-RPC error response (no `result` field, per spec).
fn respond_error(id: Option<Value>, code: i64, message: String, data: Option<Value>) {
    write_json(json!({ "jsonrpc": JSONRPC_VERSION, "id": id.unwrap_or(Value::Null), "error": rpc_error(code, message, data) }));
}

/// Write one response frame to stdout (the protocol channel). Never logs here.
fn write_json(v: Value) {
    println!("{v}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use harbor_core::policy::{PolicyEngine, PolicyRule};
    use harbor_core::redact::Redactor;
    use std::sync::Arc;

    fn test_runtime() -> Arc<HarborRuntime> {
        // A tiny runtime with an in-memory policy that allows fs.read of a
        // temp dir and denies everything else.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_string_lossy().replace('\\', "/");
        let cfg = crate::config::HarborConfig {
            fs: crate::config::FsSection {
                roots: vec![root.clone()],
                deny: Vec::new(),
                max_read_bytes: 4096,
            },
            ..Default::default()
        };
        let mut runtime = crate::config::build_runtime(&cfg);
        let mut policy = PolicyEngine::new(harbor_core::policy::Decision::Deny);
        policy.add_rule(PolicyRule::new(format!("fs.read:{root}/**"), harbor_core::policy::Decision::Allow));
        runtime.policy = policy;
        Arc::new(runtime)
    }

    #[test]
    fn tool_names_map_from_capability_ids() {
        assert_eq!(tool_name("pwsh.run"), "pwsh_run");
        assert_eq!(tool_name("fs.read"), "fs_read");
    }

    #[test]
    fn redaction_reaches_nested_strings() {
        let mut v = json!({ "stdout": "password=hunter2", "nested": { "a": "Bearer abc123" } });
        redact_value(&mut v, &Redactor::default());
        assert_eq!(v["stdout"], "[REDACTED]");
        assert_eq!(v["nested"]["a"], "Bearer [REDACTED]");
    }

    #[tokio::test]
    async fn denied_capability_returns_clean_error() {
        let runtime = test_runtime();
        let tool = ToolCap { name: "pwsh_run".into(), cap: runtime.pwsh.clone() };
        let out = call_tool(&[tool], "pwsh_run", json!({ "command": "whoami" }), &runtime, &None, &Session::new(std::path::Path::new(".")), "r1").await;
        assert!(out["isError"].as_bool().unwrap());
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("denied by policy"), "{text}");
    }

    #[tokio::test]
    async fn allowed_fs_read_returns_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        let cfg = crate::config::HarborConfig {
            fs: crate::config::FsSection {
                roots: vec![dir.path().to_string_lossy().into_owned()],
                deny: Vec::new(),
                max_read_bytes: 4096,
            },
            ..Default::default()
        };
        let mut runtime = crate::config::build_runtime(&cfg);
        let root = dir.path().to_string_lossy().replace('\\', "/");
        let mut policy = PolicyEngine::new(harbor_core::policy::Decision::Deny);
        policy.add_rule(PolicyRule::new(format!("fs.read:{root}/**"), harbor_core::policy::Decision::Allow));
        runtime.policy = policy;
        let runtime = Arc::new(runtime);
        let tool = ToolCap { name: "fs_read".into(), cap: runtime.fs[0].clone() };
        let out = call_tool(&[tool], "fs_read", json!({ "path": dir.path().join("a.txt").to_string_lossy() }), &runtime, &None, &Session::new(std::path::Path::new(".")), "r2").await;
        assert!(!out["isError"].as_bool().unwrap(), "{out}");
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("hello"));
    }
}