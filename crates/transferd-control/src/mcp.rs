//! The Model Context Protocol server: every operation as a tool.
//!
//! Transport-free: [`handle`] takes one JSON-RPC message and returns the reply (none for notifications). The hub
//! serves it over Streamable HTTP at `/mcp`; `transferd-cli mcp` serves it over stdio and forwards calls to the hub.
//!
//! Two tool sets:
//! * `all` (default): one tool per operation (`messages_send_text`, `gui_click`, ...), each with its own schema.
//! * `compact`: two tools, `transferd_operations` (search the catalog, or one operation's schema) and
//!   `transferd_call` (run one by id), for clients that prefer a short tool list.

use serde_json::{json, Value};
use std::future::Future;

pub const PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    All,
    Compact,
}

impl Mode {
    pub fn parse(s: &str) -> Self {
        if s.eq_ignore_ascii_case("compact") { Self::Compact } else { Self::All }
    }
}

pub fn tool_name(op_id: &str) -> String {
    op_id.replace('.', "_")
}

fn tools(ops: &[Value], mode: Mode) -> Vec<Value> {
    match mode {
        Mode::All => ops
            .iter()
            .map(|o| {
                let id = o["id"].as_str().unwrap_or_default();
                let mut desc = o["summary"].as_str().unwrap_or_default().to_string();
                if o["destructive"].as_bool() == Some(true) {
                    desc.push_str(" (cannot be undone)");
                }
                json!({
                    "name": tool_name(id),
                    "title": id,
                    "description": desc,
                    "inputSchema": o["input"],
                    "annotations": {"readOnlyHint": o["mutating"].as_bool() == Some(false),
                                    "destructiveHint": o["destructive"].as_bool() == Some(true)},
                })
            })
            .collect(),
        Mode::Compact => vec![
            json!({"name": "transferd_operations",
                   "description": "Search TransferDaemon's operations (account, contacts, groups, messages, transfers, connections, settings, calls, telemetry, updates, daemon, gui, tui, relay). With operation: that operation's argument schema.",
                   "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "group": {"type": "string"}, "operation": {"type": "string"}}},
                   "annotations": {"readOnlyHint": true}}),
            json!({"name": "transferd_call",
                   "description": "Run a TransferDaemon operation by id with its arguments (find them with transferd_operations): send messages and files, manage contacts and groups, drive the GUI or TUI, start relays...",
                   "inputSchema": {"type": "object", "properties": {"operation": {"type": "string"}, "args": {"type": "object"}}, "required": ["operation"]}}),
        ],
    }
}

fn content(result: &Value) -> Value {
    if result.get("format").and_then(Value::as_str) == Some("png") {
        if let Some(b64) = result.get("base64").and_then(Value::as_str) {
            let mut meta = result.clone();
            if let Some(o) = meta.as_object_mut() {
                o.remove("base64");
            }
            return json!([{"type": "image", "data": b64, "mimeType": "image/png"}, {"type": "text", "text": meta.to_string()}]);
        }
    }
    let text = serde_json::to_string_pretty(result).unwrap_or_default();
    json!([{"type": "text", "text": text}])
}

fn search(ops: &[Value], args: &Value) -> Value {
    if let Some(id) = args.get("operation").and_then(Value::as_str) {
        return ops.iter().find(|o| o["id"] == id).cloned().unwrap_or_else(|| json!({"error": format!("no operation {id}")}));
    }
    let q: Vec<String> = args.get("query").and_then(Value::as_str).unwrap_or_default().to_lowercase().split_whitespace().map(str::to_string).collect();
    let group = args.get("group").and_then(Value::as_str).unwrap_or_default();
    let hits: Vec<Value> = ops
        .iter()
        .filter(|o| group.is_empty() || o["group"] == group)
        .filter(|o| {
            let hay = format!("{} {}", o["id"].as_str().unwrap_or_default(), o["summary"].as_str().unwrap_or_default()).to_lowercase();
            q.iter().all(|w| hay.contains(w))
        })
        .map(|o| json!({"id": o["id"], "summary": o["summary"], "changes": o["mutating"], "destructive": o["destructive"]}))
        .collect();
    json!(hits)
}

/// Handle one JSON-RPC message. `ops` is the catalog (as JSON); `call` runs an operation.
pub async fn handle<F, Fut>(msg: &Value, ops: &[Value], mode: Mode, call: F) -> Option<Value>
where
    F: Fn(String, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or_default();
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let id = id?; // notifications (no id) get no reply
    let ok = |result: Value| Some(json!({"jsonrpc": "2.0", "id": id.clone(), "result": result}));
    let err = |code: i64, message: String| Some(json!({"jsonrpc": "2.0", "id": id.clone(), "error": {"code": code, "message": message}}));
    match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL_VERSION);
            ok(json!({
                "protocolVersion": asked,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "transferdaemon", "title": "TransferDaemon", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "TransferDaemon: end-to-end encrypted messages, files and calls between devices. Tools cover the daemon's whole API, its window (gui_*) and terminal UI (tui_*), and local relays (relay_*). Read tools change nothing; start with daemon_status.",
            }))
        }
        "ping" => ok(json!({})),
        "tools/list" => ok(json!({"tools": tools(ops, mode)})),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let (op, args) = match (mode, name.as_str()) {
                (Mode::Compact, "transferd_operations") => {
                    return ok(json!({"content": content(&search(ops, &args)), "isError": false}));
                }
                (Mode::Compact, "transferd_call") => (
                    args.get("operation").and_then(Value::as_str).unwrap_or_default().to_string(),
                    args.get("args").cloned().unwrap_or(json!({})),
                ),
                _ => match ops.iter().find(|o| tool_name(o["id"].as_str().unwrap_or_default()) == name) {
                    Some(o) => (o["id"].as_str().unwrap_or_default().to_string(), args),
                    None => return err(-32602, format!("unknown tool {name}")),
                },
            };
            match call(op, args).await {
                Ok(v) => ok(json!({"content": content(&v), "structuredContent": if v.is_object() { v.clone() } else { json!({"result": v}) }, "isError": false})),
                Err(e) => ok(json!({"content": [{"type": "text", "text": e}], "isError": true})),
            }
        }
        "resources/list" => ok(json!({"resources": []})),
        "prompts/list" => ok(json!({"prompts": []})),
        _ => err(-32601, format!("method not found: {method}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops() -> Vec<Value> {
        crate::catalog::all().iter().map(|o| serde_json::to_value(o).unwrap_or_default()).collect()
    }

    #[tokio::test]
    async fn lists_and_calls_tools() {
        let ops = ops();
        let call = |op: String, args: Value| async move { Ok(json!({"op": op, "args": args})) };
        let init = handle(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}), &ops, Mode::All, call).await;
        assert_eq!(init.as_ref().map(|v| v["result"]["protocolVersion"].clone()), Some(json!("2025-03-26")));
        assert!(handle(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}), &ops, Mode::All, call).await.is_none());
        let list = handle(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}), &ops, Mode::All, call).await.unwrap_or_default();
        let tools = list["result"]["tools"].as_array().cloned().unwrap_or_default();
        assert_eq!(tools.len(), ops.len());
        assert!(tools.iter().any(|t| t["name"] == "messages_send_text" && t["annotations"]["readOnlyHint"] == false));
        let r = handle(&json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "gui_click", "arguments": {"target": {"text": "Send"}}}}), &ops, Mode::All, call).await.unwrap_or_default();
        assert_eq!(r["result"]["structuredContent"]["op"], "gui.click");
        let c = handle(&json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "transferd_operations", "arguments": {"query": "send file"}}}), &ops, Mode::Compact, call).await.unwrap_or_default();
        assert!(c["result"]["content"][0]["text"].as_str().unwrap_or_default().contains("transfers.send_file"));
        let bad = handle(&json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "nope"}}), &ops, Mode::All, call).await.unwrap_or_default();
        assert_eq!(bad["error"]["code"], -32602);
    }
}
