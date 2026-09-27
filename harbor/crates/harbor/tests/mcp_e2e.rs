//! End-to-end MCP test: spawn the real `harbor` binary, speak JSON-RPC 2.0 over
//! its stdio, and verify the whole policy→capability→result pipeline.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

fn harbor_bin() -> &'static str {
    env!("CARGO_BIN_EXE_harbor")
}

/// Spawn harbor with a fail-closed policy that allows fs.read of a temp root.
struct Harness {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: i64,
    audit_path: std::path::PathBuf,
}

impl Harness {
    fn start(root: &std::path::Path) -> Self {
        let config = root.join("harbor.toml");
        let root_s = root.to_string_lossy().replace('\\', "/");
        let policy = format!(
            "[policy]\ndefault = \"deny\"\n\n[[policy.rules]]\npattern = \"fs.read:{root_s}/**\"\ndecision = \"allow\"\n\n[approval]\nenabled = false\n\n[fs]\nroots = [\"{root_s}\"]\n"
        );
        std::fs::write(&config, policy).unwrap();
        let audit_path = root.join("audit.log");

        let mut child = Command::new(harbor_bin())
            .arg("--config")
            .arg(&config)
            .env("HARBOR_AUDIT_PATH", &audit_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let reader = BufReader::new(child.stdout.take().unwrap());
        let mut harness = Self { child, stdin, reader, next_id: 1, audit_path };
        // Wait for the ready line.
        let _ = harness.read_line();
        harness
    }

    fn read_line(&mut self) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).unwrap();
            if n == 0 {
                panic!("harbor closed stdout");
            }
            let t = line.trim().to_string();
            if !t.is_empty() {
                return t;
            }
            assert!(Instant::now() < deadline, "timed out waiting for output");
        }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.stdin.write_all(format!("{msg}\n").as_bytes()).unwrap();
        self.stdin.flush().unwrap();
        loop {
            let line = self.read_line();
            let v: Value = serde_json::from_str(&line).unwrap_or(json!(null));
            if v.get("id").and_then(Value::as_i64) == Some(id) {
                return v;
            }
        }
    }

    fn close(mut self) {
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

#[test]
fn initialize_negotiates_and_reports_server_info() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = Harness::start(dir.path());
    let resp = h.rpc(
        "initialize",
        json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "test", "version": "0" } }),
    );
    let result = resp.get("result").unwrap();
    assert_eq!(result["serverInfo"]["name"], "harbor");
    assert_eq!(result["protocolVersion"], "2025-06-18");
    h.close();
}

#[test]
fn tools_list_exposes_registered_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = Harness::start(dir.path());
    let resp = h.rpc("tools/list", json!({}));
    let names: Vec<String> = resp["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    for expected in ["fs_read", "fs_write", "fs_list", "fs_stat", "pwsh_run"] {
        assert!(names.contains(&expected.to_string()), "missing tool {expected}: {names:?}");
    }
    h.close();
}

#[test]
fn allowed_fs_read_returns_content_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("note.txt"), "hello from harbor").unwrap();
    let mut h = Harness::start(dir.path());
    let resp = h.rpc(
        "tools/call",
        json!({ "name": "fs_read", "arguments": { "path": dir.path().join("note.txt").to_string_lossy() } }),
    );
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("hello from harbor"));
    h.close();
}

#[test]
fn denied_capability_is_rejected_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = Harness::start(dir.path());
    let resp = h.rpc(
        "tools/call",
        json!({ "name": "pwsh_run", "arguments": { "command": "whoami" } }),
    );
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("denied by policy"), "{text}");
    h.close();
}

#[test]
fn unknown_tool_returns_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = Harness::start(dir.path());
    let resp = h.rpc("tools/call", json!({ "name": "does_not_exist", "arguments": {} }));
    assert_eq!(resp["result"]["isError"], true);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("unknown tool"), "{text}");
    h.close();
}

#[test]
fn unknown_method_returns_jsonrpc_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = Harness::start(dir.path());
    let resp = h.rpc("bogus/method", json!({}));
    assert_eq!(resp["error"]["code"], -32601);
    h.close();
}

#[test]
fn audit_log_records_decisions() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x.txt"), "data").unwrap();
    let mut h = Harness::start(dir.path());
    // An allowed read + a denied pwsh call.
    h.rpc("tools/call", json!({ "name": "fs_read", "arguments": { "path": dir.path().join("x.txt").to_string_lossy() } }));
    h.rpc("tools/call", json!({ "name": "pwsh_run", "arguments": { "command": "whoami" } }));
    drop(h.stdin);
    h.child.wait().unwrap();

    let contents = std::fs::read_to_string(&h.audit_path).unwrap();
    let entries: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    let n = entries.len();
    assert!(n >= 2, "audit should have >=2 entries, got {n}");
    assert!(entries[n - 1].contains("\"capability\":\"pwsh.run\""), "last entry should be the pwsh call");
    assert!(entries[n - 1].contains("\"decision\":\"deny\""));
    assert!(harbor_core::audit::AuditLog::verify(&h.audit_path), "audit chain must verify");
}

#[test]
fn malformed_line_returns_parse_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = Harness::start(dir.path());
    h.stdin.write_all(b"{not json}\n").unwrap();
    h.stdin.flush().unwrap();
    let line = h.read_line();
    let v: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["error"]["code"], -32700);
    h.close();
}