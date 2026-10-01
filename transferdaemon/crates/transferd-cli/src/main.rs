//! `transferd-cli`: TransferDaemon from the command line, scripts, and MCP clients.
//!
//! Every command goes through the running daemon's control hub (found through `control.json`), so the CLI can do
//! everything the daemon can: messages, files, contacts, groups, connections, settings, calls, telemetry, updates,
//! the window (`gui ...`), the terminal UI (`tui ...`) and local relays. `transferd-cli mcp` serves all of it to MCP
//! clients over stdio.

use serde_json::{json, Map, Value};
use std::io::{BufRead, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use transferd_control::{mcp, Client, ClientError};

mod cat;
mod ghostkey;
mod replica;
mod rns;

const HELP: &str = "transferd-cli: TransferDaemon from the command line

USAGE
  transferd-cli [--json] <command> [arguments]

EVERYDAY
  status                          the daemon: identity, contacts, transfers, the window, relays
  id                              this device's public key (what friends add)
  contacts                        every contact (online, blocked, address)
  add <public-key> <name> [addr]  add a contact (addr: host:port of their listener, optional)
  address <contact> <addr|->      set (or clear with -) a contact's direct address
  send <contact> <text...>        send a message (contact: name, id or id prefix)
  send-file <contact> <path>      send a file
  messages <contact> [query]      the conversation (or search it)
  transfers                       file transfers
  pause|resume|cancel <transfer>  control a transfer
  groups                          groups
  group-send <group> <text...>    message a group
  connections                     network paths, speed, policy
  settings get <key> | set <key> <value>
  telemetry [seconds]             live telemetry
  audit [n]                       the last changes made through the control hub

EVERYTHING
  ops [words...] [--group g]      search the operations (daemon API, gui, tui, relay)
  op <id>                         one operation's arguments (JSON Schema)
  call <id> [JSON | key=value...] run any operation

WINDOW AND TERMINAL UI
  gui <action> [JSON | key=value...]   launch, state, inspect, find, click, set, type, key, navigate,
                                       open_chat, scroll, screenshot [--out file.png], window, wait
  tui <action> [JSON | key=value...]   launch, state, screen, key, type, navigate, resize, quit

CAT (netcat between two machines: a one-time address, post-quantum encryption, direct or through a relay)
  cat listen [--relay host:port]  prints a tdcat: address, then pipes stdin/stdout with whoever dials it
  cat <tdcat:address>             dials it

RETICULUM (LXMF messaging off-grid and over any link: TCP, the LAN, LoRa radios; Crosstalk / MeshChat users)
  rns setup | start [--listen h:p] [--connect h:p] [--auto] [--rnode PORT ...] | status | interfaces | peers
  rns announce | send <address> <text...> [--title t] [--propagated] [--wait] | inbox | propagation <node|off> | stop

REPLICA (state replicated across your devices with Raft, applied to SQLite: strongly consistent SQL)
  replica start --id N --peers 1=h:p,2=h:p,3=h:p [--cluster c] [--data dir]   run this device's replica
  replica exec <h:p> <SQL> | query <h:p> <SELECT ...> | status <h:p>

GHOST KEYS (anonymous identities an issuer vouches for without learning them; no daemon needed)
  ghostkey issuer-new <name> <tier> <prefix> [--bits 3072]   ghostkey request <issuer-file> <pending-file>
  ghostkey sign <issuer-secret-file> <blinded>              ghostkey finish <issuer-file> <pending> <sig> <out>
  ghostkey verify <issuer-file> <certificate>

RELAYS
  relay status | start <relayd|relayd-ws|dhtd> [bind] | stop <kind> | probe <addr>

THE DAEMON
  daemon start [--wait s]         start transferd (next to this program) if it is not running
  daemon stop                     stop it
  mcp [--tools all|compact]       serve every operation to an MCP client over stdio

Options: --json prints raw JSON. key=value values are parsed as JSON when they can be (numbers, true, {...});
dotted keys build objects (target.text=Send).
Environment: TRANSFERD_DATA_DIR (where control.json is), TRANSFERD_CONTROL_URL + TRANSFERD_CONTROL_TOKEN.";

struct Out {
    json: bool,
}

impl Out {
    fn print(&self, v: &Value) {
        if self.json {
            println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
            return;
        }
        match v {
            Value::String(s) => println!("{s}"),
            Value::Null => {}
            other => println!("{}", pretty(other, 0)),
        }
    }
}

/// A readable rendering: objects as `key: value` lines, arrays as blocks, big blobs shortened.
fn pretty(v: &Value, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    match v {
        Value::Object(o) if o.is_empty() => format!("{pad}(done)"),
        Value::Object(o) => o
            .iter()
            .filter(|(k, _)| k.as_str() != "base64")
            .map(|(k, v)| match v {
                Value::Object(_) | Value::Array(_) if !is_small(v) => format!("{pad}{k}:\n{}", pretty(v, indent + 1)),
                _ => format!("{pad}{k}: {}", inline(v)),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Array(a) if a.is_empty() => format!("{pad}(none)"),
        Value::Array(a) => a
            .iter()
            .map(|x| if is_small(x) { format!("{pad}- {}", inline(x)) } else { format!("{pad}-\n{}", pretty(x, indent + 1)) })
            .collect::<Vec<_>>()
            .join("\n"),
        other => format!("{pad}{}", inline(other)),
    }
}

fn is_small(v: &Value) -> bool {
    match v {
        Value::Object(o) => o.values().all(|x| !x.is_object() && !x.is_array()) && inline(v).len() < 100,
        Value::Array(a) => a.iter().all(|x| !x.is_object() && !x.is_array()) && inline(v).len() < 100,
        _ => true,
    }
}

fn inline(v: &Value) -> String {
    match v {
        Value::String(s) if s.len() > 200 => {
            let cut = s.char_indices().nth(120).map(|(i, _)| i).unwrap_or(s.len());
            format!("{}... ({} chars)", &s[..cut], s.len())
        }
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `JSON` or `key=value ...` into an arguments object.
fn parse_args(rest: &[String]) -> Result<Value, String> {
    if rest.is_empty() {
        return Ok(json!({}));
    }
    if rest.len() == 1 && rest[0].trim_start().starts_with('{') {
        return serde_json::from_str(&rest[0]).map_err(|e| format!("bad JSON: {e}"));
    }
    let mut m = Map::new();
    for kv in rest {
        let (k, v) = kv.split_once('=').ok_or_else(|| format!("expected key=value, got {kv:?}"))?;
        let parsed = serde_json::from_str::<Value>(v).unwrap_or_else(|_| Value::String(v.to_string()));
        let parts: Vec<&str> = k.split('.').collect();
        let mut cur = &mut m;
        for (i, p) in parts.iter().enumerate() {
            if i + 1 == parts.len() {
                cur.insert((*p).to_string(), parsed.clone());
            } else {
                cur = cur
                    .entry((*p).to_string())
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .ok_or_else(|| format!("{p} is both a value and an object"))?;
            }
        }
    }
    Ok(Value::Object(m))
}

fn fail(e: ClientError) -> String {
    e.to_string()
}

/// A contact by name, id or id prefix.
fn contact_id(c: &Client, r: &str) -> Result<String, String> {
    let v = c.call("contacts.get_contacts", json!({})).map_err(fail)?;
    let list = v["contacts"].as_array().cloned().unwrap_or_default();
    let rl = r.to_lowercase();
    let hit = list
        .iter()
        .find(|x| x["id"] == r || x["name"].as_str().map(str::to_lowercase).as_deref() == Some(rl.as_str()))
        .or_else(|| {
            let prefix: Vec<&Value> = list.iter().filter(|x| x["id"].as_str().unwrap_or_default().starts_with(r)).collect();
            (prefix.len() == 1).then(|| prefix[0])
        });
    hit.and_then(|x| x["id"].as_str().map(str::to_string)).ok_or_else(|| {
        let names: Vec<&str> = list.iter().filter_map(|x| x["name"].as_str()).collect();
        format!("no contact {r:?} (contacts: {})", if names.is_empty() { "none".into() } else { names.join(", ") })
    })
}

fn group_id(c: &Client, r: &str) -> Result<String, String> {
    let v = c.call("groups.get_groups", json!({})).map_err(fail)?;
    let rl = r.to_lowercase();
    v["groups"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .find(|g| g["group_id"] == r || g["name"].as_str().map(str::to_lowercase).as_deref() == Some(rl.as_str()))
        .and_then(|g| g["group_id"].as_str().map(str::to_string))
        .ok_or_else(|| format!("no group {r:?}"))
}

fn sibling(name: &str) -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = exe.parent()?.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    p.is_file().then_some(p)
}

fn daemon_start(wait: f64) -> Result<Value, String> {
    if let Ok(c) = Client::connect() {
        if let Ok(h) = c.health() {
            return Ok(json!({"already_running": true, "pid": h["pid"]}));
        }
    }
    let exe = sibling("transferd").ok_or("transferd is not next to transferd-cli")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.creation_flags(0x0800_0000 | 0x0000_0200); // no console window, its own process group
    }
    let child = cmd.spawn().map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs_f64(wait);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(300));
        if let Ok(c) = Client::connect() {
            if c.health().map(|h| h["pid"] == child.id()).unwrap_or(false) {
                return Ok(json!({"started": true, "pid": child.id()}));
            }
        }
    }
    Err(format!("transferd (pid {}) did not come up in {wait}s", child.id()))
}

fn mcp_stdio(mode: mcp::Mode) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut ops: Option<Vec<Value>> = None;
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}});
                writeln!(stdout, "{err}").map_err(|e| e.to_string())?;
                stdout.flush().ok();
                continue;
            }
        };
        // The catalog comes from the hub; if the daemon is not running yet, answer with none and ask again later.
        if ops.as_ref().map(Vec::is_empty).unwrap_or(true) {
            ops = Client::connect().and_then(|c| c.operations()).ok();
        }
        let catalog = ops.clone().unwrap_or_default();
        let call = |op: String, args: Value| async move {
            let c = Client::connect().map_err(fail)?;
            c.call(&op, args).map_err(fail)
        };
        if let Some(r) = rt.block_on(mcp::handle(&msg, &catalog, mode, call)) {
            writeln!(stdout, "{r}").map_err(|e| e.to_string())?;
            stdout.flush().ok();
        }
    }
    Ok(())
}

fn flag_value(rest: &[String], flag: &str) -> Option<String> {
    rest.iter().position(|a| a == flag).and_then(|i| rest.get(i + 1)).cloned()
}

/// `rest` without `flag` and the value after it.
fn without_flag(rest: &[String], flag: &str) -> Vec<String> {
    let mut out = vec![];
    let mut skip = false;
    for a in rest {
        if skip {
            skip = false;
            continue;
        }
        if a == flag {
            skip = true;
            continue;
        }
        out.push(a.clone());
    }
    out
}

fn run(args: Vec<String>, out: &Out) -> Result<Option<Value>, String> {
    let Some(cmd) = args.first().map(String::as_str) else {
        println!("{HELP}");
        return Ok(None);
    };
    let rest = &args[1..];
    let need = |n: usize, usage: &str| if rest.len() < n { Err(format!("usage: transferd-cli {usage}")) } else { Ok(()) };
    match cmd {
        "help" | "-h" | "--help" => {
            println!("{HELP}");
            Ok(None)
        }
        "mcp" => {
            let mode = flag_value(rest, "--tools").map(|m| mcp::Mode::parse(&m)).unwrap_or(mcp::Mode::All);
            mcp_stdio(mode)?;
            Ok(None)
        }
        "ghostkey" => ghostkey::run(rest).map(Some),
        "replica" => replica::run(rest).map(Some),
        "rns" => rns::run(rest).map(Some),
        "cat" => cat::run(rest).map(|v| {
            eprintln!("{v}");
            None
        }),
        "daemon" => match rest.first().map(String::as_str) {
            Some("start") => daemon_start(flag_value(rest, "--wait").and_then(|w| w.parse().ok()).unwrap_or(60.0)).map(Some),
            Some("stop") => Client::connect().and_then(|c| c.call("daemon.stop", json!({}))).map(Some).map_err(fail),
            Some("status") | None => Client::connect().and_then(|c| c.call("daemon.status", json!({}))).map(Some).map_err(fail),
            Some(other) => Err(format!("daemon start|stop|status, not {other}")),
        },
        _ => {
            let c = Client::connect().map_err(fail)?;
            let call = |op: &str, a: Value| c.call(op, a).map(Some).map_err(fail);
            match cmd {
                "status" => call("daemon.status", json!({})),
                "id" => call("account.get_public_key_hex", json!({})).map(|v| v.map(|v| v["hex"].clone())),
                "contacts" => call("contacts.get_contacts", json!({})).map(|v| v.map(|v| v["contacts"].clone())),
                "add" => {
                    need(2, "add <public-key> <name> [address]")?;
                    call("contacts.add_contact", json!({"public_key": rest[0], "name": rest[1], "address": rest.get(2).cloned().unwrap_or_default()}))
                }
                "address" => {
                    need(2, "address <contact> <host:port | ->")?;
                    let id = contact_id(&c, &rest[0])?;
                    let addr = if rest[1] == "-" { String::new() } else { rest[1].clone() };
                    call("contacts.set_contact_address", json!({"contact_id": id, "address": addr}))
                }
                "send" => {
                    need(2, "send <contact> <text...>")?;
                    let id = contact_id(&c, &rest[0])?;
                    call("messages.send_text", json!({"contact_id": id, "text": rest[1..].join(" ")}))
                }
                "send-file" => {
                    need(2, "send-file <contact> <path>")?;
                    let id = contact_id(&c, &rest[0])?;
                    call("transfers.send_file", json!({"contact_id": id, "file_path": rest[1]}))
                }
                "messages" => {
                    need(1, "messages <contact> [query]")?;
                    let id = contact_id(&c, &rest[0])?;
                    let v = if rest.len() > 1 {
                        c.call("messages.search_messages", json!({"contact_id": id, "query": rest[1..].join(" ")}))
                    } else {
                        c.call("messages.get_messages", json!({"contact_id": id}))
                    }
                    .map_err(fail)?;
                    if out.json {
                        return Ok(Some(v));
                    }
                    for m in v["messages"].as_array().cloned().unwrap_or_default() {
                        let who = if m["outbound"] == true { "you" } else { "them" };
                        let body = if m["content_type"] == "file" { format!("[file] {}", inline(&m["file_name"])) } else { inline(&m["text"]) };
                        println!("{who:>4}  {body}  [{}]", inline(&m["status"]));
                    }
                    Ok(None)
                }
                "transfers" => call("transfers.get_transfers", json!({})).map(|v| v.map(|v| v["transfers"].clone())),
                "pause" | "resume" | "cancel" => {
                    need(1, &format!("{cmd} <transfer-id>"))?;
                    call(&format!("transfers.{cmd}_transfer"), json!({"transfer_id": rest[0]}))
                }
                "groups" => call("groups.get_groups", json!({})).map(|v| v.map(|v| v["groups"].clone())),
                "group-send" => {
                    need(2, "group-send <group> <text...>")?;
                    let id = group_id(&c, &rest[0])?;
                    call("groups.send_group_text", json!({"group_id": id, "text": rest[1..].join(" ")}))
                }
                "connections" => call("connections.list_connections", json!({})).map(|v| v.map(|v| v["connections"].clone())),
                "settings" => match rest.first().map(String::as_str) {
                    Some("get") => {
                        need(2, "settings get <key>")?;
                        call("settings.get_setting", json!({"key": rest[1]}))
                    }
                    Some("set") => {
                        need(3, "settings set <key> <value>")?;
                        call("settings.set_setting", json!({"key": rest[1], "value": rest[2..].join(" ")}))
                    }
                    _ => Err("settings get <key> | settings set <key> <value>".into()),
                },
                "telemetry" => {
                    let secs: f64 = rest.first().and_then(|s| s.parse().ok()).unwrap_or(5.0);
                    call("telemetry.stream_telemetry", json!({"seconds": secs}))
                }
                "audit" => {
                    let n: usize = rest.first().and_then(|s| s.parse().ok()).unwrap_or(30);
                    c.get(&format!("/v1/audit?limit={n}")).map(Some).map_err(fail)
                }
                "ops" => {
                    let group = flag_value(rest, "--group");
                    let words: Vec<String> = without_flag(rest, "--group").iter().map(|a| a.to_lowercase()).collect();
                    let hits: Vec<Value> = c
                        .operations()
                        .map_err(fail)?
                        .into_iter()
                        .filter(|o| group.as_ref().map(|g| o["group"] == g.as_str()).unwrap_or(true))
                        .filter(|o| {
                            let hay = format!("{} {}", inline(&o["id"]), inline(&o["summary"])).to_lowercase();
                            words.iter().all(|w| hay.contains(w.as_str()))
                        })
                        .collect();
                    if out.json {
                        return Ok(Some(Value::Array(hits)));
                    }
                    for o in hits {
                        let mark = if o["destructive"] == true { "!" } else if o["mutating"] == true { "*" } else { " " };
                        println!("{mark} {:<36} {}", inline(&o["id"]), inline(&o["summary"]));
                    }
                    println!("\n  * changes something   ! cannot be undone");
                    Ok(None)
                }
                "op" => {
                    need(1, "op <id>")?;
                    c.get(&format!("/v1/operations/{}", rest[0])).map(Some).map_err(fail)
                }
                "call" => {
                    need(1, "call <id> [JSON | key=value...]")?;
                    call(&rest[0], parse_args(&rest[1..])?)
                }
                "gui" | "tui" => {
                    need(1, &format!("{cmd} <action> [JSON | key=value...]"))?;
                    let out_file = flag_value(rest, "--out");
                    let plain = without_flag(&rest[1..], "--out");
                    let v = c.call(&format!("{cmd}.{}", rest[0]), parse_args(&plain)?).map_err(fail)?;
                    if cmd == "tui" && rest[0] == "screen" && !out.json {
                        println!("{}", v["text"].as_str().unwrap_or_default());
                        return Ok(None);
                    }
                    if let (Some(path), Some(b64)) = (out_file, v.get("base64").and_then(Value::as_str)) {
                        std::fs::write(&path, decode_base64(b64)?).map_err(|e| e.to_string())?;
                        return Ok(Some(json!({"saved": path, "width": v["width"], "height": v["height"]})));
                    }
                    Ok(Some(v))
                }
                "relay" => match rest.first().map(String::as_str) {
                    Some("status") | None => call("relay.status", json!({})),
                    Some("start") => {
                        need(2, "relay start <relayd|relayd-ws|dhtd> [bind]")?;
                        let mut a = json!({"kind": rest[1]});
                        if let Some(b) = rest.get(2) {
                            a["bind"] = json!(b);
                        }
                        call("relay.start", a)
                    }
                    Some("stop") => {
                        need(2, "relay stop <kind>")?;
                        call("relay.stop", json!({"kind": rest[1]}))
                    }
                    Some("probe") => {
                        need(2, "relay probe <addr>")?;
                        call("relay.probe", json!({"addr": rest[1]}))
                    }
                    Some(other) => Err(format!("relay status|start|stop|probe, not {other}")),
                },
                other => Err(format!("unknown command {other:?} (transferd-cli help)")),
            }
        }
    }
}

fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut map = [255u8; 256];
    for (i, c) in T.iter().enumerate() {
        map[*c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = map[c as usize];
        if v == 255 {
            return Err("bad base64".into());
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let json = match args.iter().position(|a| a == "--json") {
        Some(i) => {
            args.remove(i);
            true
        }
        None => false,
    };
    let out = Out { json };
    match run(args, &out) {
        Ok(Some(v)) => {
            out.print(&v);
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_values_become_arguments() {
        let v = parse_args(&["target.text=Send".into(), "double=true".into(), "n=3".into(), "s=hi there".into()]).unwrap_or_default();
        assert_eq!(v, json!({"target": {"text": "Send"}, "double": true, "n": 3, "s": "hi there"}));
        assert_eq!(parse_args(&[r#"{"a": 1}"#.into()]).unwrap_or_default(), json!({"a": 1}));
        assert!(parse_args(&["novalue".into()]).is_err());
    }

    #[test]
    fn base64_decodes() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap_or_default(), b"hello");
    }

    #[test]
    fn flags_are_taken_out() {
        let a: Vec<String> = ["x", "--out", "f.png", "y"].iter().map(|s| s.to_string()).collect();
        assert_eq!(flag_value(&a, "--out").as_deref(), Some("f.png"));
        assert_eq!(without_flag(&a, "--out"), vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn pretty_prints() {
        let s = pretty(&json!({"a": 1, "b": [1, 2], "c": {"d": "x"}}), 0);
        assert!(s.contains("a: 1") && s.contains("c: {\"d\":\"x\"}"));
    }
}
