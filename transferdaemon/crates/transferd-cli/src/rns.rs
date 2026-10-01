//! `transferd-cli rns ...`: Reticulum and LXMF from TransferD (Crosstalk / Reticulum MeshChat parity), through the
//! bridge in bridges/rns (the reference Reticulum stack, in a process and a configuration of its own).
//!
//!   rns setup [--python exe]          a Python environment with rns and lxmf (downloads them from PyPI)
//!   rns start [--name n] [--listen host:port]... [--connect host:port]... [--auto]
//!             [--rnode PORT --freq HZ --bw HZ --sf N --cr N --txpower DBM]
//!   rns status | interfaces | peers | announce | stop
//!   rns send <lxmf address> <text...> [--title t] [--propagated] [--wait]
//!   rns inbox [--since unix-seconds]
//!   rns propagation <node address | off>
//!
//! Where: TRANSFERD_RNS_DIR, else <TRANSFERD_DATA_DIR, else the per-user data folder>/rns. The Python is
//! TRANSFERD_RNS_PYTHON, else the environment `rns setup` made there.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BRIDGE: &str = include_str!("../../../bridges/rns/transferd_rns_bridge.py");

fn home() -> PathBuf {
    if let Some(d) = std::env::var_os("TRANSFERD_RNS_DIR") {
        return PathBuf::from(d);
    }
    let base = std::env::var_os("TRANSFERD_DATA_DIR").map(PathBuf::from).unwrap_or_else(|| {
        let local = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("XDG_DATA_HOME")).map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share"));
        local.join("transferdaemon")
    });
    base.join("rns")
}

fn venv_python(h: &Path) -> PathBuf {
    if let Some(p) = std::env::var_os("TRANSFERD_RNS_PYTHON") {
        return PathBuf::from(p);
    }
    if cfg!(windows) { h.join("venv").join("Scripts").join("python.exe") } else { h.join("venv").join("bin").join("python") }
}

fn flag(rest: &[String], name: &str) -> Option<String> {
    rest.iter().position(|a| a == name).and_then(|i| rest.get(i + 1)).cloned()
}

fn flags(rest: &[String], name: &str) -> Vec<String> {
    rest.iter().enumerate().filter(|(_, a)| *a == name).filter_map(|(i, _)| rest.get(i + 1).cloned()).collect()
}

fn control(h: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(h.join("data").join("control.json"))
        .map_err(|_| "the Reticulum bridge is not running: `transferd-cli rns start`".to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn call(h: &Path, op: &str, args: Value) -> Result<Value, String> {
    let ctl = control(h)?;
    let port = ctl["port"].as_u64().ok_or("control.json has no port")?;
    let mut s = TcpStream::connect(("127.0.0.1", port as u16))
        .map_err(|e| format!("the Reticulum bridge does not answer ({e}): `transferd-cli rns start`"))?;
    s.set_read_timeout(Some(Duration::from_secs(90))).map_err(|e| e.to_string())?;
    let mut req = json!({"token": ctl["token"], "op": op});
    if let (Some(r), Some(a)) = (req.as_object_mut(), args.as_object()) {
        r.extend(a.clone());
    }
    s.write_all(format!("{req}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&line).map_err(|e| format!("the bridge said {line:?}: {e}"))?;
    match v.get("error") {
        Some(e) => Err(e.as_str().unwrap_or("error").to_string()),
        None => Ok(v["result"].clone()),
    }
}

fn setup(h: &Path, python: Option<String>) -> Result<Value, String> {
    std::fs::create_dir_all(h).map_err(|e| e.to_string())?;
    let py = python.unwrap_or_else(|| if cfg!(windows) { "python".into() } else { "python3".into() });
    let venv = h.join("venv");
    let run = |cmd: &mut Command| -> Result<(), String> {
        let st = cmd.status().map_err(|e| e.to_string())?;
        if st.success() { Ok(()) } else { Err(format!("{cmd:?} failed")) }
    };
    if !venv_python(h).exists() {
        run(Command::new(&py).arg("-m").arg("venv").arg(&venv))?;
    }
    run(Command::new(venv_python(h)).args(["-m", "pip", "install", "-q", "--upgrade", "rns>=1.3.5", "lxmf>=0.9.3"]))?;
    Ok(json!({"python": venv_python(h), "installed": ["rns", "lxmf"]}))
}

fn start(h: &Path, rest: &[String]) -> Result<Value, String> {
    if let Ok(v) = call(h, "status", json!({})) {
        return Ok(json!({"already_running": true, "status": v}));
    }
    let py = venv_python(h);
    if !py.exists() {
        return Err(format!("no Python with Reticulum at {}: `transferd-cli rns setup`", py.display()));
    }
    let script = h.join("transferd_rns_bridge.py");
    std::fs::create_dir_all(h).map_err(|e| e.to_string())?;
    std::fs::write(&script, BRIDGE).map_err(|e| e.to_string())?;
    let data = h.join("data");
    let _ = std::fs::remove_file(data.join("control.json"));
    let mut cmd = Command::new(&py);
    cmd.arg(&script).arg("--data").arg(&data).arg("--name").arg(flag(rest, "--name").unwrap_or_else(|| "TransferD".into()));
    for l in flags(rest, "--listen") {
        cmd.arg("--listen").arg(l);
    }
    for c in flags(rest, "--connect") {
        cmd.arg("--connect").arg(c);
    }
    if rest.iter().any(|a| a == "--auto") {
        cmd.arg("--auto");
    }
    for f in ["--rnode", "--freq", "--bw", "--sf", "--cr", "--txpower"] {
        if let Some(v) = flag(rest, f) {
            cmd.arg(f).arg(v);
        }
    }
    std::fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    let log = std::fs::File::create(h.join("bridge.log")).map_err(|e| e.to_string())?;
    let err = log.try_clone().map_err(|e| e.to_string())?;
    cmd.stdin(Stdio::null()).stdout(log).stderr(err);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000 | 0x0000_0008); // no window, detached: it outlives this command
    }
    // the bridge outlives this command: it must not inherit our stdout/stderr (a caller reading our output would
    // otherwise wait for an end that only comes when the bridge stops)
    #[cfg(windows)]
    no_inherit_std_handles();
    let child = cmd.spawn().map_err(|e| e.to_string())?;
    let end = Instant::now() + Duration::from_secs(30);
    while Instant::now() < end {
        if let Ok(v) = call(h, "status", json!({})) {
            return Ok(json!({"started": child.id(), "status": v}));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!("the bridge did not start; see {}", h.join("bridge.log").display()))
}

#[cfg(windows)]
fn no_inherit_std_handles() {
    extern "system" {
        fn GetStdHandle(which: u32) -> isize;
        fn SetHandleInformation(handle: isize, mask: u32, flags: u32) -> i32;
    }
    const HANDLE_FLAG_INHERIT: u32 = 1;
    // STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE (-10, -11, -12 as DWORD)
    for which in [0xFFFF_FFF6u32, 0xFFFF_FFF5, 0xFFFF_FFF4] {
        // SAFETY: plain Win32 calls on this process's own standard handles; failure leaves them as they were
        unsafe {
            let h = GetStdHandle(which);
            if h != 0 && h != -1 {
                SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

pub fn run(rest: &[String]) -> Result<Value, String> {
    let h = home();
    match rest.first().map(String::as_str) {
        Some("setup") => setup(&h, flag(rest, "--python")),
        Some("start") => start(&h, rest),
        Some(op @ ("status" | "interfaces" | "peers" | "announce" | "stop")) => call(&h, op, json!({})),
        Some("inbox") => call(&h, "inbox", json!({"since": flag(rest, "--since").and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)})),
        Some("propagation") => {
            let node = rest.get(1).ok_or("rns propagation <node address | off>")?;
            call(&h, "propagation", json!({"node": if node == "off" { Value::Null } else { json!(node) }}))
        }
        Some("send") => {
            if rest.len() < 3 {
                return Err("rns send <lxmf address> <text...> [--title t] [--propagated] [--wait]".into());
            }
            let words: Vec<&str> = rest[2..].iter().map(String::as_str)
                .take_while(|w| !w.starts_with("--")).collect();
            let sent = call(&h, "send", json!({"to": rest[1], "content": words.join(" "),
                "title": flag(rest, "--title").unwrap_or_default(), "propagated": rest.iter().any(|a| a == "--propagated")}))?;
            if !rest.iter().any(|a| a == "--wait") {
                return Ok(sent);
            }
            let id = sent["id"].clone();
            let end = Instant::now() + Duration::from_secs(120);
            loop {
                let st = call(&h, "message", json!({"id": id}))?;
                let s = st["state"].as_str().unwrap_or("");
                if matches!(s, "delivered" | "failed" | "rejected" | "cancelled") || Instant::now() > end {
                    return Ok(st);
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        _ => Err("rns setup | start | status | interfaces | peers | announce | send | inbox | propagation | stop".into()),
    }
}
