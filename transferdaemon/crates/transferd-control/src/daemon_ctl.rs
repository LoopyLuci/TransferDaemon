//! Managing the daemon from a window, a terminal or a script: is it running, start it, stop it, restart it, and read
//! and save its `config.json`. The GUI, the terminal and the CLI all go through here, so they do it the same way.
//!
//! Stopping and status go through the control hub (see [`crate::client`]). Starting runs the daemon program detached,
//! with its console output appended to `daemon.out.log` in the data folder, so a daemon that dies at start-up leaves
//! its last words behind.

use crate::client::{self, Client, ClientError};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The settings file the daemon reloads when it changes.
pub const CONFIG_FILE: &str = "config.json";
/// Where a started daemon's console output goes.
pub const OUTPUT_FILE: &str = "daemon.out.log";

/// Where the daemon program is: `TRANSFERD_EXE`, else `transferd` next to the running program, else found on PATH.
pub fn daemon_exe() -> PathBuf {
    if let Some(path) = std::env::var_os("TRANSFERD_EXE") {
        return PathBuf::from(path);
    }
    let name = if cfg!(windows) { "transferd.exe" } else { "transferd" };
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        let beside = dir.join(name);
        if beside.exists() {
            return beside;
        }
    }
    PathBuf::from(name)
}

/// The hub's health reply when a daemon is answering. A stale `control.json` (from a daemon that died) gives `None`.
pub fn running() -> Option<Value> {
    let client = Client::connect().ok()?.with_timeout(Duration::from_secs(3));
    client.health().ok()
}

/// Everything the daemon reports about itself (`daemon.status`).
pub fn status() -> Result<Value, ClientError> {
    Client::connect()?.call("daemon.status", json!({}))
}

/// Ask the daemon to stop, and wait (up to 15 s) until it has.
pub fn stop() -> Result<(), ClientError> {
    let client = Client::connect()?.with_timeout(Duration::from_secs(10));
    client.call("daemon.stop", json!({}))?;
    wait_until(Duration::from_secs(15), || running().is_none());
    Ok(())
}

/// Start the daemon detached, and wait (up to 20 s) until its hub answers. Returns the new process id.
pub fn start() -> Result<u32, String> {
    if running().is_some() {
        return Err("the daemon is already running".to_string());
    }
    let exe = daemon_exe();
    let out_path = client::data_dir().join(OUTPUT_FILE);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    }
    let out = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&out_path)
        .map_err(|e| format!("could not open {}: {e}", out_path.display()))?;
    let err = out.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&exe);
    cmd.stdin(Stdio::null()).stdout(Stdio::from(out)).stderr(Stdio::from(err));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Its own process group and no console window, so it keeps running after the window that started it closes.
        cmd.creation_flags(0x0000_0200 | 0x0800_0000);
    }
    let child = cmd.spawn().map_err(|e| format!("could not start {}: {e}", exe.display()))?;
    let pid = child.id();
    if wait_until(Duration::from_secs(20), || running().is_some()) {
        Ok(pid)
    } else {
        Err(format!("the daemon started (pid {pid}) but its control hub did not answer within 20 s; see {}", out_path.display()))
    }
}

/// Stop the daemon if it runs, then start it.
pub fn restart() -> Result<u32, String> {
    if running().is_some() {
        stop().map_err(|e| e.to_string())?;
    }
    start()
}

/// The text of `config.json`, or an empty object when there is no file yet.
pub fn read_config() -> Result<String, String> {
    match fs::read_to_string(config_path()) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("{}\n".to_string()),
        Err(e) => Err(format!("could not read {}: {e}", config_path().display())),
    }
}

/// Save `config.json`. The text must be a JSON object; the daemon picks the change up without a restart.
pub fn write_config(text: &str) -> Result<(), String> {
    let parsed: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    if !parsed.is_object() {
        return Err("the settings must be a JSON object, like {\"key\": value}".to_string());
    }
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    }
    let pretty = serde_json::to_string_pretty(&parsed).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, format!("{pretty}\n"))
        .and_then(|_| fs::rename(&tmp, &path))
        .map_err(|e| format!("could not save {}: {e}", path.display()))
}

/// Where `config.json` is.
pub fn config_path() -> PathBuf {
    client::data_dir().join(CONFIG_FILE)
}

/// Poll `ready` every quarter second until it is true or `timeout` passes. Returns whether it became true.
fn wait_until(timeout: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if ready() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn config_must_be_a_json_object() {
        let dir = std::env::temp_dir().join(format!("td-config-{}", std::process::id()));
        std::env::set_var("TRANSFERD_DATA_DIR", &dir);
        assert!(write_config("[1, 2]").is_err());
        assert!(write_config("not json").is_err());
        assert!(write_config("{\"relays\": []}").is_ok());
        assert!(read_config().unwrap().contains("\"relays\""));
        std::env::remove_var("TRANSFERD_DATA_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wait_gives_up_after_its_timeout() {
        let started = Instant::now();
        assert!(!wait_until(Duration::from_millis(300), || false));
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert!(wait_until(Duration::from_millis(300), || true));
    }
}
