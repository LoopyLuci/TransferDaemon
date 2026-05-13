//! TransferDaemon Launcher — single entry point for end users.
//!
//! Workflow:
//!   1. Resolve daemon address from `TRANSFERD_ADDR` env var (default 127.0.0.1:50051).
//!   2. Look for `transferd` and `transferd-ui` next to the launcher binary itself
//!      (i.e. in the same directory — the portable project root or bin/ folder).
//!   3. Probe the daemon; start it in the background if not already running.
//!   4. Wait up to 10 s for the daemon to become ready.
//!   5. Launch `transferd-ui`, forwarding the daemon address.
//!   6. When the UI exits, exit the launcher with the same status code.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use launcher_lib::{daemon_addr, probe_daemon, spawn_daemon, wait_for_daemon};

/// Append `.exe` on Windows.
fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

/// Resolve a sibling binary relative to the launcher's own location.
/// Falls back to the `find_binary` PATH search from the library if the
/// sibling doesn't exist (supports running cargo-built launchers in-tree).
fn sibling_binary(name: &str) -> PathBuf {
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(exe(name))));

    if let Some(ref p) = sibling {
        if p.exists() {
            return p.clone();
        }
    }

    // Fallback: search PATH (development / in-tree runs).
    launcher_lib::find_binary(name).unwrap_or_else(|| {
        eprintln!("[launcher] error: '{name}' not found next to launcher or on PATH");
        std::process::exit(1);
    })
}

#[tokio::main]
async fn main() {
    let addr = daemon_addr();
    eprintln!("[launcher] daemon address: {addr}");

    let daemon_bin = sibling_binary("transferd");
    let ui_bin     = sibling_binary("transferd-ui");

    // ── Step 1: ensure daemon is running ─────────────────────────────────────
    if !probe_daemon(&addr).await {
        eprintln!("[launcher] daemon not responding — starting {}…", daemon_bin.display());

        if let Err(e) = spawn_daemon(&daemon_bin, &addr) {
            eprintln!("[launcher] error: could not spawn daemon: {e}");
            std::process::exit(1);
        }

        eprintln!("[launcher] waiting for daemon to become ready…");
        if let Err(e) = wait_for_daemon(&addr, 20, Duration::from_millis(500)).await {
            eprintln!("[launcher] error: {e}");
            std::process::exit(1);
        }
        eprintln!("[launcher] daemon is ready");
    } else {
        eprintln!("[launcher] daemon already running");
    }

    // ── Step 2: launch the UI ────────────────────────────────────────────────
    eprintln!("[launcher] launching UI: {}", ui_bin.display());

    let status = std::process::Command::new(&ui_bin)
        .env("TRANSFERD_ADDR", &addr)
        .stdin(Stdio::null())
        .status()
        .unwrap_or_else(|e| {
            eprintln!("[launcher] error: could not launch UI: {e}");
            std::process::exit(1);
        });

    std::process::exit(status.code().unwrap_or(0));
}
