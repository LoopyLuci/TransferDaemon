//! TransferDaemon Launcher — single entry point for end users.
//!
//! Workflow:
//!   1. Resolve daemon address from `TRANSFERD_ADDR` env var (default 127.0.0.1:50051).
//!   2. Probe the daemon; start it in the background if not already running.
//!   3. Wait up to 10 s for the daemon to become ready.
//!   4. Launch `transferd-ui`, forwarding the daemon address.
//!   5. When the UI exits, exit the launcher with the same status code.

use std::process::Stdio;
use launcher_lib::{daemon_addr, find_binary, probe_daemon, spawn_daemon, wait_for_daemon};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let addr = daemon_addr();
    eprintln!("[launcher] daemon address: {addr}");

    // ── Step 1: ensure daemon is running ─────────────────────────────────────
    if !probe_daemon(&addr).await {
        eprintln!("[launcher] daemon not responding — starting it...");

        let daemon_bin = find_binary("transferd").unwrap_or_else(|| {
            eprintln!("[launcher] error: 'transferd' binary not found in search path");
            std::process::exit(1);
        });
        eprintln!("[launcher] found daemon: {}", daemon_bin.display());

        if let Err(e) = spawn_daemon(&daemon_bin, &addr) {
            eprintln!("[launcher] error: could not spawn daemon: {e}");
            std::process::exit(1);
        }

        // ── Step 2: wait up to 10 s (20 × 500 ms) ──────────────────────────
        eprintln!("[launcher] waiting for daemon to become ready...");
        if let Err(e) = wait_for_daemon(&addr, 20, Duration::from_millis(500)).await {
            eprintln!("[launcher] error: {e}");
            std::process::exit(1);
        }
        eprintln!("[launcher] daemon is ready");
    } else {
        eprintln!("[launcher] daemon already running");
    }

    // ── Step 3: launch the UI ────────────────────────────────────────────────
    let ui_bin = find_binary("transferd-ui").unwrap_or_else(|| {
        eprintln!("[launcher] error: 'transferd-ui' binary not found in search path");
        std::process::exit(1);
    });
    eprintln!("[launcher] launching UI: {}", ui_bin.display());

    let status = std::process::Command::new(&ui_bin)
        .env("TRANSFERD_ADDR", &addr)
        .stdin(Stdio::null())
        .status()
        .unwrap_or_else(|e| {
            eprintln!("[launcher] error: could not launch UI: {e}");
            std::process::exit(1);
        });

    // Mirror the UI's exit code.
    std::process::exit(status.code().unwrap_or(0));
}
