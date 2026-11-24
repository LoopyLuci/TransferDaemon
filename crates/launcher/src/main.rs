//! TransferDaemon Launcher — single entry point for end users.
//!
//! Workflow:
//!   1. Rotate logs — keep the last 10 runs in logs/launcher_log_N.log.
//!   2. Resolve daemon address from `TRANSFERD_ADDR` env var (default 127.0.0.1:50051).
//!   3. Look for `transferd` and `transferd-ui` next to the launcher binary itself.
//!   4. Probe the daemon; start it in the background if not already running.
//!   5. Wait up to 10 s for the daemon to become ready.
//!   6. Launch `transferd-ui`, forwarding the daemon address.
//!   7. When the UI exits, exit the launcher with the same status code.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use launcher_lib::{daemon_addr, probe_daemon, spawn_daemon, wait_for_daemon};

const LOG_DIR:  &str = "logs";
const LOG_BASE: &str = "launcher_log";
const MAX_LOGS: u32  = 10;

/// Append `.exe` on Windows.
fn exe(name: &str) -> String {
    if cfg!(windows) { format!("{name}.exe") } else { name.to_owned() }
}

/// Shift existing log files and return the path for the new index-0 file.
fn rotate_logs(base: &Path) -> PathBuf {
    let dir = base.join(LOG_DIR);
    let _ = fs::create_dir_all(&dir);
    for i in (0..MAX_LOGS).rev() {
        let old = dir.join(format!("{LOG_BASE}_{i}.log"));
        if old.exists() {
            if i + 1 < MAX_LOGS {
                let new = dir.join(format!("{LOG_BASE}_{}.log", i + 1));
                let _ = fs::rename(&old, &new);
            } else {
                let _ = fs::remove_file(&old);
            }
        }
    }
    dir.join(format!("{LOG_BASE}_0.log"))
}

/// Initialise env_logger writing to a rotated file in `base/logs/`.
fn init_logging(base: &Path) {
    let log_path = rotate_logs(base);
    let file = fs::File::create(&log_path)
        .expect("failed to create launcher log file");
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format_timestamp_millis()
    .target(env_logger::Target::Pipe(Box::new(file)))
    .init();
    log::info!("launcher started — log: {}", log_path.display());
}

/// Resolve a sibling binary relative to the launcher's own location.
///
/// Search order:
///   1. `<launcher-dir>/bin/<name>`  — installer layout (portable package)
///   2. `<launcher-dir>/<name>`      — flat layout / in-tree `cargo run`
///   3. `find_binary` PATH search    — last resort
fn sibling_binary(name: &str) -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));

    let in_bin  = exe_dir.join("bin").join(exe(name));
    let in_root = exe_dir.join(exe(name));

    if in_bin.exists()  { return in_bin; }
    if in_root.exists() { return in_root; }

    launcher_lib::find_binary(name).unwrap_or_else(|| {
        log::error!("'{name}' not found in bin/, next to launcher, or on PATH");
        std::process::exit(1);
    })
}

#[tokio::main]
async fn main() {
    // Resolve the project root as the directory the launcher lives in.
    let root = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));

    init_logging(&root);

    let addr = daemon_addr();
    log::info!("daemon address: {addr}");

    let daemon_bin = sibling_binary("transferd");
    let ui_bin     = sibling_binary("transferd-ui");

    // ── Step 1: ensure daemon is running ─────────────────────────────────────
    if !probe_daemon(&addr).await {
        log::info!("daemon not responding — starting {}…", daemon_bin.display());

        if let Err(e) = spawn_daemon(&daemon_bin, &addr) {
            log::error!("could not spawn daemon: {e}");
            std::process::exit(1);
        }

        log::info!("waiting for daemon to become ready…");
        if let Err(e) = wait_for_daemon(&addr, 20, Duration::from_millis(500)).await {
            log::error!("{e}");
            std::process::exit(1);
        }
        log::info!("daemon is ready");
    } else {
        log::info!("daemon already running");
    }

    // ── Step 2: launch the UI ────────────────────────────────────────────────
    log::info!("launching UI: {}", ui_bin.display());

    let mut cmd = std::process::Command::new(&ui_bin);
    cmd.env("TRANSFERD_ADDR", &addr);
    if let Some(token) = transferd_api::auth::resolve_token() {
        cmd.env("TRANSFERD_TOKEN", token);
    }
    let status = cmd
        .stdin(Stdio::null())
        .status()
        .unwrap_or_else(|e| {
            log::error!("could not launch UI: {e}");
            std::process::exit(1);
        });

    log::info!("UI exited with status: {status}");
    std::process::exit(status.code().unwrap_or(0));
}
