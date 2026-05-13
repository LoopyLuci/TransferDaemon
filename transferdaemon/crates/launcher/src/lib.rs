//! Launcher library — testable core logic for the TransferDaemon launcher binary.
//!
//! Responsibilities:
//!   1. `probe_daemon`   — fast gRPC health-check (returns true/false, no error).
//!   2. `wait_for_daemon` — retries until the daemon answers or the timeout fires.
//!   3. `find_binary`    — locates a named binary next to the launcher, in
//!                          platform-specific install dirs, or on `$PATH`.
//!   4. `spawn_daemon`   — launches `transferd` as a detached background process.

use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum LaunchError {
    #[error("daemon did not become ready after {tries} attempts")]
    DaemonTimeout { tries: u32 },
    #[error("binary '{name}' not found in search path")]
    BinaryNotFound { name: String },
    #[error("failed to spawn daemon: {0}")]
    SpawnFailed(#[from] std::io::Error),
    #[error("transport error: {0}")]
    Transport(String),
}

// ---------------------------------------------------------------------------
// Daemon probe
// ---------------------------------------------------------------------------

/// Returns `true` if the daemon at `addr` responds to a health-check RPC.
/// Never panics; all errors return `false`.
pub async fn probe_daemon(addr: &str) -> bool {
    use transferd_api::AccountServiceClient;
    use transferd_api::Empty;

    let channel = match tonic::transport::Channel::from_shared(addr.to_owned()) {
        Ok(e) => e
            .connect_timeout(Duration::from_millis(300))
            .connect()
            .await,
        Err(_) => return false,
    };

    match channel {
        Ok(ch) => {
            let mut client = AccountServiceClient::new(ch);
            client.get_identity(Empty {}).await.is_ok()
        }
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Wait for daemon
// ---------------------------------------------------------------------------

/// Polls `probe_daemon` up to `max_tries` times with `interval` between each.
/// Returns `Ok(())` as soon as a probe succeeds.
pub async fn wait_for_daemon(
    addr: &str,
    max_tries: u32,
    interval: Duration,
) -> Result<(), LaunchError> {
    for _ in 0..max_tries {
        if probe_daemon(addr).await {
            return Ok(());
        }
        tokio::time::sleep(interval).await;
    }
    Err(LaunchError::DaemonTimeout { tries: max_tries })
}

// ---------------------------------------------------------------------------
// Binary search
// ---------------------------------------------------------------------------

/// Locate a binary by searching (in order):
///   1. The same directory as the currently running launcher.
///   2. The platform-specific install prefix (`~/.local/bin` on Linux/macOS,
///      `%LOCALAPPDATA%\TransferDaemon\bin` on Windows).
///   3. Every directory on `$PATH`.
pub fn find_binary(name: &str) -> Option<PathBuf> {
    // 1. Sibling of the launcher.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(binary_name(name));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    // 2. Platform install prefix.
    for dir in install_prefix_dirs() {
        let candidate = dir.join(binary_name(name));
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    // 3. $PATH.
    if let Ok(paths) = std::env::var("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(binary_name(name));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

/// Append `.exe` on Windows.
fn binary_name(name: &str) -> String {
    if cfg!(windows) && !name.ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

/// Platform-specific install prefix directories (ordered by priority).
fn install_prefix_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(windows)]
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        dirs.push(PathBuf::from(local).join("TransferDaemon").join("bin"));
    }

    #[cfg(not(windows))]
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".local").join("bin"));
    }

    dirs
}

// ---------------------------------------------------------------------------
// Spawn daemon
// ---------------------------------------------------------------------------

/// Launch the daemon binary as a fully detached background process.
/// The process's stdout/stderr are discarded; it runs independently of the
/// launcher.
pub fn spawn_daemon(binary: &std::path::Path, addr: &str) -> Result<(), LaunchError> {
    use std::process::Stdio;

    std::process::Command::new(binary)
        .env("TRANSFERD_ADDR", addr)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Default addresses
// ---------------------------------------------------------------------------

/// Default address used when no environment override is set.
pub const DEFAULT_DAEMON_ADDR: &str = "http://127.0.0.1:50051";

/// Read `TRANSFERD_ADDR` from the environment, falling back to the default.
pub fn daemon_addr() -> String {
    std::env::var("TRANSFERD_ADDR").unwrap_or_else(|_| DEFAULT_DAEMON_ADDR.to_owned())
}
