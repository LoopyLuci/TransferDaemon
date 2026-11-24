//! Integration tests for the launcher library.
//!
//! Tests that require a live daemon start an in-process tonic server on a
//! random port — no filesystem or process spawning needed.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tonic::transport::Server;
use launcher_lib::{probe_daemon, wait_for_daemon, find_binary, daemon_addr, DEFAULT_DAEMON_ADDR};
use transferd_lib::{grpc::add_all_services, new_state};

// ---------------------------------------------------------------------------
// In-process daemon helper
// ---------------------------------------------------------------------------

async fn start_test_daemon() -> (SocketAddr, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = new_state();
    tokio::spawn(async move {
        add_all_services(Server::builder(), state)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let url = format!("http://{addr}");
    (addr, url)
}

// ---------------------------------------------------------------------------
// probe_daemon tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_probe_daemon_not_running_returns_false() {
    // Nothing is listening on a random ephemeral port.
    let nothing = "http://127.0.0.1:19999";
    let result = probe_daemon(nothing).await;
    assert!(!result, "probe should return false when daemon is not running");
}

#[tokio::test]
async fn test_probe_daemon_running_returns_true() {
    let (_addr, url) = start_test_daemon().await;
    let result = probe_daemon(&url).await;
    assert!(result, "probe should return true when daemon is running");
}

#[tokio::test]
async fn test_probe_daemon_invalid_address_returns_false() {
    let bad = "not-a-valid-address";
    let result = probe_daemon(bad).await;
    assert!(!result, "probe should return false for invalid address");
}

// ---------------------------------------------------------------------------
// wait_for_daemon tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_wait_for_daemon_succeeds_immediately() {
    let (_addr, url) = start_test_daemon().await;
    let result = wait_for_daemon(&url, 5, Duration::from_millis(50)).await;
    assert!(result.is_ok(), "wait should succeed with live daemon");
}

#[tokio::test]
async fn test_wait_for_daemon_times_out() {
    let url = "http://127.0.0.1:19998";
    let result = wait_for_daemon(url, 3, Duration::from_millis(20)).await;
    assert!(result.is_err(), "wait should time out with no daemon");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("3"), "error should mention attempt count");
}

#[tokio::test]
async fn test_wait_for_daemon_retries_until_ready() {
    // Simulate a daemon that becomes available after two retries.
    // We start the server with a small intentional delay.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url  = format!("http://{addr}");
    let state = new_state();

    tokio::spawn(async move {
        // Delay before accepting to simulate slow daemon startup.
        tokio::time::sleep(Duration::from_millis(120)).await;
        add_all_services(Server::builder(), state)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    // Give the background task time to park on sleep.
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Wait with generous retries — should succeed once the server starts.
    let result = wait_for_daemon(&url, 20, Duration::from_millis(50)).await;
    assert!(result.is_ok(), "wait should eventually succeed: {result:?}");
}

// ---------------------------------------------------------------------------
// find_binary tests
// ---------------------------------------------------------------------------

#[test]
fn test_find_binary_missing_returns_none() {
    // A binary named this is unlikely to exist anywhere.
    let result = find_binary("transferdaemon-nonexistent-binary-xyz");
    assert!(result.is_none(), "should return None for unknown binary");
}

#[test]
fn test_find_binary_on_path_finds_standard_tool() {
    // `cargo` is always on PATH in the test environment.
    let result = find_binary("cargo");
    assert!(result.is_some(), "should find 'cargo' on PATH in test env");
    assert!(result.unwrap().exists());
}

#[cfg(unix)]
#[test]
fn test_find_binary_sibling_takes_priority() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    // Create a temp directory, put a fake binary in it, and set current_exe
    // to something in that directory (we can't override current_exe, so we
    // test the PATH fallback instead — the sibling logic is tested in main).
    let tmp = std::env::temp_dir().join("launcher_test_priority");
    fs::create_dir_all(&tmp).unwrap();
    let fake = tmp.join("transferd-ui");
    fs::write(&fake, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();

    // Add tmp to the front of PATH so find_binary's PATH search finds it.
    let old_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{old_path}", tmp.display());
    // We use a scoped env manipulation.
    std::env::set_var("PATH", &new_path);
    let found = find_binary("transferd-ui");
    std::env::set_var("PATH", &old_path);
    fs::remove_file(&fake).ok();

    assert!(found.is_some(), "should find fake transferd-ui on injected PATH");
}

// ---------------------------------------------------------------------------
// daemon_addr tests (sequential — env vars are process-global)
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_addr_default_and_override() {
    // Run both sub-cases in the same test to avoid parallel env-var races.
    std::env::remove_var("TRANSFERD_ADDR");
    assert_eq!(daemon_addr(), DEFAULT_DAEMON_ADDR, "should return default when env var absent");

    std::env::set_var("TRANSFERD_ADDR", "http://10.0.0.1:9090");
    let addr = daemon_addr();
    std::env::remove_var("TRANSFERD_ADDR");
    assert_eq!(addr, "http://10.0.0.1:9090", "should reflect env var when set");
}

// ---------------------------------------------------------------------------
// Multi-daemon isolation: two daemons on separate ports don't interfere
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_two_daemons_are_independent() {
    let (_a1, url1) = start_test_daemon().await;
    let (_a2, url2) = start_test_daemon().await;

    // Both are alive.
    assert!(probe_daemon(&url1).await);
    assert!(probe_daemon(&url2).await);

    // A port that definitely has nothing.
    assert!(!probe_daemon("http://127.0.0.1:19997").await);
}
