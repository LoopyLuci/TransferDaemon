//! Synchronous bridge from the eframe UI thread to the daemon's async runtime.
//!
//! eframe's `update()` is synchronous. Instead of creating a second runtime on
//! the UI thread, callers can use `block_on_daemon` to run a single future on
//! the daemon's existing runtime and block the current (UI) thread until it
//! completes.
//!
//! Only use this for short-lived gRPC calls — not for long-running futures.

use std::future::Future;

/// Spawn `f` on the daemon's tokio runtime and block the calling thread for the result.
///
/// Panics if the daemon runtime has not been initialized yet (i.e. called before
/// `daemon_thread::spawn` returns).
pub fn block_on_daemon<F, T>(f: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = crate::daemon_thread::RUNTIME_HANDLE.get()
        .expect("Daemon runtime not initialized — call daemon_thread::spawn first");
    handle.spawn(async move {
        let result = f.await;
        let _ = tx.send(result);
    });
    rx.recv().expect("Daemon gRPC call dropped sender")
}
