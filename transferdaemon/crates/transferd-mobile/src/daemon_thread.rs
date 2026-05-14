//! Background thread that runs the TransferDaemon gRPC server.

use std::sync::OnceLock;
use tokio::runtime::Handle;

/// Handle to the daemon's tokio runtime.
/// Set once when the daemon spawns; used by `grpc_bridge::block_on_daemon`.
pub static RUNTIME_HANDLE: OnceLock<Handle> = OnceLock::new();

pub fn spawn(socket_path: String) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("daemon tokio runtime");

        // Store the handle before blocking so other threads can queue tasks.
        let handle = rt.handle().clone();
        RUNTIME_HANDLE.set(handle).ok();

        rt.block_on(async move {
            let port: u16 = std::env::var("TRANSFERD_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50051);
            let addr = format!("127.0.0.1:{port}").parse().expect("parse addr");
            eprintln!("[daemon] starting on {addr} (socket hint: {socket_path})");

            let state = transferd_lib::new_state();
            transferd_lib::grpc::add_all_services(tonic::transport::Server::builder(), state)
                .serve(addr)
                .await
                .expect("daemon serve");
        });
    });
}
