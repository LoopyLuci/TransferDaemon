//! In-process TransferDaemon for testing.
//!
//! `TestDaemon` starts a full gRPC daemon on a random port, providing
//! a real backend for integration tests.

use std::sync::Arc;
use parking_lot::Mutex;
use tokio_stream::wrappers::TcpListenerStream;

/// A test daemon instance running on a random port.
pub struct TestDaemon {
    /// The gRPC endpoint address (e.g., "http://127.0.0.1:50051").
    pub addr: String,
    /// The daemon state shared with gRPC services.
    pub state: Arc<Mutex<transferd_lib::DaemonState>>,
}

impl TestDaemon {
    /// Start a new test daemon on a random port.
    pub async fn start() -> Self {
        let state = transferd_lib::new_state();

        // Bind to a random port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await
            .expect("Failed to bind test daemon port");
        let addr = listener.local_addr().expect("Failed to get local addr");
        let addr_str = format!("127.0.0.1:{}", addr.port());

        // Start the gRPC server
        let serve_state = Arc::clone(&state);
        tokio::spawn(async move {
            let router = transferd_lib::grpc::add_all_services(
                tonic::transport::Server::builder(),
                serve_state,
            );
            router
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .ok();
        });

        // Wait for the server to be ready
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Update state with the proper address
        {
            let mut s = state.lock();
            s.settings.insert("daemon_addr".into(), addr_str.clone());
        }

        Self {
            addr: format!("http://{addr_str}"),
            state,
        }
    }

    /// Get the daemon's port number.
    pub fn port(&self) -> u16 {
        self.addr.rsplit(':').next()
            .and_then(|p| p.trim_end_matches('"').parse().ok())
            .unwrap_or(50051)
    }

    /// Cleanly shut down the daemon.
    pub fn shutdown(self) {
        drop(self.state);
    }
}
