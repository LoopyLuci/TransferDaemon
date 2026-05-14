//! TransferDaemon daemon binary.
//!
//! Starts all six gRPC services on `[::1]:50051` (override with `TRANSFERD_ADDR`).

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::env::var("TRANSFERD_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".into());
    // Strip any scheme prefix (http:// or https://) — tonic serve() needs a bare SocketAddr.
    let addr_str = raw
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let addr = addr_str.parse()?;

    // Use the platform-default encrypted store so data persists across restarts.
    let state = transferd_lib::new_state_persistent();

    println!("TransferDaemon gRPC server listening on {addr}");

    transferd_lib::grpc::add_all_services(tonic::transport::Server::builder(), state)
        .serve(addr)
        .await?;

    Ok(())
}
