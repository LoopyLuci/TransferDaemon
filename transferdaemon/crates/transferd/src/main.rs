//! TransferDaemon daemon binary.
//!
//! Starts all seven gRPC services on `[::1]:50051` (override with `TRANSFERD_ADDR`),
//! a peer transport listener on `addr+1`, and the background transport tick that
//! flushes queued messages over active lanes.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::env::var("TRANSFERD_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".into());
    // Strip any scheme prefix (http:// or https://) — tonic serve() needs a bare SocketAddr.
    let addr_str = raw
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let addr: std::net::SocketAddr = addr_str.parse()?;

    // Use the platform-default encrypted store so data persists across restarts.
    let state = transferd_lib::new_state_persistent();

    // Generate a per-install gRPC auth token and persist it for UIs/launcher.
    // Loopback-only binding limits exposure, but local processes should not be
    // able to inject messages into the daemon.
    {
        use rand::RngCore as _;
        let mut token_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);
        {
            let mut s = state.lock();
            s.auth_token = Some(token.clone());
        }
        let token_path = transferd_api::auth::token_file_path();
        if let Err(e) = transferd_api::auth::write_token_file(&token_path, &token) {
            tracing::warn!("[auth] could not persist token file: {e}");
        } else {
            println!("TransferDaemon auth token: {token_path:?}");
        }
    }

    // Start the telemetry collector and wire the global ATE hook.
    let telemetry_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("transferdaemon")
        .join("telemetry");
    std::fs::create_dir_all(&telemetry_dir)?;

    let collector = transferd_telemetry::TelemetryCollector::start(&telemetry_dir);
    {
        let mut s = state.lock();
        s.telemetry = Some(std::sync::Arc::clone(&collector));
    }

    // Register the global ATE lane-selection hook so session.rs emits events.
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        let col = std::sync::Arc::clone(&collector);
        transferd_core::telemetry::register_ate_hook(move |data| {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut hash = [0u8; 8];
            hash.copy_from_slice(&data.session_id[..8]);
            let event = transferd_telemetry::TelemetryEvent::AteLane(
                transferd_telemetry::AteLaneEvent {
                    ts,
                    session_id_hash: hash,
                    gsn: data.gsn,
                    selected_lane: data.selected_lane,
                    rtt_ms: data.rtt_ms,
                    bandwidth_bps: data.bandwidth_bps,
                    active_chunks: data.active_chunks,
                    total_lanes: data.total_lanes,
                },
            );
            let col2 = std::sync::Arc::clone(&col);
            tokio::spawn(async move { col2.record(event).await; });
        });
    }

    // Background transport tick: flush queued messages over active lanes and
    // apply any inbound events (acks, read receipts, unsolicited messages).
    transferd_lib::transport::spawn_transport_tick(state.clone());

    // Start the inbound peer transport listener (localhost only for security,
    // on the gRPC port + 1). Each connection completes the X25519 handshake and
    // is wrapped in an encrypted `TcpLane`.
    {
        let state_clone = state.clone();
        let tcp_port = addr.port() + 1;
        let bind_addr: std::net::SocketAddr = match format!("127.0.0.1:{tcp_port}").parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("[transport] invalid peer bind address: {e}");
                return Ok(());
            }
        };
        tokio::spawn(async move {
            match transferd_lib::transport::spawn_inbound_listener(state_clone, bind_addr).await {
                Ok(listening) => {
                    println!("TransferDaemon peer listener on {listening} (localhost only)");
                }
                Err(e) => {
                    tracing::error!("[transport] failed to bind peer listener: {e}");
                }
            }
        });
    }

    // Start the inbound relay listener if a relay is configured.
    {
        let state_clone = state.clone();
        tokio::spawn(async move {
            transferd_lib::relay_hub::spawn_inbound_relay_listener(state_clone).await;
        });
    }

    // Initialize mesh networking (zero-relay direct mode + auto-meshing relay)
    {
        use std::sync::Arc as SyncArc;
        use parking_lot::Mutex as PkMutex;

        let config = transferd_lib::mesh::MeshConfig {
            enable_direct: true,
            enable_relay: true,
            mesh_maintenance_secs: 60,
            ..Default::default()
        };
        let mesh = SyncArc::new(PkMutex::new(transferd_lib::mesh::MeshNetwork::new(config)));

        // Register existing contacts in the mesh
        {
            let s = state.lock();
            for contact in &s.contacts {
                let mut m = mesh.lock();
                m.register_peer(&contact.id);
                if let Some(addr) = &contact.address {
                    m.set_direct_addr(&contact.id, addr);
                }
            }
        }

        // Start mesh maintenance loop
        let mesh_clone = mesh.clone();
        tokio::spawn(async move {
            transferd_lib::mesh::run_mesh_loop(mesh_clone).await;
        });
    }

    println!("TransferDaemon gRPC server listening on {addr}");

    transferd_lib::grpc::add_all_services(tonic::transport::Server::builder(), state)
        .serve(addr)
        .await?;

    Ok(())
}