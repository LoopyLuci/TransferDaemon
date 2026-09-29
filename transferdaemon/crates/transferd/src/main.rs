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
    let grpc_token = {
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
        token
    };

    // The control hub: every operation over local HTTP and MCP, and the place the GUI and TUI attach so they can be
    // driven from outside (transferd-cli, ABP, any MCP client). TRANSFERD_CONTROL=off leaves it out.
    let control_facts = std::sync::Arc::new(std::sync::Mutex::new(serde_json::Map::new()));
    let hub = if std::env::var("TRANSFERD_CONTROL").map(|v| v == "off" || v == "0").unwrap_or(false) {
        None
    } else {
        let bind: std::net::SocketAddr = std::env::var("TRANSFERD_CONTROL_ADDR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| std::net::SocketAddr::from(([127, 0, 0, 1], 50060)));
        let host = if addr.ip().is_unspecified() { "127.0.0.1".to_string() } else { addr.ip().to_string() };
        let hub = transferd_control::hub::Hub::new(transferd_control::hub::HubConfig {
            grpc_url: format!("http://{host}:{}", addr.port()),
            grpc_token: Some(grpc_token.clone()),
            bind,
            version: env!("CARGO_PKG_VERSION").to_string(),
            facts: control_facts.clone(),
        });
        match transferd_control::hub::serve(hub.clone()).await {
            Ok(bound) => {
                println!("TransferDaemon control hub on http://{bound} (operations, MCP at /mcp)");
                Some(hub)
            }
            Err(e) => {
                tracing::error!("[control] could not start the control hub on {bind}: {e}");
                None
            }
        }
    };

    // Start the telemetry collector and wire the global ATE hook.
    let telemetry_dir = transferd_control::client::data_dir()
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

    // Start the inbound peer transport listener. By default it binds localhost
    // only (security); set TRANSFERD_BIND_ADDR=0.0.0.0 (or a LAN/Tailscale IP)
    // to accept direct peer connections so tailnet/LAN peers can connect
    // without a relay. The bound address is published as a direct `tcp://`
    // endpoint.
    {
        let state_clone = state.clone();
        let facts = control_facts.clone();
        let tcp_port = addr.port() + 1;
        let bind_host = std::env::var("TRANSFERD_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".into());
        let bind_addr: std::net::SocketAddr = match format!("{bind_host}:{tcp_port}").parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("[transport] invalid peer bind address: {e}");
                return Ok(());
            }
        };
        tokio::spawn(async move {
            match transferd_lib::transport::spawn_inbound_listener(state_clone.clone(), bind_addr).await {
                Ok(listening) => {
                    println!("TransferDaemon peer listener on {listening} (bind {bind_host})");
                    state_clone.lock().peer_listen = Some(listening);
                    if let Ok(mut f) = facts.lock() {
                        f.insert("peer_listener".into(), serde_json::json!(listening.to_string()));
                        f.insert("peer_bind".into(), serde_json::json!(bind_host));
                    }
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

    let server = transferd_lib::grpc::add_all_services(tonic::transport::Server::builder(), state).serve(addr);
    match &hub {
        Some(hub) => {
            let stop = hub.stop.clone();
            tokio::select! {
                r = server => r?,
                _ = stop.notified() => println!("TransferDaemon stopping (asked through the control hub)"),
                _ = tokio::signal::ctrl_c() => println!("TransferDaemon stopping"),
            }
            hub.shutdown();
        }
        None => server.await?,
    }

    Ok(())
}