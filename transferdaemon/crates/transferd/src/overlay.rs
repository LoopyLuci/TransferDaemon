//! The overlay inside the daemon: one node per installation, its operations on the control hub.
//!
//! The node is `transferd_overlay::OverlayNode`; this module only decides where its key and state
//! live, which relays it registers on, and plugs its `overlay.*` operations into the hub so the
//! CLI, MCP clients and anything else on this machine reach them like every other operation.
//!
//! | Setting | Default | |
//! |---|---|---|
//! | `TRANSFERD_OVERLAY` | on | `off` leaves the overlay out entirely |
//! | `TRANSFERD_OVERLAY_RELAYS` | the UDP entries of `TRANSFERD_RELAY_ADDR` | `host:port,...` |
//! | `TRANSFERD_OVERLAY_LISTEN` | none | a direct listener (`host:port`); nothing is needed for reachability |
//! | `TRANSFERD_OVERLAY_DIRECT` | none | addresses to publish in invites (`host:port,...`) |
//! | `TRANSFERD_OVERLAY_NAME` | the computer's name | how this node introduces itself |
//! | `TRANSFERD_MESH_DNS` | none | mesh DNS upstreams (node ids or groups, `,`-separated): answer DNS through them |
//! | `TRANSFERD_MESH_DNS_LISTEN` | `127.0.0.1:53053` | where mesh DNS answers (UDP and TCP) |
//!
//! Without `TRANSFERD_MESH_DNS`, mesh DNS keeps whatever `overlay.dns_set` last set (it is in the
//! state file); with it, the environment wins at every start.
//!
//! The node's key is a 64-byte seed kept like the recovery-phrase cache (`phrase_cache`): DPAPI
//! on Windows, an owner-only file elsewhere. Paired nodes, exposed services and groups are in
//! `overlay/state.json`, the audit trail in `overlay/audit.jsonl`, all under the data folder.

use std::path::Path;
use std::pin::Pin;
use std::future::Future;
use std::sync::Arc;

use serde_json::Value;
use transferd_control::catalog::{extension_op, Operation};
use transferd_control::hub::{Extension, Hub};
use transferd_overlay::{NodeIdentity, OverlayConfig, OverlayNode};

/// Whether the overlay is wanted (on unless `TRANSFERD_OVERLAY` is `off`/`0`/`false`).
pub fn enabled() -> bool {
    !matches!(std::env::var("TRANSFERD_OVERLAY").as_deref(), Ok("off") | Ok("0") | Ok("false"))
}

/// Start this installation's overlay node and put its operations on `hub`.
pub async fn start(hub: &Arc<Hub>) -> Option<Arc<OverlayNode>> {
    if !enabled() {
        return None;
    }
    let dir = transferd_control::client::data_dir().join("overlay");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!("[overlay] cannot create {}: {e}; the overlay is off", dir.display());
        return None;
    }
    let identity = match load_or_create_identity(&dir.join("node.key"), &node_name()) {
        Ok(identity) => identity,
        Err(e) => {
            tracing::warn!("[overlay] no node key: {e}; the overlay is off");
            return None;
        }
    };
    let config = OverlayConfig {
        relays: relays(),
        direct: list("TRANSFERD_OVERLAY_DIRECT"),
        listen: std::env::var("TRANSFERD_OVERLAY_LISTEN").ok().and_then(|v| v.trim().parse().ok()),
        state_path: Some(dir.join("state.json")),
        audit_path: Some(dir.join("audit.jsonl")),
        ..OverlayConfig::local(identity)
    };
    match OverlayNode::start(config).await {
        Ok(node) => {
            println!("TransferDaemon overlay node {} ({} relay(s))", node.node_id(), node.relays().len());
            hub.add_extension(Arc::new(Ops(node.clone())));
            let upstreams = list("TRANSFERD_MESH_DNS");
            if !upstreams.is_empty() {
                let mut dns = transferd_overlay::dns::MeshDnsConfig::new(upstreams);
                if let Ok(listen) = std::env::var("TRANSFERD_MESH_DNS_LISTEN") {
                    dns.listen = listen.trim().to_string();
                }
                match node.set_mesh_dns(Some(dns)).await {
                    Ok(status) => println!("TransferDaemon mesh DNS on {}", status["listen"].as_str().unwrap_or("?")),
                    Err(e) => tracing::warn!("[overlay] mesh DNS did not start: {e}"),
                }
            }
            Some(node)
        }
        Err(e) => {
            tracing::warn!("[overlay] the node did not start: {e}");
            None
        }
    }
}

/// The relays to register on: `TRANSFERD_OVERLAY_RELAYS`, else the UDP relays the daemon
/// already uses (`TRANSFERD_RELAY_ADDR`; WebSocket entries are left out, the overlay's relay
/// path is UDP).
fn relays() -> Vec<String> {
    let own = list("TRANSFERD_OVERLAY_RELAYS");
    if !own.is_empty() {
        return own;
    }
    list("TRANSFERD_RELAY_ADDR").into_iter().filter(|r| !r.contains("://") || r.starts_with("udp://")).collect()
}

fn list(var: &str) -> Vec<String> {
    std::env::var(var)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn node_name() -> String {
    std::env::var("TRANSFERD_OVERLAY_NAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "transferdaemon".into())
}

/// The node's identity from its stored seed, or a new one (stored) on first start.
fn load_or_create_identity(path: &Path, name: &str) -> std::io::Result<NodeIdentity> {
    if let Some(text) = crate::phrase_cache::read(path) {
        let seed = hex::decode(text.trim())
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{} is not a node key", path.display())))?;
        return Ok(NodeIdentity::from_seed(&seed, name));
    }
    if path.exists() {
        // Present but unreadable (another user's DPAPI blob, a damaged file): never replace a
        // key silently, every paired node knows this one.
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{} exists but cannot be read; move it away to start with a new node id", path.display()),
        ));
    }
    let mut seed = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    crate::phrase_cache::write(path, &hex::encode(seed))?;
    Ok(NodeIdentity::from_seed(&seed, name))
}

/// The node's operations, as a hub extension.
struct Ops(Arc<OverlayNode>);

impl Extension for Ops {
    fn operations(&self) -> Vec<Operation> {
        transferd_overlay::ops::operations()
            .into_iter()
            .map(|(id, summary, mutating, input, output)| extension_op(id, summary, mutating, false, input, output))
            .collect()
    }

    fn call<'a>(
        &'a self,
        op: &'a str,
        args: Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, (String, String)>> + Send + 'a>> {
        Box::pin(async move {
            transferd_overlay::ops::call(&self.0, op, args).await.map_err(|e| (e.code().to_string(), e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_key_is_created_once_and_read_back_as_the_same_identity() {
        let dir = std::env::temp_dir().join(format!("td-overlay-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("node.key");
        let first = load_or_create_identity(&path, "a").expect("created");
        let again = load_or_create_identity(&path, "a").expect("read back");
        assert_eq!(first.node_id(), again.node_id());
        std::fs::write(&path, b"not a key").expect("damage it");
        assert!(load_or_create_identity(&path, "a").is_err(), "a damaged key is refused, not replaced");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
