//! Protocol plugin registry — maps URL schemes to `TransportLane` factories.
//!
//! ## Built-in plugins
//!
//! | Scheme   | Lane            | Status      |
//! |----------|-----------------|-------------|
//! | `tcp`    | `TcpLane`       | Implemented |
//! | `relay`  | `RelayLane`     | Implemented |
//! | `swarm`  | `SwarmLane`     | Stub        |
//! | `ble`    | (future)        | —           |
//! | `mqtt`   | (future)        | —           |
//!
//! ## Adding a plugin
//!
//! 1. Implement `ProtocolPlugin` for your type.
//! 2. Call `PluginRegistry::register(Box::new(MyPlugin))` at startup.
//! 3. When the ATE resolves a destination URL, `PluginRegistry::create_lane`
//!    picks the right plugin by scheme.
//!
//! Dynamic loading (`.so`/`.dll`) is intentionally out of scope for v1 — the
//! static registry is sufficient for the supported protocol set and avoids
//! unsafe linker gymnastics.

use crate::transport::{TransportError, TransportLane};
use std::future::Future;
use std::pin::Pin;

// ---------------------------------------------------------------------------
// Plugin trait
// ---------------------------------------------------------------------------

/// A factory that can create `TransportLane` instances for a specific URL scheme.
pub trait ProtocolPlugin: Send + Sync {
    /// Human-readable name shown in logs and diagnostics.
    fn name(&self) -> &'static str;

    /// URL scheme this plugin handles (e.g. `"tcp"`, `"relay"`, `"swarm"`).
    fn scheme(&self) -> &'static str;

    /// Returns a hint about lane capabilities for ATE scheduling.
    fn capabilities(&self) -> LaneCapabilities { LaneCapabilities::default() }

    /// Creates a lane connected to `endpoint` using `session_key` for encryption.
    ///
    /// `endpoint` is the scheme-specific address string, e.g. `"127.0.0.1:9000"`.
    fn create_lane<'a>(
        &'a self,
        id: u32,
        endpoint: &'a str,
        session_key: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn TransportLane>, TransportError>> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Lane capability hints
// ---------------------------------------------------------------------------

/// Static capability hints used by the ATE when choosing initial lane parameters.
#[derive(Clone, Debug)]
pub struct LaneCapabilities {
    /// Approximate maximum throughput in bits per second.
    pub max_bps: u64,
    /// Approximate round-trip time in milliseconds.
    pub typical_rtt_ms: u64,
    /// True if this lane can be used when an internet connection is unavailable.
    pub local_only: bool,
    /// True if this lane provides end-to-end encryption independent of `transferd`.
    pub transport_encrypted: bool,
}

impl Default for LaneCapabilities {
    fn default() -> Self {
        Self {
            max_bps: 100_000_000,
            typical_rtt_ms: 20,
            local_only: false,
            transport_encrypted: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Holds all registered protocol plugins and resolves scheme → lane factories.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Box<dyn ProtocolPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self { Self::default() }

    /// Registers a plugin. Last-registered plugin wins for duplicate schemes.
    pub fn register(&mut self, plugin: Box<dyn ProtocolPlugin>) {
        self.plugins.push(plugin);
    }

    /// Returns the plugin for `scheme`, or `None` if none is registered.
    pub fn find(&self, scheme: &str) -> Option<&dyn ProtocolPlugin> {
        self.plugins.iter().rev().find(|p| p.scheme() == scheme).map(|p| p.as_ref())
    }

    /// Creates a lane by scheme. Returns `TransportError::ProtocolViolation` for unknown schemes.
    pub async fn create_lane(
        &self,
        id: u32,
        scheme: &str,
        endpoint: &str,
        session_key: &[u8; 32],
    ) -> Result<Box<dyn TransportLane>, TransportError> {
        let plugin = self.find(scheme).ok_or(TransportError::ProtocolViolation)?;
        plugin.create_lane(id, endpoint, session_key).await
    }

    /// Returns capability hints for a scheme, or defaults if unknown.
    pub fn capabilities(&self, scheme: &str) -> LaneCapabilities {
        self.find(scheme)
            .map(|p| p.capabilities())
            .unwrap_or_default()
    }

    pub fn registered_schemes(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|p| p.scheme()).collect()
    }
}

// ---------------------------------------------------------------------------
// Built-in: TcpPlugin
// ---------------------------------------------------------------------------

/// Plugin for the `tcp://` scheme — creates a `TcpLane` connecting to `host:port`.
pub struct TcpPlugin;

impl ProtocolPlugin for TcpPlugin {
    fn name(&self) -> &'static str { "TCP transport" }
    fn scheme(&self) -> &'static str { "tcp" }

    fn capabilities(&self) -> LaneCapabilities {
        LaneCapabilities {
            max_bps: 10_000_000_000, // 10 Gbps possible on LAN
            typical_rtt_ms: 1,
            local_only: false,
            transport_encrypted: false, // encryption is handled by TcpLane itself
        }
    }

    fn create_lane<'a>(
        &'a self,
        id: u32,
        endpoint: &'a str,
        session_key: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn TransportLane>, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let addr: std::net::SocketAddr = endpoint
                .parse()
                .map_err(|_| TransportError::LinkDown(format!("invalid addr: {endpoint}")))?;
            let lane = crate::lanes::tcp_lane::TcpLane::connect(id, addr, session_key)
                .await
                .map_err(|e| TransportError::LinkDown(e.to_string()))?;
            Ok(Box::new(lane) as Box<dyn TransportLane>)
        })
    }
}

// ---------------------------------------------------------------------------
// Built-in: RelayPlugin
// ---------------------------------------------------------------------------

/// Plugin for the `relay://` scheme — creates a send-only `RelayLane`.
///
/// Endpoint format: `"relay_addr|forward_token_hex"` (see `RelayLane::new` for details).
/// In practice the daemon assembles RelayLanes directly; this plugin is provided
/// for completeness and future CLI-driven configuration.
pub struct RelayPlugin;

impl ProtocolPlugin for RelayPlugin {
    fn name(&self) -> &'static str { "Blind relay (relayd)" }
    fn scheme(&self) -> &'static str { "relay" }

    fn capabilities(&self) -> LaneCapabilities {
        LaneCapabilities {
            max_bps: 100_000_000,
            typical_rtt_ms: 30,
            local_only: false,
            transport_encrypted: true,
        }
    }

    fn create_lane<'a>(
        &'a self,
        _id: u32,
        _endpoint: &'a str,
        _session_key: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn TransportLane>, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            // Full wiring is done by the daemon using RelayLane::new() directly.
            // This stub allows the registry to advertise "relay" capability.
            Err(TransportError::ProtocolViolation)
        })
    }
}

// ---------------------------------------------------------------------------
// Built-in: SwarmPlugin stub
// ---------------------------------------------------------------------------

/// Plugin for the `swarm://` scheme — decentralized piece-swarm distribution.
///
/// Creates a **seeder** lane backed by a fresh `SwarmStore`.  The caller is
/// responsible for sharing the store with leecher lanes via
/// `SwarmLane::new_leecher(id, store.clone())`.
///
/// ## Endpoint format
///
/// Currently unused — any non-empty string is accepted.  In a future librqbit
/// integration, this would be a magnet URI (`magnet:?xt=urn:btih:…`) that the
/// leecher uses to join the real BitTorrent swarm.
pub struct SwarmPlugin;

impl ProtocolPlugin for SwarmPlugin {
    fn name(&self) -> &'static str { "Swarm (piece-store / BitTorrent)" }
    fn scheme(&self) -> &'static str { "swarm" }

    fn capabilities(&self) -> LaneCapabilities {
        LaneCapabilities {
            max_bps: 500_000_000,  // 500 Mbps — realistic for a well-seeded swarm
            typical_rtt_ms: 200,   // higher latency than TCP/relay
            local_only: false,
            transport_encrypted: false, // payload encryption handled by transferd-crypto
        }
    }

    fn create_lane<'a>(
        &'a self,
        id: u32,
        _endpoint: &'a str,
        _session_key: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn TransportLane>, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            // LIBRQBIT: when wiring the real BitTorrent backend, parse `_endpoint`
            // as a magnet URI here and create either a seeder (if we own the data)
            // or a leecher (if we're downloading).  For now we create a seeder with
            // a fresh in-process store.
            let store = crate::lanes::swarm_lane::SwarmStore::new();
            let lane = crate::lanes::swarm_lane::SwarmLane::new_seeder(id, store);
            Ok(Box::new(lane) as Box<dyn TransportLane>)
        })
    }
}

// ---------------------------------------------------------------------------
// Default registry constructor
// ---------------------------------------------------------------------------

/// Returns a registry pre-loaded with all built-in plugins.
pub fn default_registry() -> PluginRegistry {
    let mut r = PluginRegistry::new();
    r.register(Box::new(TcpPlugin));
    r.register(Box::new(RelayPlugin));
    r.register(Box::new(SwarmPlugin));
    r
}
