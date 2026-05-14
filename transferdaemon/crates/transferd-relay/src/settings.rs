use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthPolicy {
    /// Any peer that solves PoW may register.
    Public,
    /// Only peers whose session token is in the allow-list may register.
    AllowList(Vec<[u8; 32]>),
}

impl Default for AuthPolicy {
    fn default() -> Self { Self::Public }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelaySettings {
    pub enabled: bool,
    pub port: u16,
    /// PoW difficulty: number of leading zero bits required.
    pub difficulty: u32,
    /// Bandwidth cap in kilobits per second (0 = unlimited).
    pub bandwidth_kbps: u64,
    /// Maximum concurrent registered sessions.
    pub max_sessions: usize,
    pub auth_policy: AuthPolicy,
    /// DHT port for relay announcement / discovery (0 = OS-assigned).
    pub dht_port: u16,
    /// Seed peers for DHT bootstrap (host:port strings).
    /// Empty → LAN-only operation (mDNS-style zero-config is Phase 4).
    pub dht_bootstrap_nodes: Vec<String>,
    /// Blake3 hash of the node's hybrid public key — used as DHT node ID seed
    /// and for signing relay announce records.  Set by the daemon at startup.
    pub identity_pubkey_hash: [u8; 32],
}

impl Default for RelaySettings {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 7777,
            difficulty: 14,
            bandwidth_kbps: 10_000, // 10 Mbps default cap
            max_sessions: 256,
            auth_policy: AuthPolicy::Public,
            dht_port: 6881,
            dht_bootstrap_nodes: vec![
                // Community volunteer bootstrap nodes — replace with real ones post-Phase 4.
                // Left empty so tests run with no external network dependency.
            ],
            identity_pubkey_hash: [0u8; 32],
        }
    }
}
