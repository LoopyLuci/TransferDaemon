//! Minimal Kademlia DHT for relay discovery.
//!
//! ## Design
//!
//! Implements the core Kademlia operations (PING, FIND_NODE, STORE, FIND_VALUE)
//! over UDP using tokio.  Only the subset required for relay announcement is
//! implemented; full DHT crawling or content routing is out of scope.
//!
//! ### Parameters
//! - Node ID: 32 bytes (blake3-derived)
//! - k = 8  (bucket size / closest nodes returned)
//! - α = 3  (parallelism for iterative lookups)
//! - RPC timeout: 2 seconds
//!
//! ### Wire format
//! Every UDP datagram is `bincode::serialize(&DhtMsg)`.  No manual tag byte —
//! bincode encodes the enum discriminant automatically.  Max datagram: 64 KiB.
//!
//! ### RPC matching
//! Each outbound request carries a random `rpc_id: u64`.  The response echoes
//! the same `rpc_id`.  The receive loop dispatches responses to waiting
//! `oneshot` channels via a `HashMap<u64, oneshot::Sender<DhtMsg>>`.

use crate::announce::RelayAnnounce;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, oneshot};
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const K: usize = 8;
const ALPHA: usize = 3;
const RPC_TIMEOUT: Duration = Duration::from_secs(2);
const RELAY_TTL_SECS: u64 = 15 * 60; // 15 minutes
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(12 * 60); // re-announce every 12 min

// ---------------------------------------------------------------------------
// Node ID and XOR metric
// ---------------------------------------------------------------------------

pub type NodeId = [u8; 32];

/// XOR distance between two IDs (big-endian comparison).
fn xor_dist(a: &NodeId, b: &NodeId) -> NodeId {
    let mut d = [0u8; 32];
    for i in 0..32 { d[i] = a[i] ^ b[i]; }
    d
}

/// Number of leading zero bits in `id` — used to select the k-bucket.
fn leading_zeros(id: &NodeId) -> usize {
    for (byte_idx, &byte) in id.iter().enumerate() {
        if byte != 0 {
            return byte_idx * 8 + byte.leading_zeros() as usize;
        }
    }
    256
}

// ---------------------------------------------------------------------------
// NodeInfo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NodeInfo {
    pub id: NodeId,
    pub addr: SocketAddr,
}

// ---------------------------------------------------------------------------
// Wire messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMsg {
    Ping        { rpc_id: u64, from: NodeInfo },
    Pong        { rpc_id: u64, from: NodeInfo },
    FindNode    { rpc_id: u64, from: NodeInfo, target: NodeId },
    FindNodeResp{ rpc_id: u64, from: NodeInfo, closer: Vec<NodeInfo> },
    Store       { rpc_id: u64, from: NodeInfo, key: NodeId, value: Vec<u8>, ttl_secs: u64 },
    StoreAck    { rpc_id: u64, from: NodeInfo },
    FindValue   { rpc_id: u64, from: NodeInfo, key: NodeId },
    FindValueResp {
        rpc_id: u64,
        from: NodeInfo,
        /// The value if this node holds it.
        value: Option<Vec<u8>>,
        /// Closer nodes to consult if the value was not found here.
        closer: Vec<NodeInfo>,
    },
}

impl DhtMsg {
    fn rpc_id(&self) -> u64 {
        match self {
            DhtMsg::Ping        { rpc_id, .. } => *rpc_id,
            DhtMsg::Pong        { rpc_id, .. } => *rpc_id,
            DhtMsg::FindNode    { rpc_id, .. } => *rpc_id,
            DhtMsg::FindNodeResp{ rpc_id, .. } => *rpc_id,
            DhtMsg::Store       { rpc_id, .. } => *rpc_id,
            DhtMsg::StoreAck    { rpc_id, .. } => *rpc_id,
            DhtMsg::FindValue   { rpc_id, .. } => *rpc_id,
            DhtMsg::FindValueResp{rpc_id, .. } => *rpc_id,
        }
    }

    fn sender(&self) -> &NodeInfo {
        match self {
            DhtMsg::Ping        { from, .. } => from,
            DhtMsg::Pong        { from, .. } => from,
            DhtMsg::FindNode    { from, .. } => from,
            DhtMsg::FindNodeResp{ from, .. } => from,
            DhtMsg::Store       { from, .. } => from,
            DhtMsg::StoreAck    { from, .. } => from,
            DhtMsg::FindValue   { from, .. } => from,
            DhtMsg::FindValueResp{from, .. } => from,
        }
    }

    /// True for response messages (these are routed to pending RPC waiters).
    fn is_response(&self) -> bool {
        matches!(self, DhtMsg::Pong{..} | DhtMsg::FindNodeResp{..} | DhtMsg::StoreAck{..} | DhtMsg::FindValueResp{..})
    }
}

// ---------------------------------------------------------------------------
// K-Bucket
// ---------------------------------------------------------------------------

struct KBucket {
    nodes: VecDeque<NodeInfo>,
    last_changed: Instant,
}

impl KBucket {
    fn new() -> Self {
        Self { nodes: VecDeque::new(), last_changed: Instant::now() }
    }

    /// Insert or move-to-tail a node (LRU: tail = most recently seen).
    fn update(&mut self, node: NodeInfo) {
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
        }
        if self.nodes.len() >= K {
            self.nodes.pop_front(); // evict oldest
        }
        self.nodes.push_back(node);
        self.last_changed = Instant::now();
    }

    fn nodes(&self) -> impl Iterator<Item = &NodeInfo> { self.nodes.iter() }
}

// ---------------------------------------------------------------------------
// Routing table (256 k-buckets)
// ---------------------------------------------------------------------------

struct RoutingTable {
    own_id: NodeId,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    fn new(own_id: NodeId) -> Self {
        let buckets = (0..256).map(|_| KBucket::new()).collect();
        Self { own_id, buckets }
    }

    fn bucket_index(&self, id: &NodeId) -> usize {
        let dist = xor_dist(&self.own_id, id);
        leading_zeros(&dist).min(255)
    }

    fn update(&mut self, node: NodeInfo) {
        if node.id == self.own_id { return; }
        let idx = self.bucket_index(&node.id);
        self.buckets[idx].update(node);
    }

/// Returns up to `n` nodes closest to `target`, sorted by XOR distance.
    fn find_closest(&self, target: &NodeId, n: usize) -> Vec<NodeInfo> {
        let mut candidates: Vec<(NodeId, NodeInfo)> = self.buckets.iter()
            .flat_map(|b| b.nodes().cloned())
            .map(|node| (xor_dist(target, &node.id), node))
            .collect();
        candidates.sort_by_key(|(dist, _)| *dist);
        candidates.into_iter().map(|(_, n)| n).take(n).collect()
    }

    fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.nodes().count()).sum()
    }
}

// ---------------------------------------------------------------------------
// Local DHT storage
// ---------------------------------------------------------------------------

struct DhtStore {
    entries: HashMap<NodeId, (Vec<u8>, u64)>, // key -> (value, expires_at_secs)
}

impl DhtStore {
    fn new() -> Self { Self { entries: HashMap::new() } }

    fn insert(&mut self, key: NodeId, value: Vec<u8>, ttl_secs: u64) {
        let expires_at = now_secs() + ttl_secs;
        self.entries.insert(key, (value, expires_at));
    }

    fn get(&self, key: &NodeId) -> Option<&Vec<u8>> {
        self.entries.get(key).and_then(|(v, exp)| {
            if *exp > now_secs() { Some(v) } else { None }
        })
    }

fn prune(&mut self) {
        let now = now_secs();
        self.entries.retain(|_, (_, exp)| *exp > now);
    }

    fn len(&self) -> usize { self.entries.len() }
}

// ---------------------------------------------------------------------------
// DhtNodeInner — shared mutable state
// ---------------------------------------------------------------------------

struct DhtNodeInner {
    info: NodeInfo,
    routing: RoutingTable,
    store: DhtStore,
    pending: HashMap<u64, oneshot::Sender<DhtMsg>>,
}

impl DhtNodeInner {
    fn new(id: NodeId, addr: SocketAddr) -> Self {
        Self {
            info: NodeInfo { id, addr },
            routing: RoutingTable::new(id),
            store: DhtStore::new(),
            pending: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// DhtNode — public API
// ---------------------------------------------------------------------------

/// A Kademlia DHT node with a UDP listener.
///
/// Cloning this handle is cheap (Arc inside).
#[derive(Clone)]
pub struct DhtNode {
    socket: Arc<UdpSocket>,
    inner: Arc<Mutex<DhtNodeInner>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl DhtNode {
    // ── Constructor ───────────────────────────────────────────────────────────

/// Bind a UDP socket and start the receive loop.
    ///
    /// `id` should be a blake3-derived 32-byte node ID unique to this instance.
    /// The node advertises its bound address; when binding `0.0.0.0` (or an
    /// ephemeral port) that address is NOT reachable by remote peers, so use
    /// [`Self::start_with_advertised`] to advertise the externally-reachable
    /// address instead (e.g. a public VPS IP).
    pub async fn start(bind_addr: &str, id: NodeId) -> std::io::Result<Self> {
        Self::start_with_advertised(bind_addr, id, None).await
    }

    /// Like [`Self::start`], but advertises `advertised` (e.g. a public IP) in
    /// routing/NodeInfo messages instead of the bound address. This is what a
    /// hosted bootstrap node must use: it binds `0.0.0.0:port` and advertises
    /// `public-ip:port` so remote peers can route to it.
    pub async fn start_with_advertised(
        bind_addr: &str,
        id: NodeId,
        advertised: Option<SocketAddr>,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        let node_addr = advertised.unwrap_or(local_addr);
        let socket = Arc::new(socket);
        let inner = Arc::new(Mutex::new(DhtNodeInner::new(id, node_addr)));
        let (shutdown_tx, _) = broadcast::channel(8);

        let node = Self { socket: socket.clone(), inner: inner.clone(), shutdown_tx: shutdown_tx.clone() };
        node.spawn_recv_loop(socket, inner.clone(), shutdown_tx.clone());
        node.spawn_store_pruner(inner, shutdown_tx.clone());
        Ok(node)
    }

pub fn id(&self) -> NodeId { self.inner.lock().unwrap_or_else(|e| e.into_inner()).info.id }
    pub fn addr(&self) -> SocketAddr { self.inner.lock().unwrap_or_else(|e| e.into_inner()).info.addr }

    /// Debug introspection: number of known peers and stored values.
    pub fn debug_stats(&self) -> (usize, usize) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (g.routing.len(), g.store.len())
    }

    pub fn stop(&self) { let _ = self.shutdown_tx.send(()); }

    // ── Single-node RPCs ─────────────────────────────────────────────────────

    pub async fn ping(&self, addr: SocketAddr) -> bool {
        let rpc_id = random_u64();
        let msg = DhtMsg::Ping { rpc_id, from: self.my_info() };
        self.send_rpc(addr, msg, rpc_id).await
            .map(|r| matches!(r, DhtMsg::Pong{..}))
            .unwrap_or(false)
    }

    pub async fn rpc_find_node(&self, addr: SocketAddr, target: NodeId) -> Option<Vec<NodeInfo>> {
        let rpc_id = random_u64();
        let msg = DhtMsg::FindNode { rpc_id, from: self.my_info(), target };
        match self.send_rpc(addr, msg, rpc_id).await? {
            DhtMsg::FindNodeResp { closer, .. } => Some(closer),
            _ => None,
        }
    }

    pub async fn rpc_store(&self, addr: SocketAddr, key: NodeId, value: Vec<u8>, ttl_secs: u64) -> bool {
        let rpc_id = random_u64();
        let msg = DhtMsg::Store { rpc_id, from: self.my_info(), key, value, ttl_secs };
        self.send_rpc(addr, msg, rpc_id).await
            .map(|r| matches!(r, DhtMsg::StoreAck{..}))
            .unwrap_or(false)
    }

    pub async fn rpc_find_value(&self, addr: SocketAddr, key: NodeId) -> Option<DhtMsg> {
        let rpc_id = random_u64();
        let msg = DhtMsg::FindValue { rpc_id, from: self.my_info(), key };
        self.send_rpc(addr, msg, rpc_id).await
    }

    // ── High-level DHT operations ─────────────────────────────────────────────

    /// Bootstrap by contacting `peers`, learning their routing tables.
    pub async fn bootstrap(&self, peers: Vec<SocketAddr>) {
        let own_id = self.id();
        for peer_addr in peers {
            if let Some(closer) = self.rpc_find_node(peer_addr, own_id).await {
                let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                // The responding peer itself is already added by the recv loop;
                // add any nodes it told us about.
                for node in closer {
                    guard.routing.update(node);
                }
            }
        }
    }

    /// Publish `(key, value)` to the k closest nodes in the network.
    pub async fn dht_store(&self, key: NodeId, value: Vec<u8>, ttl_secs: u64) {
        // Store locally first.
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).store.insert(key, value.clone(), ttl_secs);

        // Iterative node lookup to find the k closest nodes.
        let closest = self.iterative_find_node(key).await;

        // STORE on each.
        for node in closest {
            self.rpc_store(node.addr, key, value.clone(), ttl_secs).await;
        }
    }

    /// Iterative FIND_VALUE lookup across the DHT.
    pub async fn dht_get(&self, key: NodeId) -> Option<Vec<u8>> {
        // Check local storage first.
        if let Some(v) = self.inner.lock().unwrap_or_else(|e| e.into_inner()).store.get(&key).cloned() {
            return Some(v);
        }

        let mut asked: HashSet<NodeId> = HashSet::new();
        asked.insert(self.id()); // don't re-ask ourselves

        let mut candidates: Vec<NodeInfo> = self.inner.lock().unwrap_or_else(|e| e.into_inner())
            .routing.find_closest(&key, K);

        loop {
            let to_ask: Vec<NodeInfo> = candidates.iter()
                .filter(|n| !asked.contains(&n.id))
                .take(ALPHA)
                .cloned()
                .collect();

            if to_ask.is_empty() { break; }

            let mut found_closer = false;
            for node in &to_ask {
                asked.insert(node.id);
                match self.rpc_find_value(node.addr, key).await {
                    Some(DhtMsg::FindValueResp { value: Some(v), .. }) => {
                        return Some(v);
                    }
                    Some(DhtMsg::FindValueResp { value: None, closer, .. }) => {
                        for c in closer {
                            if !asked.contains(&c.id)
                                && !candidates.iter().any(|n| n.id == c.id) {
                                    candidates.push(c);
                                    found_closer = true;
                                }
                        }
                    }
                    _ => {}
                }
            }

            // Re-sort by XOR distance after adding new candidates.
            candidates.sort_by_key(|n| xor_dist(&key, &n.id));
            candidates.truncate(K * 2);

            if !found_closer { break; }
        }

        None
    }

    // ── Relay-specific helpers ─────────────────────────────────────────────────

    /// Publish a `RelayAnnounce` record to the DHT.
    pub async fn publish_relay(&self, announce: &RelayAnnounce) {
        let key = RelayAnnounce::dht_key(&announce.identity_pubkey_hash);
        let value = bincode::serialize(announce).unwrap_or_default();
        self.dht_store(key, value, RELAY_TTL_SECS).await;
    }

    /// Look up a relay announcement for a given `identity_pubkey_hash`.
    pub async fn lookup_relay(&self, identity_pubkey_hash: &[u8; 32]) -> Option<RelayAnnounce> {
        let key = RelayAnnounce::dht_key(identity_pubkey_hash);
        let bytes = self.dht_get(key).await?;
        let announce: RelayAnnounce = bincode::deserialize(&bytes).ok()?;
        if announce.is_expired() || !announce.verify() { return None; }
        Some(announce)
    }

    /// Returns a list of all relay announcements stored locally (for scanning).
    pub fn local_relays(&self) -> Vec<RelayAnnounce> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.store.entries.values()
            .filter(|(_, exp)| *exp > now_secs())
            .filter_map(|(v, _)| bincode::deserialize::<RelayAnnounce>(v).ok())
            .filter(|a| a.verify() && !a.is_expired())
            .collect()
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn my_info(&self) -> NodeInfo {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).info.clone()
    }

    /// Send an RPC and wait for the response (identified by `rpc_id`).
    async fn send_rpc(&self, addr: SocketAddr, msg: DhtMsg, rpc_id: u64) -> Option<DhtMsg> {
        let (tx, rx) = oneshot::channel();
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).pending.insert(rpc_id, tx);

        let bytes = bincode::serialize(&msg).ok()?;
        self.socket.send_to(&bytes, addr).await.ok()?;

        match timeout(RPC_TIMEOUT, rx).await {
            Ok(Ok(resp)) => Some(resp),
            _ => {
                self.inner.lock().unwrap_or_else(|e| e.into_inner()).pending.remove(&rpc_id);
                None
            }
        }
    }

    /// Iterative FIND_NODE — returns k closest nodes to `target`.
    async fn iterative_find_node(&self, target: NodeId) -> Vec<NodeInfo> {
        let mut asked: HashSet<NodeId> = HashSet::new();
        asked.insert(self.id());

        let mut candidates: Vec<NodeInfo> = self.inner.lock().unwrap_or_else(|e| e.into_inner())
            .routing.find_closest(&target, K);

        loop {
            let to_ask: Vec<NodeInfo> = candidates.iter()
                .filter(|n| !asked.contains(&n.id))
                .take(ALPHA)
                .cloned()
                .collect();

            if to_ask.is_empty() { break; }

            let mut added_any = false;
            for node in &to_ask {
                asked.insert(node.id);
                if let Some(closer) = self.rpc_find_node(node.addr, target).await {
                    for c in closer {
                        if !candidates.iter().any(|n| n.id == c.id) {
                            candidates.push(c);
                            added_any = true;
                        }
                    }
                }
            }

            candidates.sort_by_key(|n| xor_dist(&target, &n.id));
            candidates.truncate(K * 2);

            if !added_any { break; }
        }

        candidates.into_iter().take(K).collect()
    }

    fn spawn_recv_loop(
        &self,
        socket: Arc<UdpSocket>,
        inner: Arc<Mutex<DhtNodeInner>>,
        shutdown_tx: broadcast::Sender<()>,
    ) {
        let socket_send = socket.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    result = socket.recv_from(&mut buf) => {
                        let (n, src) = match result { Ok(x) => x, Err(_) => continue };
                        let msg: DhtMsg = match bincode::deserialize(&buf[..n]) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };

                        // Update routing table with sender.
                        {
                            let mut g = inner.lock().unwrap_or_else(|e| e.into_inner());
                            let sender = msg.sender().clone();
                            g.routing.update(sender);
                        }

                        if msg.is_response() {
                            // Route to waiting oneshot.
                            let tx = inner.lock().unwrap_or_else(|e| e.into_inner()).pending.remove(&msg.rpc_id());
                            if let Some(tx) = tx { let _ = tx.send(msg); }
                        } else {
                            // Handle inbound request and send reply.
                            handle_request(&socket_send, &inner, msg, src).await;
                        }
                    }
                }
            }
        });
    }

    fn spawn_store_pruner(
        &self,
        inner: Arc<Mutex<DhtNodeInner>>,
        shutdown_tx: broadcast::Sender<()>,
    ) {
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        inner.lock().unwrap_or_else(|e| e.into_inner()).store.prune();
                    }
                }
            }
        });
    }
}

impl Drop for DhtNode {
    fn drop(&mut self) { self.stop(); }
}

// ---------------------------------------------------------------------------
// Inbound request handler
// ---------------------------------------------------------------------------

async fn handle_request(
    socket: &UdpSocket,
    inner: &Arc<Mutex<DhtNodeInner>>,
    msg: DhtMsg,
    _src: SocketAddr,
) {
    let reply: Option<DhtMsg> = {
        let mut g = inner.lock().unwrap_or_else(|e| e.into_inner());
        let my_info = g.info.clone();
        match &msg {
            DhtMsg::Ping { rpc_id, .. } => {
                Some(DhtMsg::Pong { rpc_id: *rpc_id, from: my_info })
            }
            DhtMsg::FindNode { rpc_id, target, .. } => {
                let closer = g.routing.find_closest(target, K);
                Some(DhtMsg::FindNodeResp { rpc_id: *rpc_id, from: my_info, closer })
            }
            DhtMsg::Store { rpc_id, key, value, ttl_secs, .. } => {
                g.store.insert(*key, value.clone(), *ttl_secs);
                Some(DhtMsg::StoreAck { rpc_id: *rpc_id, from: my_info })
            }
            DhtMsg::FindValue { rpc_id, key, .. } => {
                let value = g.store.get(key).cloned();
                let closer = if value.is_none() { g.routing.find_closest(key, K) } else { vec![] };
                Some(DhtMsg::FindValueResp { rpc_id: *rpc_id, from: my_info, value, closer })
            }
            _ => None, // responses handled by routing above
        }
    };

if let Some(reply) = reply {
        // Reply to the datagram's actual source, not the peer's advertised
        // address (which is loopback or 0.0.0.0 when bound to an ephemeral /
        // wildcard socket on another host).
        if let Ok(bytes) = bincode::serialize(&reply) {
            let _ = socket.send_to(&bytes, _src).await;
        }
    }
}

// ---------------------------------------------------------------------------
// DhtAnnouncer — relay-lifecycle layer on top of DhtNode
// ---------------------------------------------------------------------------

/// Wraps a `DhtNode` and handles periodic re-announcement of a relay record.
pub struct DhtAnnouncer {
    pub node: DhtNode,
}

impl DhtAnnouncer {
    /// Create a new announcer with a fresh DHT node on `bind_addr`.
    ///
    /// `identity_pubkey_hash` is the blake3 hash of the node's hybrid public key.
    pub async fn new(bind_addr: &str, identity_pubkey_hash: [u8; 32]) -> std::io::Result<Self> {
        let id = derive_node_id(&identity_pubkey_hash);
        let node = DhtNode::start(bind_addr, id).await?;
        Ok(Self { node })
    }

    /// Join the DHT network via known bootstrap peers (addr strings like "1.2.3.4:6881").
    pub async fn bootstrap(&self, peers: &[String]) {
        let addrs: Vec<SocketAddr> = peers.iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        self.node.bootstrap(addrs).await;
    }

    /// Publish the relay record once.
    pub async fn publish(&self, announce: &RelayAnnounce) {
        self.node.publish_relay(announce).await;
    }

    /// Spawn a background task that re-publishes `announce` every `REPUBLISH_INTERVAL`.
    ///
    /// The task runs until `shutdown_rx` fires.
    pub fn start_republish_task(
        &self,
        announce: RelayAnnounce,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let node = self.node.clone();
        tokio::spawn(async move {
            node.publish_relay(&announce).await;
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    _ = tokio::time::sleep(REPUBLISH_INTERVAL) => {
                        node.publish_relay(&announce).await;
                    }
                }
            }
        });
    }

    /// Look up a relay for a peer identified by their `identity_pubkey_hash`.
    pub async fn lookup(&self, identity_pubkey_hash: &[u8; 32]) -> Option<RelayAnnounce> {
        self.node.lookup_relay(identity_pubkey_hash).await
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive a deterministic 32-byte DHT node ID from an identity hash.
pub fn derive_node_id(identity_pubkey_hash: &[u8; 32]) -> NodeId {
    let mut input = b"transferd-dht-node-id-v1".to_vec();
    input.extend_from_slice(identity_pubkey_hash);
    *blake3::hash(&input).as_bytes()
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn random_u64() -> u64 {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    fn make_id(byte: u8) -> NodeId { [byte; 32] }

    #[test]
    fn xor_distance_self_is_zero() {
        let id = make_id(0xAA);
        assert_eq!(xor_dist(&id, &id), [0u8; 32]);
    }

    #[test]
    fn leading_zeros_counts_correctly() {
        let mut id = [0u8; 32];
        id[0] = 0b0001_0000; // 3 leading zeros in first byte → 3 total
        assert_eq!(leading_zeros(&id), 3);

        let all_zeros = [0u8; 32];
        assert_eq!(leading_zeros(&all_zeros), 256);
    }

    #[test]
    fn routing_table_find_closest_returns_sorted() {
        let own_id = make_id(0x00);
        let mut rt = RoutingTable::new(own_id);
        for i in 1u8..=10 {
            rt.update(NodeInfo { id: make_id(i), addr: "127.0.0.1:1".parse().unwrap() });
        }
        let target = make_id(0x03);
        let closest = rt.find_closest(&target, 3);
        assert_eq!(closest.len(), 3);
        // Verify sorted by XOR distance to 0x03
        for win in closest.windows(2) {
            let d0 = xor_dist(&target, &win[0].id);
            let d1 = xor_dist(&target, &win[1].id);
            assert!(d0 <= d1, "results must be sorted by XOR distance");
        }
    }

    #[tokio::test]
    async fn two_node_ping_pong() {
        let id_a = derive_node_id(&[0xA1u8; 32]);
        let id_b = derive_node_id(&[0xB1u8; 32]);

        let a = DhtNode::start("127.0.0.1:0", id_a).await.unwrap();
        let b = DhtNode::start("127.0.0.1:0", id_b).await.unwrap();

        assert!(a.ping(b.addr()).await, "A should be able to PING B");
        assert!(b.ping(a.addr()).await, "B should be able to PING A");
    }

    #[tokio::test]
async fn store_and_retrieve_via_dht() {
        let id_a = derive_node_id(&[0xA2u8; 32]);
        let id_b = derive_node_id(&[0xB2u8; 32]);

        let a = DhtNode::start("127.0.0.1:0", id_a).await.unwrap();
        let b = DhtNode::start("127.0.0.1:0", id_b).await.unwrap();

        // Bootstrap: B learns A.
        b.bootstrap(vec![a.addr()]).await;

        let key = [0x42u8; 32];
        let value = b"hello dht".to_vec();

        // A stores a value.
        a.dht_store(key, value.clone(), 300).await;

        // B retrieves it (by looking up in A, since B bootstrapped from A).
        let retrieved = b.dht_get(key).await;
        assert_eq!(retrieved.as_deref(), Some(value.as_slice()),
            "B must retrieve the value stored by A");
    }

    #[tokio::test]
    async fn advertised_address_is_used_for_routing() {
        // A hosted bootstrap node binds the wildcard address (reachable on any
        // interface) but advertises an externally-reachable address. Peers must
        // route to the ADVERTISED address, not the bound `0.0.0.0` one.
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let id_a = derive_node_id(&[0x11u8; 32]);
        let id_b = derive_node_id(&[0x22u8; 32]);
        let advertised = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let a = DhtNode::start_with_advertised(
            &format!("0.0.0.0:{port}"), id_a, Some(advertised),
        ).await.unwrap();
        assert_eq!(a.addr(), advertised, "node must advertise the override, not 0.0.0.0");

        let b = DhtNode::start("127.0.0.1:0", id_b).await.unwrap();
        b.bootstrap(vec![a.addr()]).await;

        let key = [0x55u8; 32];
        a.dht_store(key, b"via-advertised".to_vec(), 300).await;
        let retrieved = b.dht_get(key).await;
        assert_eq!(retrieved.as_deref(), Some(b"via-advertised".as_slice()),
            "B must reach A through its advertised address");
    }

    #[tokio::test]
    async fn relay_announce_publish_lookup() {
        let hash_alice = [0xAAu8; 32];
        let hash_bob   = [0xBBu8; 32];

        let alice = DhtAnnouncer::new("127.0.0.1:0", hash_alice).await.unwrap();
        let bob   = DhtAnnouncer::new("127.0.0.1:0", hash_bob).await.unwrap();

        // Bob bootstraps from Alice.
        bob.bootstrap(&[alice.node.addr().to_string()]).await;

        let now = now_secs();
        let announce = RelayAnnounce {
            identity_pubkey_hash: hash_alice,
            relay_addr: alice.node.addr().to_string(),
            difficulty: 14,
            bandwidth_kbps: 10_000,
            auth_mode: "public".into(),
            published_at: now,
            expires_at: now + 900,
            auth: [0u8; 32],
        }.sign(&hash_alice);

        alice.publish(&announce).await;

        // Bob can find Alice's relay via DHT.
        let found = tokio::time::timeout(
            Duration::from_secs(5),
            bob.lookup(&hash_alice),
        ).await.expect("lookup timed out");

        assert!(found.is_some(), "Bob must discover Alice's relay via DHT");
        let rec = found.unwrap();
        assert_eq!(rec.relay_addr, announce.relay_addr);
        assert_eq!(rec.auth_mode, "public");
        assert!(rec.verify(), "record must pass verification");
    }
}



