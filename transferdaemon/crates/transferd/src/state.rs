//! DaemonState — shared in-memory state for all gRPC service implementations.
//!
//! Persistence is write-through: every mutation calls `try_save()`, which
//! encrypts and writes `~/.local/share/transferdaemon/user_data.enc` (or the
//! platform equivalent) when a store path is configured.  In tests the path is
//! left `None` so saves are no-ops and no filesystem activity occurs.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use transferd_crypto::identity::HybridSigningKey;
use transferd_store::{PersistedUserData, StoreParams};

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Identity {
    /// Hex-encoded 32-byte Ed25519 verifying key (classical component).
    pub public_key:          String,
    /// Hex-encoded 2624-byte hybrid public key: `ed25519_pk ‖ ml_dsa_87_pk`.
    /// Empty on very old records that pre-date the quantum upgrade.
    pub hybrid_public_key:   String,
    pub display_name:        String,
    pub phrase:              String, // 12-word recovery phrase (kept in memory for auto-save)
}

// ---------------------------------------------------------------------------
// Contact
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Contact {
    pub id:           String,
    pub name:         String,
    pub last_seen_ts: u64,
    pub online:       bool,
    /// Whether this contact is blocked (cannot send us messages).
    pub blocked:      bool,
    /// Network address for this contact (e.g., "127.0.0.1:50051" or relay token).
    /// This is set during contact addition or discovery.
    pub address:      Option<String>,
    /// Hex-encoded 2624-byte hybrid public key verified on the peer's FIRST
    /// authenticated session (trust-on-first-use). `None` before first contact.
    pub hybrid_public_key: Option<String>,
    /// The peer's advertised transfer limits (per-content-type caps +
    /// bandwidth budgets), learned at discovery. `None` when unknown — the
    /// sender then uses its own limits (and the peer enforces on its side).
    pub limits: Option<relayd::limits::TransferLimits>,
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id:           String,
    pub contact_id:   String,
    pub outbound:     bool,
    pub content_type: String, // "text" | "file"
    pub text:         String,
    pub file_name:    String,
    pub file_size:    u64,
    pub file_xferd:   u64,
    pub file_mime:    String,
    pub timestamp_ts: u64,
    pub status:       String, // "pending" | "sent" | "delivered" | "read" | "failed"
    /// When set, this message belongs to a group thread (`contact_id` holds the
    /// group id); `sender_pk` identifies the actual author.
    pub group_id:  Option<String>,
    pub sender_pk: String,
    /// Id of the message this one quotes (reply). Resolved against the same thread.
    pub reply_to: Option<String>,
    /// Aggregated emoji reactions: `(emoji, reactor_public_key)`.
    pub reactions: Vec<(String, String)>,
}

impl StoredMessage {
pub fn new_text(id: String, contact_id: String, outbound: bool, text: String) -> Self {
        Self {
            id,
            contact_id,
            outbound,
            content_type: "text".into(),
            text,
            file_name: String::new(),
            file_size: 0,
            file_xferd: 0,
            file_mime: String::new(),
            timestamp_ts: now_secs(),
            status: if outbound { "sent".into() } else { "delivered".into() },
            group_id: None,
            sender_pk: String::new(),
            reply_to: None,
            reactions: Vec::new(),
        }
    }

    /// Returns a preview string for search/filtering purposes.
    pub fn content_preview(&self) -> String {
        if self.content_type == "text" {
            let t = &self.text;
            if t.len() > 80 { format!("{}…", &t[..77]) } else { t.clone() }
        } else {
            format!("📁 {}", self.file_name)
        }
    }
}

// ---------------------------------------------------------------------------
// Transfer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Transfer {
    pub id:           String,
    pub contact_name: String,
    pub file_name:    String,
    pub size_bytes:   u64,
    pub xferd_bytes:  u64,
    pub outbound:     bool,
    pub lanes_active: u32,
    pub bps:          u64,
}

// ---------------------------------------------------------------------------
// Group
// ---------------------------------------------------------------------------

/// Group role codes (mirror the proto `GroupRole` enum).
pub mod group_role {
    pub const OWNER:  u8 = 1;
    pub const ADMIN:  u8 = 2;
    pub const MEMBER: u8 = 3;

    pub fn name(role: u8) -> &'static str {
        match role {
            OWNER => "Owner",
            ADMIN => "Admin",
            _ => "Member",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GroupMember {
    pub public_key: String,
    pub role:       u8,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub id:         String,
    pub name:       String,
    pub owner:      String,
    pub members:    Vec<GroupMember>,
    pub created_at: u64,
}

// ---------------------------------------------------------------------------
// Call
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CallRecord {
    pub conv_id:   String,
    pub video:     bool,
    pub local_sdp: String,
    pub state:     String, // "calling" | "active" | "rejected" | "ended"
}

// ---------------------------------------------------------------------------
// DaemonState
// ---------------------------------------------------------------------------

pub struct DaemonState {
    pub identity:  Option<Identity>,
    pub contacts:  Vec<Contact>,
    /// contact_id → messages
    pub messages:  HashMap<String, Vec<StoredMessage>>,
    /// group_id → group
    pub groups:    HashMap<String, Group>,
    pub transfers: Vec<Transfer>,
    pub settings:  HashMap<String, String>,
    pub calls:     HashMap<String, CallRecord>,
    pub next_id:   u64,

    /// Running relay engine, if the relay is enabled.
    pub relay_engine: Option<Arc<transferd_relay::RelayEngine>>,

    /// Live telemetry collector, started by the daemon binary.
    pub telemetry: Option<Arc<transferd_telemetry::TelemetryCollector>>,

    /// Per-install gRPC auth token. When `Some`, every gRPC request must carry
    /// `Authorization: Bearer <token>`. `None` (tests / in-memory) disables auth.
    pub auth_token: Option<String>,

    /// Peer connection manager for network transport.
    ///
    /// Owned by its own async mutex so transport operations (connect, send,
    /// recv) can run without holding the global `parking_lot` state lock.
    /// Clone the `Arc` under a brief state lock, then operate on the clone.
    pub transport: Arc<tokio::sync::Mutex<crate::peer_manager::PeerConnectionManager>>,

    /// Inbound relay endpoint, when a relay is configured.
    pub relay_hub: Option<Arc<crate::relay_hub::RelayHub>>,

/// DHT node used for peer endpoint discovery, when configured.
    pub dht: Option<Arc<transferd_relay::DhtNode>>,

    /// The address our inbound peer transport listener is bound to (set by the
    /// daemon after spawning it). Used to publish direct `tcp://` endpoints so
    /// tailnet/LAN peers can connect without a relay.
    pub peer_listen: Option<std::net::SocketAddr>,

    /// Transient typing indicators: contact_id → unix ts until which the
    /// contact is considered "typing". Not persisted.
    pub typing_until: HashMap<String, u64>,

    // ── Persistence ──────────────────────────────────────────────────────────
    /// Path to the encrypted user data file.  `None` → persistence disabled
    /// (default for in-memory / test mode).
    pub store_path:   Option<PathBuf>,
    /// Argon2 parameters used for key derivation.
    pub store_params: StoreParams,
    /// Cached store credentials (derived AES-256 key + salt), set on
    /// `create_identity` / `restore_identity`. Saves reuse the key instead of
    /// re-running Argon2id on every mutation. Key is zeroized on drop.
    store_key: Option<transferd_store::StoreCredentials>,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self {
            identity:     None,
            contacts:     Vec::new(),
            messages:     HashMap::new(),
            groups:       HashMap::new(),
            transfers:    Vec::new(),
            settings:     HashMap::new(),
            calls:        HashMap::new(),
            next_id:      0,
            relay_engine: None,
            telemetry:    None,
            auth_token:   None,
            transport: Arc::new(tokio::sync::Mutex::new(crate::peer_manager::PeerConnectionManager::new())),
relay_hub:  None,
            dht:        None,
            peer_listen: None,
            typing_until: HashMap::new(),
            store_path:   None,
            store_params: StoreParams::production(),
            store_key:    None,
        }
    }
}

impl DaemonState {
    /// Create a state that persists to `path` using `params`.
    pub fn with_store(path: PathBuf, params: StoreParams) -> Self {
        Self { store_path: Some(path), store_params: params, ..Default::default() }
    }

    pub fn next_id(&mut self) -> String {
        self.next_id += 1;
        format!("d-{}", self.next_id)
    }

    // ── Persistence helpers ───────────────────────────────────────────────────

    /// Serialize the current in-memory state into a `PersistedUserData` snapshot.
    fn snapshot(&self) -> PersistedUserData {
        let id = self.identity.as_ref();
        PersistedUserData {
            version:              1,
            display_name:         id.map(|i| i.display_name.clone()).unwrap_or_default(),
            public_key_hex:       id.map(|i| i.public_key.clone()).unwrap_or_default(),
            hybrid_public_key_hex: id.map(|i| i.hybrid_public_key.clone()).unwrap_or_default(),
            recovery_phrase:      id.map(|i| i.phrase.clone()).unwrap_or_default(),
            contacts: self.contacts.iter().map(|c| transferd_store::PersistedContact {
                id:           c.id.clone(),
                name:         c.name.clone(),
                last_seen_ts: c.last_seen_ts,
                online:       c.online,
                blocked:      c.blocked,
                address:      c.address.clone(),
                hybrid_public_key: c.hybrid_public_key.clone(),
                limits:      c.limits.as_ref().and_then(|l| bincode::serialize(l).ok()),
            }).collect(),
messages: self.messages.iter().map(|(cid, msgs)| {
                let pm = msgs.iter().map(|m| transferd_store::PersistedMessage {
                    id:           m.id.clone(),
                    contact_id:   m.contact_id.clone(),
                    outbound:     m.outbound,
                    content_type: m.content_type.clone(),
                    text:         m.text.clone(),
                    file_name:    m.file_name.clone(),
                    file_size:    m.file_size,
                    file_xferd:   m.file_xferd,
                    file_mime:    m.file_mime.clone(),
                    timestamp_ts: m.timestamp_ts,
                    status:       m.status.clone(),
                    group_id:     m.group_id.clone(),
                    sender_pk:    m.sender_pk.clone(),
                    reply_to:     m.reply_to.clone(),
                    reactions:    m.reactions.clone(),
                }).collect();
                (cid.clone(), pm)
            }).collect(),
            groups: self.groups.iter().map(|(gid, g)| {
                let pg = transferd_store::PersistedGroup {
                    id: g.id.clone(),
                    name: g.name.clone(),
                    owner: g.owner.clone(),
                    members: g.members.iter().map(|m| transferd_store::PersistedGroupMember {
                        public_key: m.public_key.clone(),
                        role: m.role,
                    }).collect(),
                    created_at: g.created_at,
                };
                (gid.clone(), pg)
            }).collect(),
            settings:      self.settings.clone(),
            transfers:     self.transfers.iter().map(|t| transferd_store::PersistedTransfer {
                id:           t.id.clone(),
                contact_name: t.contact_name.clone(),
                file_name:    t.file_name.clone(),
                size_bytes:   t.size_bytes,
                xferd_bytes:  t.xferd_bytes,
                outbound:     t.outbound,
                lanes_active: t.lanes_active,
                bps:          t.bps,
            }).collect(),
            next_id:       self.next_id,
            created_at:    0,
            last_modified: now_secs(),
        }
    }

    /// Populate in-memory state from a `PersistedUserData` snapshot (loaded
    /// from disk after successful decryption).
    fn apply(&mut self, data: PersistedUserData) {
        self.identity = Some(Identity {
            public_key:        data.public_key_hex,
            hybrid_public_key: data.hybrid_public_key_hex,
            display_name:      data.display_name,
            phrase:            data.recovery_phrase,
        });
        self.contacts = data.contacts.into_iter().map(|c| Contact {
            id:           c.id,
            name:         c.name,
            last_seen_ts: c.last_seen_ts,
            online:       c.online,
            blocked:      c.blocked,
            address:      c.address,
            hybrid_public_key: c.hybrid_public_key,
            limits:      c.limits.as_ref().and_then(|b| bincode::deserialize(b).ok()),
        }).collect();
        self.messages = data.messages.into_iter().map(|(cid, msgs)| {
            let sm = msgs.into_iter().map(|m| StoredMessage {
                id:           m.id,
                contact_id:   m.contact_id,
                outbound:     m.outbound,
                content_type: m.content_type,
                text:         m.text,
                file_name:    m.file_name,
                file_size:    m.file_size,
                file_xferd:   m.file_xferd,
                file_mime:    m.file_mime,
                timestamp_ts: m.timestamp_ts,
status:       m.status,
                group_id:     m.group_id,
                sender_pk:    m.sender_pk,
                reply_to:     m.reply_to,
                reactions:    m.reactions,
            }).collect();
            (cid, sm)
        }).collect();
        self.groups = data.groups.into_iter().map(|(gid, g)| {
            let grp = Group {
                id: g.id,
                name: g.name,
                owner: g.owner,
                members: g.members.into_iter().map(|m| GroupMember {
                    public_key: m.public_key,
                    role: m.role,
                }).collect(),
                created_at: g.created_at,
            };
            (gid, grp)
        }).collect();
        self.settings = data.settings;
        self.transfers = data.transfers.into_iter().map(|t| Transfer {
            id:           t.id,
            contact_name: t.contact_name,
            file_name:    t.file_name,
            size_bytes:   t.size_bytes,
            xferd_bytes:  t.xferd_bytes,
            outbound:     t.outbound,
            lanes_active: t.lanes_active,
            bps:          t.bps,
        }).collect();
        self.next_id  = data.next_id;
    }

    /// Set the in-memory credentials used for subsequent saves.  Called after
    /// deriving the key on `create_identity` / `restore_identity`.
    ///
    /// Deriving Argon2id with production params is expensive, so this happens
    /// once here and the derived key is cached for all later saves.
    pub fn set_phrase(&mut self, phrase: &str) {
        if let Some(path) = &self.store_path {
            match transferd_store::StoreCredentials::derive(path, phrase, &self.store_params) {
                Ok(creds) => self.store_key = Some(creds),
                Err(e) => tracing::error!("transferd: key derivation failed: {e}"),
            }
        }
        // Also record the phrase in the identity for snapshot().
        if let Some(id) = &mut self.identity {
            id.phrase = phrase.to_owned();
        }
    }

    /// Derive the hybrid Ed25519 + ML-DSA-87 signing key from the recovery
    /// phrase. Returns `None` when no identity exists yet.
    pub fn hybrid_signing_key(&self) -> Option<HybridSigningKey> {
        let phrase = self.identity.as_ref()?.phrase.clone();
        let mnemonic = bip39::Mnemonic::parse(&phrase).ok()?;
        let seed = mnemonic.to_seed("");
        let seed_arr: &[u8; 64] = seed[..64].try_into().ok()?;
        Some(HybridSigningKey::from_bip39_seed(seed_arr))
    }

    /// Install a deterministic hybrid identity derived from `phrase`. Used by
    /// tests and CLI tooling to set up a daemon without the onboarding RPCs.
    /// Returns `false` when the phrase is invalid.
    pub fn install_identity(&mut self, phrase: &str, display_name: &str) -> bool {
        let Ok(mnemonic) = phrase.parse::<bip39::Mnemonic>() else { return false };
        let seed = mnemonic.to_seed("");
        let Ok(seed_arr) = seed[..64].try_into() else { return false };
        let sk = HybridSigningKey::from_bip39_seed(seed_arr);
        let vk = sk.verifying_key();
        let pk_hex = hex::encode(&vk.to_bytes()[..32]);
        let hybrid_pk_hex = vk.to_hex();
        self.identity = Some(Identity {
            public_key: pk_hex,
            hybrid_public_key: hybrid_pk_hex,
            display_name: display_name.to_owned(),
            phrase: phrase.to_owned(),
        });
        self.set_phrase(phrase);
        true
    }

    /// Record the verified hybrid identity for a contact (trust-on-first-use).
    /// Returns `Ok(true)` when accepted, `Ok(false)` when a previously-recorded
    /// identity differs (identity change — caller must refuse the session).
    pub fn record_verified_identity(&mut self, contact_id: &str, hybrid_pk_hex: &str) -> bool {
        let Some(c) = self.contacts.iter_mut().find(|c| c.id == contact_id) else {
            return true; // unknown contact: nothing to enforce
        };
        match &c.hybrid_public_key {
            Some(recorded) => recorded == hybrid_pk_hex,
            None => {
                c.hybrid_public_key = Some(hybrid_pk_hex.to_owned());
                self.try_save();
                true
            }
        }
    }

    /// Encrypt the current state and write it to `store_path`.
    /// No-op when `store_path` is `None` or no phrase has been set yet.
    pub fn try_save(&self) {
        let (path, creds) = match (&self.store_path, &self.store_key) {
            (Some(p), Some(k)) => (p, k),
            _ => return,
        };
        let data = self.snapshot();
        if let Err(e) = transferd_store::save_with_key(path, creds, &data) {
            tracing::error!("transferd: store save failed: {e}");
        }
    }

    /// Attempt to load persisted data from disk using `phrase`.
    ///
    /// Returns `true` and populates in-memory state on success.
    /// Returns `false` (without modifying state) if no file exists or the
    /// phrase is wrong.
    pub fn try_load(&mut self, phrase: &str) -> bool {
        let path = match &self.store_path {
            Some(p) => p.clone(),
            None    => return false,
        };
        if !transferd_store::file_exists(&path) {
            return false;
        }
        match transferd_store::load(&path, phrase, &self.store_params) {
            Ok(data) => {
                self.apply(data);
                // Cache derived credentials so later saves skip Argon2id.
                self.set_phrase(phrase);
                true
            }
            Err(e) => {
                tracing::error!("transferd: store load failed: {e}");
                false
            }
        }
    }

    // ── Inbound message handling ──────────────────────────────────────────────

    /// Record that a contact is currently online (from a received message).
    fn mark_contact_online(&mut self, contact_id: &str) {
if let Some(c) = self.contacts.iter_mut().find(|c| c.id == contact_id) {
            c.online = true;
            c.last_seen_ts = now_secs();
        }
    }

    /// Record (or clear) a transient typing indicator for a contact.
    pub fn mark_contact_typing(&mut self, contact_id: &str, until_ts: u64) {
        if until_ts == 0 {
            self.typing_until.remove(contact_id);
        } else {
            self.typing_until.insert(contact_id.to_string(), until_ts);
        }
    }

    /// Whether `contact_id` is currently marked as typing.
    pub fn is_typing(&self, contact_id: &str) -> bool {
        self.typing_until.get(contact_id).copied().unwrap_or(0) >= now_secs()
    }

    /// Toggle an emoji reaction from `reactor` on the message `target_msg_id`
    /// (searched across all threads). Adding a reaction the reactor already
    /// sent removes it; otherwise it is appended.
    pub fn toggle_reaction(&mut self, reactor: &str, target_msg_id: &str, emoji: &str) {
        for msgs in self.messages.values_mut() {
            if let Some(m) = msgs.iter_mut().find(|m| m.id == target_msg_id) {
                if let Some(pos) = m.reactions.iter().position(|(e, s)| e == emoji && s == reactor) {
                    m.reactions.remove(pos);
                } else {
                    m.reactions.push((emoji.to_string(), reactor.to_string()));
                }
                self.try_save();
                return;
            }
        }
    }

/// Store an inbound text message from `sender` and return its id. The id is
    /// the SENDER's own message id so both peers reference the same message
    /// (needed for replies and reactions). Duplicate ids are ignored.
    pub fn store_inbound_text(
        &mut self,
        sender: &str,
        msg_id: &str,
        text: &str,
        ts: u64,
        reply_to: Option<String>,
    ) -> String {
        self.mark_contact_online(sender);
        let thread = self.messages.entry(sender.to_string()).or_default();
        // Dedup ONLY true retransmits: the same sender re-sending the same
        // message id. The msg_id counter is per-daemon ("d-1", "d-2", …), so
        // two different peers can legitimately share an id — an outbound
        // message we sent to this contact must not shadow an inbound one from
        // them with the same id.
        if thread.iter().any(|m| m.id == msg_id && m.sender_pk == sender) {
            return msg_id.to_string(); // duplicate delivery (retransmit)
        }
        let id = msg_id.to_string();
        let msg = StoredMessage {
            id: id.clone(),
            contact_id: sender.to_string(),
            outbound: false,
            content_type: "text".into(),
            text: text.to_string(),
            file_name: String::new(),
            file_size: 0,
            file_xferd: 0,
            file_mime: String::new(),
            timestamp_ts: if ts == 0 { now_secs() } else { ts },
            status: "delivered".into(),
            group_id: None,
            sender_pk: sender.to_string(),
            reply_to,
            reactions: Vec::new(),
        };
        thread.push(msg);
        id
    }

    /// Store an inbound file-transfer record from `sender` and return its local id.
    pub fn store_inbound_file_meta(
        &mut self,
        sender: &str,
        file_name: &str,
        file_size: u64,
        mime: &str,
        ts: u64,
    ) -> String {
        self.mark_contact_online(sender);
        let id = self.next_id();
        let msg = StoredMessage {
            id: id.clone(),
            contact_id: sender.to_string(),
            outbound: false,
            content_type: "file".into(),
            text: String::new(),
            file_name: file_name.to_string(),
            file_size,
            file_xferd: file_size,
            file_mime: mime.to_string(),
            timestamp_ts: if ts == 0 { now_secs() } else { ts },
status: "received".into(),
            group_id: None,
            sender_pk: sender.to_string(),
            reply_to: None,
            reactions: Vec::new(),
        };
        self.messages.entry(sender.to_string()).or_default().push(msg);
        id
    }

/// Store an inbound group-thread text message under the group id. Uses the
    /// sender's message id so replies/reactions resolve on both sides.
    pub fn store_inbound_group_text(
        &mut self,
        group_id: &str,
        sender: &str,
        msg_id: &str,
        text: &str,
        ts: u64,
        reply_to: Option<String>,
    ) -> String {
        let thread = self.messages.entry(group_id.to_string()).or_default();
        if thread.iter().any(|m| m.id == msg_id) {
            return msg_id.to_string();
        }
        let id = msg_id.to_string();
        let msg = StoredMessage {
            id: id.clone(),
            contact_id: group_id.to_string(),
            outbound: false,
            content_type: "text".into(),
            text: text.to_string(),
            file_name: String::new(),
            file_size: 0,
            file_xferd: 0,
            file_mime: String::new(),
            timestamp_ts: if ts == 0 { now_secs() } else { ts },
            status: "delivered".into(),
            group_id: Some(group_id.to_string()),
            sender_pk: sender.to_string(),
            reply_to,
            reactions: Vec::new(),
        };
        thread.push(msg);
        id
    }

    /// Update the delivery status of a stored message by its local id.
    pub fn mark_status(&mut self, msg_id: &str, status: &str) {
        for msgs in self.messages.values_mut() {
            if let Some(m) = msgs.iter_mut().find(|m| m.id == msg_id) {
                m.status = status.to_string();
                return;
            }
        }
    }

/// Apply an inbound wire message to local state. Returns a reply message
    /// (an `Ack`) when the peer expects one.
    pub fn apply_inbound(&mut self, msg: &crate::wire::WireMsg) -> Option<crate::wire::WireMsg> {
        use crate::wire::WireMsg;
        match msg {
            WireMsg::Text { sender, msg_id, text, ts, group_id, reply_to } => {
                if let Some(gid) = group_id {
                    self.store_inbound_group_text(gid, sender, msg_id, text, *ts, reply_to.clone());
                } else {
                    self.store_inbound_text(sender, msg_id, text, *ts, reply_to.clone());
                    // Only raise a notification for genuinely new messages.
                    self.fire_inbound_notify(sender, text);
                }
                Some(WireMsg::Ack { msg_id: msg_id.clone() })
            }
            WireMsg::File { sender, msg_id, file_name, file_size, mime, ts, seq, total_chunks, .. } => {
                // Only store the record (and ack) once the full file has arrived.
                if seq + 1 >= *total_chunks && *total_chunks > 0 {
                    self.store_inbound_file_meta(sender, file_name, *file_size, mime, *ts);
                    Some(WireMsg::Ack { msg_id: msg_id.clone() })
                } else {
                    None
                }
            }
            WireMsg::Ack { msg_id } => {
                self.mark_status(msg_id, "delivered");
                None
            }
            WireMsg::Read { msg_id } => {
                self.mark_status(msg_id, "read");
                None
            }
            WireMsg::Typing { sender, is_typing } => {
                if *is_typing {
                    self.mark_contact_typing(sender, now_secs() + TYPING_WINDOW_SECS);
                } else {
                    self.mark_contact_typing(sender, 0);
                }
                None
            }
            WireMsg::Reaction { sender, target_msg_id, emoji } => {
                self.toggle_reaction(sender, target_msg_id, emoji);
                None
            }
        }
    }
}

/// How long a "is typing…" indicator stays visible after the last typing event.
const TYPING_WINDOW_SECS: u64 = 4;

/// Global hook fired when a new inbound 1:1 text message arrives
/// `(sender_name, text, contact_id)`. Used by mobile to raise system
/// notifications; no-op when unset.
type InboundNotify = Box<dyn Fn(&str, &str, &str) + Send + Sync>;
static INBOUND_NOTIFY: OnceLock<InboundNotify> = OnceLock::new();

/// Install a global inbound-message notification hook.
pub fn set_inbound_notify<F: Fn(&str, &str, &str) + Send + Sync + 'static>(f: F) {
    let _ = INBOUND_NOTIFY.set(Box::new(f));
}

impl DaemonState {
    fn fire_inbound_notify(&self, sender: &str, text: &str) {
        if let Some(f) = INBOUND_NOTIFY.get() {
            let name = self.contacts.iter()
                .find(|c| c.id == sender)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| sender.to_string());
            f(&name, text, sender);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::WireMsg;

    #[test]
    fn inbound_text_uses_sender_id_and_dedups() {
        let mut s = DaemonState::default();
        let id = s.store_inbound_text("peer", "msg-1", "hello", 100, None);
        assert_eq!(id, "msg-1");
        // Duplicate delivery (same sender + id) is ignored.
        let id2 = s.store_inbound_text("peer", "msg-1", "hello", 100, None);
        assert_eq!(id2, "msg-1");
        assert_eq!(s.messages["peer"].len(), 1);
        assert_eq!(s.messages["peer"][0].reply_to, None);
        // A reply records the quoted id.
        s.store_inbound_text("peer", "msg-2", "replying", 101, Some("msg-1".into()));
        assert_eq!(s.messages["peer"][1].reply_to.as_deref(), Some("msg-1"));
        // An OUTBOUND message we sent with the same id as an inbound one must
        // not shadow it: the per-daemon counter makes "d-1" collide across
        // peers. Our outbound message has sender_pk = "" (we are the sender),
        // so a different sender's inbound "d-1" is a distinct message.
        s.messages.entry("peer".into()).or_default().push(StoredMessage {
            sender_pk: String::new(), // outbound from us
            id: "d-1".into(),
            ..StoredMessage::new_text("d-1".into(), "peer".into(), true, "from me".into())
        });
        s.store_inbound_text("peer", "d-1", "from them", 200, None);
        assert_eq!(s.messages["peer"].len(), 4, "colliding id from another peer must be stored");
        assert!(s.messages["peer"].iter().any(|m| m.text == "from them" && !m.outbound));
    }

    #[test]
    fn apply_typing_sets_indicator() {
        let mut s = DaemonState::default();
        s.contacts.push(Contact {
            id: "peer".into(),
            name: "Peer".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: None,
            hybrid_public_key: None,
            limits: None,
        });
        let typing = WireMsg::Typing { sender: "peer".into(), is_typing: true };
        s.apply_inbound(&typing);
        assert!(s.is_typing("peer"));
        let stop = WireMsg::Typing { sender: "peer".into(), is_typing: false };
        s.apply_inbound(&stop);
        assert!(!s.is_typing("peer"));
    }

    #[test]
    fn apply_reaction_toggles() {
        let mut s = DaemonState::default();
        s.store_inbound_text("peer", "msg-1", "hello", 100, None);
        s.toggle_reaction("peer", "msg-1", "❤️");
        assert_eq!(s.messages["peer"][0].reactions.len(), 1);
        // Same reactor + emoji removes it.
        s.toggle_reaction("peer", "msg-1", "❤️");
        assert!(s.messages["peer"][0].reactions.is_empty());
        // A different reactor adds a distinct entry.
        s.toggle_reaction("me", "msg-1", "❤️");
        assert_eq!(s.messages["peer"][0].reactions.len(), 1);
    }

    #[test]
    fn record_verified_identity_first_use_records() {
        let mut s = DaemonState::default();
        s.contacts.push(Contact {
            id: "ab".repeat(32),
            name: "Peer".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: None,
            hybrid_public_key: None,
            limits: None,
        });
        assert!(s.record_verified_identity(&"ab".repeat(32), &"cd".repeat(1312)));
        assert_eq!(s.contacts[0].hybrid_public_key.as_deref(), Some("cd".repeat(1312).as_str()));
    }

    #[test]
    fn record_verified_identity_rejects_change() {
        let mut s = DaemonState::default();
        s.contacts.push(Contact {
            id: "ab".repeat(32),
            name: "Peer".into(),
            last_seen_ts: 0,
            online: false,
            blocked: false,
            address: None,
            hybrid_public_key: Some("cd".repeat(1312)),
            limits: None,
        });
        assert!(s.record_verified_identity(&"ab".repeat(32), &"cd".repeat(1312)), "same identity ok");
        assert!(!s.record_verified_identity(&"ab".repeat(32), &"ef".repeat(1312)), "changed identity rejected");
    }
}
