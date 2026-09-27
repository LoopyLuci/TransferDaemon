//! gRPC service implementations for all six TransferDaemon services.

use std::pin::Pin;
use std::sync::Arc;
use parking_lot::Mutex;
use tonic::{Request, Response, Status};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;

use transferd_api::{
    // Account
    AccountService,
    CreateIdentityRequest, RestoreIdentityRequest, IdentityReply,
    RecoveryPhraseReply, PublicKeyReply, Empty,
    // Friends
    FriendService,
    AddContactRequest, ContactReply, ContactList,
    RenameContactRequest, RemoveContactRequest, BlockContactRequest,
    SafetyNumberRequest, SafetyNumberReply,
    UpdateService, UpdateServiceServer, UpdateReply,
    // Messages
    MessageService,
    GetMessagesRequest, MessageReply, MessageList, SendTextRequest, SearchMessagesRequest,
    SendTypingRequest, ReactionRequest, Reaction,
    // Transfers
    TransferService,
    CancelTransferRequest, TransferReply, TransferList, SendFileRequest,
    // Settings
    SettingsService,
    GetSettingRequest, SetSettingRequest, SettingReply,
    // Calls
    CallService,
    CallStartRequest, CallStartResponse,
    CallAcceptRequest, CallAcceptResponse,
    CallRejectRequest, CallEndRequest,
    IceCandidateMsg, CallEvent,
    // Groups
    GroupService,
    // Telemetry
    TelemetryService,
    TelemetryEventMsg, TelemetrySnapshot,
    SystemHealthMsg, AteLaneMsg,
};

use crate::state::{DaemonState, Contact, CallRecord, StoredMessage, now_secs};
use rand::rngs::OsRng;
use rand::RngCore;
use transferd_crypto::identity::HybridSigningKey;

type State = Arc<Mutex<DaemonState>>;
type BoxStream<T> = Pin<Box<dyn futures::Stream<Item = Result<T, Status>> + Send>>;

/// Establish a transport session for a contact.
///
/// Address resolution: an explicit contact address is used when present;
/// otherwise the contact's relay endpoint is discovered via the DHT.
/// Address formats:
///   `relay://host:port/<64-hex-token>` → relay session via the daemon's RelayHub
///   `<host>:<port>` → direct TCP session
///
/// Returns `true` if a session exists (or was just established).
async fn ensure_contact_session(state: &State, contact_id: &str, address: Option<&str>) -> bool {
    let transport = state.lock().transport.clone();
    if transport.lock().await.has_session(contact_id) {
        return true;
    }

    // Resolve the endpoint address(es): explicit, or DHT-discovered by public
    // key (which may return MULTIPLE relays the peer is reachable through).
    // (The parking_lot guard is dropped before any await so the future stays Send.)
    let (resolved, _discovered_limits): (Vec<String>, Option<relayd::limits::TransferLimits>) = match address {
        Some(addr) => (vec![addr.to_owned()], None),
        None => {
            let dht = { let s = state.lock(); s.dht.clone() };
            match dht {
                Some(dht) => {
                    match crate::peer_discovery::resolve_peer(&dht, contact_id).await {
                        Some((addrs, limits)) => {
                            tracing::info!("[grpc] discovered {} relay endpoint(s) for {contact_id}", addrs.len());
                            // Cache the peer's advertised limits on the contact
                            // so the send path can enforce them.
                            if let Some(l) = limits.clone() {
                                let mut s = state.lock();
                                if let Some(c) = s.contacts.iter_mut().find(|c| c.id == contact_id) {
                                    c.limits = Some(l);
                                }
                            }
                            (addrs, limits)
                        }
                        None => (Vec::new(), None),
                    }
                }
                None => (Vec::new(), None),
            }
        }
    };
    if resolved.is_empty() {
        return false;
    }

    // Policy steers which transports may be used.
    let policy = { let s = state.lock(); s.settings.get("conn.policy").cloned().unwrap_or_else(|| "auto".into()) };

    // Prefer a direct address when discovered — `tcp://host:port` (LAN /
    // Tailscale P2P) or a scheme-less `host:port` (legacy Contact.address) —
    // otherwise use the relay set.
    let direct = resolved.iter().find(|a| {
        a.starts_with("tcp://") || (!a.starts_with("relay://") && !a.starts_with("wsrelay://"))
    });
    let direct_addr = direct.map(|a| a.trim_start_matches("tcp://"));
    let relays: Vec<&String> = resolved
        .iter()
        .filter(|a| a.starts_with("relay://") || a.starts_with("wsrelay://"))
        .collect();

    let session = if let Some(d) = direct_addr {
        if policy == "relay" {
            tracing::info!("[grpc] policy=relay: skipping direct lane to {contact_id}");
            return false;
        }
        let identity = match state.lock().hybrid_signing_key() {
            Some(id) => id,
            None => {
                tracing::warn!("[grpc] no identity: cannot establish session to {contact_id}");
                return false;
            }
        };
        crate::peer_manager::establish_tcp_session(contact_id, d, &identity).await
    } else if !relays.is_empty() {
        if policy == "direct" {
            tracing::info!("[grpc] policy=direct: skipping relay lane to {contact_id}");
            return false;
        }
        // Keep only relays this daemon is ALSO registered on (a relay lane is
        // only useful when both sides can reach the same relay).
        let hub = { let s = state.lock(); s.relay_hub.clone() };
        let mut shared: Vec<std::net::SocketAddr> = Vec::new();
        let mut token = String::new();
        for r in &relays {
            // Both `relay://host:port/token` and `wsrelay://host:port/token`;
            // the host may be a DNS name (e.g. a Cloudflare Worker).
            let rest = r
                .strip_prefix("relay://")
                .or_else(|| r.strip_prefix("wsrelay://"));
            if let Some((a, t)) = rest.and_then(|r| r.split_once('/')) {
                if let Some(addr) = crate::relay_hub::resolve_addr(a) {
                    if hub.as_ref().map(|h| h.has_relay(addr)).unwrap_or(false) {
                        shared.push(addr);
                        token = t.to_string();
                    }
                }
            }
        }
        if shared.is_empty() {
            tracing::warn!(
                "[grpc] no shared relay with {contact_id} among {} candidate(s)",
                relays.len()
            );
            return false;
        }
        crate::peer_manager::establish_relay_session(contact_id, &shared, &token, state).await
    } else {
        return false;
    };
    match session {
        Ok((s, peer_hybrid_pk)) => {
            // Trust-on-first-use: record the verified hybrid fingerprint, and
            // refuse the session if a recorded identity has changed.
            let fingerprint_ok = {
                let mut st = state.lock();
                let ok = st.record_verified_identity(contact_id, &hex::encode(&peer_hybrid_pk));
                if !ok {
                    tracing::warn!(
                        "[grpc] refusing session to {contact_id}: peer identity changed since first contact"
                    );
                }
                ok
            };
            if !fingerprint_ok {
                return false;
            }
            transport.lock().await.insert_session(contact_id, s);
            true
        }
        Err(e) => {
            tracing::warn!("[grpc] could not establish session to {contact_id}: {e}");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// AccountServiceImpl
// ---------------------------------------------------------------------------

pub struct AccountServiceImpl(pub State);

#[tonic::async_trait]
impl AccountService for AccountServiceImpl {
    async fn get_identity(&self, _: Request<Empty>) -> Result<Response<IdentityReply>, Status> {
        let s = self.0.lock();
        Ok(Response::new(match &s.identity {
            Some(id) => IdentityReply {
                has_identity:      true,
                public_key:        id.public_key.clone(),
                hybrid_public_key: id.hybrid_public_key.clone(),
                display_name:      id.display_name.clone(),
            },
            None => IdentityReply { has_identity: false, ..Default::default() },
        }))
    }

    async fn create_identity(
        &self, req: Request<CreateIdentityRequest>,
    ) -> Result<Response<RecoveryPhraseReply>, Status> {
        let name = req.into_inner().display_name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("display name required"));
        }

        // 128 bits of fresh OS entropy → 12-word BIP-39 mnemonic.
        let mut entropy = [0u8; 16];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| Status::internal(format!("mnemonic generation failed: {e}")))?;
        let phrase = mnemonic.to_string();

        // Derive hybrid Ed25519 + ML-DSA-87 key pair from the 64-byte BIP-39 seed.
        let seed = mnemonic.to_seed("");
        let seed_arr: &[u8; 64] = seed[..64].try_into()
            .map_err(|_| Status::internal("seed too short"))?;
        let hybrid_sk = HybridSigningKey::from_bip39_seed(seed_arr);
        let hybrid_vk = hybrid_sk.verifying_key();
        // Classical public key (first 32 bytes of hybrid key, hex-encoded).
        let pk_hex = hex::encode(&hybrid_vk.to_bytes()[..32]);
        let hybrid_pk_hex = hybrid_vk.to_hex();

        let mut s = self.0.lock();
        s.identity = Some(crate::state::Identity {
            public_key:        pk_hex,
            hybrid_public_key: hybrid_pk_hex,
            display_name:      name,
            phrase:            phrase.clone(),
        });
        s.set_phrase(&phrase);
        s.try_save();

        // If a relay is configured, register our inbound token (token depends on
        // the just-created public key).
        if crate::relay_hub::relay_enabled() {
            tokio::spawn(crate::relay_hub::spawn_inbound_relay_listener(self.0.clone()));
        }
        // Start DHT discovery (if configured) and publish our endpoint.
        tokio::spawn(crate::peer_discovery::ensure_dht(self.0.clone()));

        Ok(Response::new(RecoveryPhraseReply { phrase }))
    }

    async fn restore_identity(
        &self, req: Request<RestoreIdentityRequest>,
    ) -> Result<Response<IdentityReply>, Status> {
        let phrase_str = req.into_inner().phrase;

        // Parse and validate the BIP-39 phrase (also rejects unknown words).
        let mnemonic = phrase_str.trim().parse::<bip39::Mnemonic>()
            .map_err(|e| Status::invalid_argument(format!("invalid recovery phrase: {e}")))?;

        // Re-derive the hybrid Ed25519 + ML-DSA-87 key pair from the phrase.
        let seed = mnemonic.to_seed("");
        let seed_arr: &[u8; 64] = seed[..64].try_into()
            .map_err(|_| Status::internal("seed too short"))?;
        let hybrid_sk = HybridSigningKey::from_bip39_seed(seed_arr);
        let hybrid_vk = hybrid_sk.verifying_key();
        let pk_hex = hex::encode(&hybrid_vk.to_bytes()[..32]);
        let hybrid_pk_hex = hybrid_vk.to_hex();

        let mut s = self.0.lock();

        // Try to load the full persisted state (contacts, messages, display
        // name) from disk.  This is the primary path after a clean restart.
        let loaded_from_disk = s.try_load(&phrase_str);

        if !loaded_from_disk {
            // No store file (or wrong phrase) — reconstruct the key only.
            // Preserve in-memory display name if we happen to have it, otherwise
            // leave blank so the UI can prompt the user to set one.
            let display_name = s.identity.as_ref()
                .map(|i| i.display_name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_default();
            s.identity = Some(crate::state::Identity {
                public_key:        pk_hex.clone(),
                hybrid_public_key: hybrid_pk_hex.clone(),
                display_name:      display_name.clone(),
                phrase:            phrase_str.clone(),
            });
            s.set_phrase(&phrase_str);
            s.try_save(); // create the store file for future restores
        } else if let Some(ref mut id) = s.identity {
            // Upgrade: if an existing store lacked the hybrid key, populate it now.
            if id.hybrid_public_key.is_empty() {
                id.hybrid_public_key = hybrid_pk_hex;
                s.try_save();
            }
        }

        let (pk, hpk, name) = {
            let id = s.identity.as_ref()
                .ok_or_else(|| Status::internal("identity not initialised after restore"))?;
            (id.public_key.clone(), id.hybrid_public_key.clone(), id.display_name.clone())
        };

        // If a relay is configured, register our inbound token for this identity.
        if crate::relay_hub::relay_enabled() {
            tokio::spawn(crate::relay_hub::spawn_inbound_relay_listener(self.0.clone()));
        }
        // Start DHT discovery (if configured) and publish our endpoint.
        tokio::spawn(crate::peer_discovery::ensure_dht(self.0.clone()));

        Ok(Response::new(IdentityReply {
            has_identity:      true,
            public_key:        pk,
            hybrid_public_key: hpk,
            display_name:      name,
        }))
    }

    async fn get_public_key_hex(&self, _: Request<Empty>) -> Result<Response<PublicKeyReply>, Status> {
        let s = self.0.lock();
        Ok(Response::new(PublicKeyReply {
            hex: s.identity.as_ref().map(|i| i.public_key.clone()).unwrap_or_default(),
        }))
    }
}

// ---------------------------------------------------------------------------
// FriendServiceImpl
// ---------------------------------------------------------------------------

pub struct FriendServiceImpl(pub State);

#[tonic::async_trait]
impl FriendService for FriendServiceImpl {
    async fn get_contacts(&self, _: Request<Empty>) -> Result<Response<ContactList>, Status> {
        let s = self.0.lock();
        let contacts = s.contacts.iter().map(|c| ContactReply {
            id:           c.id.clone(),
            name:         c.name.clone(),
            last_seen_ts: c.last_seen_ts,
            online:       c.online,
            blocked:      c.blocked,
            typing:       s.is_typing(&c.id),
        }).collect();
        Ok(Response::new(ContactList { contacts }))
    }

    async fn add_contact(
        &self, req: Request<AddContactRequest>,
    ) -> Result<Response<ContactReply>, Status> {
        let r = req.into_inner();
        if r.public_key.len() != 64 {
            return Err(Status::invalid_argument("public key must be 64 hex chars"));
        }
        if r.name.trim().is_empty() {
            return Err(Status::invalid_argument("name required"));
        }
        let contact = Contact {
            id:           r.public_key.clone(),
            name:         r.name.clone(),
            last_seen_ts: 0,
            online:       false,
            blocked:      false,
            address:      None,
            hybrid_public_key: None,
            limits:      None,
        };
        let mut s = self.0.lock();
        // Prevent duplicates.
        if s.contacts.iter().any(|c| c.id == r.public_key) {
            return Err(Status::already_exists("contact already exists"));
        }
        s.contacts.push(contact);
        s.try_save();
        Ok(Response::new(ContactReply {
            id:           r.public_key,
            name:         r.name,
            last_seen_ts: 0,
            online:       false,
            blocked:      false,
            typing:       false,
        }))
    }

    async fn rename_contact(
        &self, req: Request<RenameContactRequest>,
    ) -> Result<Response<ContactReply>, Status> {
        let r = req.into_inner();
        if r.name.trim().is_empty() {
            return Err(Status::invalid_argument("name required"));
        }
        let mut s = self.0.lock();
        let contact = s.contacts.iter_mut().find(|c| c.id == r.contact_id)
            .ok_or_else(|| Status::not_found("contact not found"))?;
        contact.name = r.name.clone();
        let reply = ContactReply {
            id:           contact.id.clone(),
            name:         contact.name.clone(),
            last_seen_ts: contact.last_seen_ts,
            online:       contact.online,
            blocked:      contact.blocked,
            typing:       false,
        };
        s.try_save();
        Ok(Response::new(reply))
    }

    async fn remove_contact(
        &self, req: Request<RemoveContactRequest>,
    ) -> Result<Response<Empty>, Status> {
        let contact_id = req.into_inner().contact_id;
        let mut s = self.0.lock();
        let before = s.contacts.len();
        s.contacts.retain(|c| c.id != contact_id);
        // Remove the conversation history too.
        s.messages.remove(&contact_id);
        s.transfers.retain(|t| t.contact_name != contact_id);
        if s.contacts.len() == before {
            return Err(Status::not_found("contact not found"));
        }
        s.try_save();
        Ok(Response::new(Empty {}))
    }

    async fn block_contact(
        &self, req: Request<BlockContactRequest>,
    ) -> Result<Response<ContactReply>, Status> {
        self.set_blocked(req.into_inner().contact_id, true)
    }

    async fn unblock_contact(
        &self, req: Request<BlockContactRequest>,
    ) -> Result<Response<ContactReply>, Status> {
        self.set_blocked(req.into_inner().contact_id, false)
    }

    async fn get_safety_number(
        &self, req: Request<SafetyNumberRequest>,
    ) -> Result<Response<SafetyNumberReply>, Status> {
        let contact_id = req.into_inner().contact_id;
        let (our_pk, peer_pk) = {
            let s = self.0.lock();
            let our = s.identity.as_ref().map(|i| i.hybrid_public_key.clone()).unwrap_or_default();
            let peer = s.contacts.iter().find(|c| c.id == contact_id)
                .and_then(|c| c.hybrid_public_key.clone())
                .unwrap_or_default();
            (our, peer)
        };
        if our_pk.is_empty() || peer_pk.is_empty() {
            return Ok(Response::new(SafetyNumberReply {
                safety_number: String::new(),
                verified: false,
            }));
        }
        let number = crate::safety::safety_number(&our_pk, &peer_pk)
            .ok_or_else(|| Status::internal("invalid identity material"))?;
        Ok(Response::new(SafetyNumberReply {
            safety_number: number,
            verified: true,
        }))
    }
}

impl FriendServiceImpl {
    /// Set or clear the blocked flag on a contact and persist.
    #[allow(clippy::result_large_err)]
    fn set_blocked(&self, contact_id: String, blocked: bool) -> Result<Response<ContactReply>, Status> {
        let mut s = self.0.lock();
        let contact = s.contacts.iter_mut().find(|c| c.id == contact_id)
            .ok_or_else(|| Status::not_found("contact not found"))?;
        contact.blocked = blocked;
        let reply = ContactReply {
            id:           contact.id.clone(),
            name:         contact.name.clone(),
            last_seen_ts: contact.last_seen_ts,
            online:       contact.online,
            blocked:      contact.blocked,
            typing:       false,
        };
        s.try_save();
        Ok(Response::new(reply))
    }
}

// ---------------------------------------------------------------------------
// MessageServiceImpl
// ---------------------------------------------------------------------------

pub struct MessageServiceImpl(pub State);

fn stored_to_reply(m: &StoredMessage) -> MessageReply {
    MessageReply {
        id:               m.id.clone(),
        contact_id:       m.contact_id.clone(),
        outbound:         m.outbound,
        content_type:     m.content_type.clone(),
        text:             m.text.clone(),
        file_name:        m.file_name.clone(),
        file_size_bytes:  m.file_size,
        file_transferred: m.file_xferd,
        file_mime:        m.file_mime.clone(),
        timestamp_ts:     m.timestamp_ts,
        status:           m.status.clone(),
        group_id:         m.group_id.clone().unwrap_or_default(),
        sender_pk:        m.sender_pk.clone(),
        reply_to:         m.reply_to.clone().unwrap_or_default(),
        reactions:        m.reactions.iter().map(|(e, s)| Reaction {
            emoji:  e.clone(),
            sender: s.clone(),
        }).collect(),
    }
}

#[tonic::async_trait]
impl MessageService for MessageServiceImpl {
    async fn get_messages(
        &self, req: Request<GetMessagesRequest>,
    ) -> Result<Response<MessageList>, Status> {
        let cid = req.into_inner().contact_id;
        let s = self.0.lock();
        let messages = s.messages.get(&cid)
            .map(|v| v.iter().map(stored_to_reply).collect())
            .unwrap_or_default();
        Ok(Response::new(MessageList { messages }))
    }
    async fn search_messages(
         &self, req: Request<SearchMessagesRequest>,
     ) -> Result<Response<MessageList>, Status> {
         let r = req.into_inner();
         let q = r.query.to_lowercase();
         let s = self.0.lock();
         let messages = s.messages.get(&r.contact_id)
             .map(|v| v.iter()
                 .filter(|m| m.content_preview().to_lowercase().contains(&q))
                 .map(stored_to_reply)
                 .collect())
             .unwrap_or_default();
         Ok(Response::new(MessageList { messages }))
     }

    async fn send_text(
        &self, req: Request<SendTextRequest>,
    ) -> Result<Response<MessageReply>, Status> {
        let r = req.into_inner();
        if r.text.trim().is_empty() {
            return Err(Status::invalid_argument("message text required"));
        }

        let contact_id = r.contact_id.clone();
        let reply_to = if r.reply_to.is_empty() { None } else { Some(r.reply_to.clone()) };

        // 0. Outbound limit check: our own message cap applies to what we send;
        //    a peer's advertised cap (if known) is the tighter bound.
        let outbound = crate::limits::daemon_limits_with(&self.0.lock().settings.clone());
        let peer_limits = {
            let s = self.0.lock();
            s.contacts.iter().find(|c| c.id == contact_id).and_then(|c| c.limits.clone())
        };
        let cap = crate::limits::peer_cap(peer_limits.as_ref(), relayd::limits::ContentType::Message)
            .unwrap_or_else(|| outbound.cap_for(relayd::limits::ContentType::Message).unwrap_or(u64::MAX));
        if (r.text.len() as u64) > cap {
            return Err(Status::failed_precondition(crate::limits::refusal_reason(
                relayd::limits::ContentType::Message,
                r.text.len() as u64,
                cap,
            )));
        }

        // 1. Resolve the contact's direct address (short state lock).
        let address = {
            let s = self.0.lock();
            s.contacts.iter().find(|c| c.id == contact_id)
                .and_then(|c| c.address.clone())
        };

        // 2. Establish a lane session (direct TCP or relay) if we know the
        //    address and none exists. The async connect + handshake runs on the
        //    transport mutex, never while holding the global state lock.
        let transport = self.0.lock().transport.clone();
        ensure_contact_session(&self.0, &contact_id, address.as_deref()).await;

        // 3. Store the message locally (pending until actually dispatched).
        let reply;
        let msg_id;
        let payload;
        {
            let mut s = self.0.lock();
            let id = s.next_id();
            let mut msg = StoredMessage::new_text(id.clone(), contact_id.clone(), true, r.text.clone());
            msg.status = "pending".into();
            msg.reply_to = reply_to.clone();
            reply = stored_to_reply(&msg);
            s.messages.entry(contact_id.clone()).or_default().push(msg);
            s.try_save();
            let sender_pk = s.identity.as_ref().map(|i| i.public_key.clone()).unwrap_or_default();
            msg_id = id;
            payload = crate::wire::WireMsg::Text {
                sender: sender_pk,
                msg_id: msg_id.clone(),
                text: r.text.clone(),
                ts: now_secs(),
                group_id: None,
                reply_to,
            }
            .encode()
            .map_err(|_| Status::internal("failed to encode message"))?;
        }

        // 4. Queue the message for delivery over the lane.
        {
            let mut pm = transport.lock().await;
            if pm.has_session(&contact_id) {
                let _ = pm.send_message(&contact_id, msg_id, bytes::Bytes::from(payload));
            } else {
                tracing::debug!("[grpc] send_text: queued locally only (no session) for {contact_id}");
            }
        }

        tracing::info!("[grpc] send_text to {contact_id}: queued for lane delivery");
        Ok(Response::new(reply))
    }

    async fn send_typing(
        &self, req: Request<SendTypingRequest>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();
        let contact_id = r.contact_id.clone();
        let address = {
            let s = self.0.lock();
            s.contacts.iter().find(|c| c.id == contact_id)
                .and_then(|c| c.address.clone())
        };
        let transport = self.0.lock().transport.clone();
        ensure_contact_session(&self.0, &contact_id, address.as_deref()).await;

        let sender_pk = self.0.lock().identity.as_ref().map(|i| i.public_key.clone()).unwrap_or_default();
        let payload = crate::wire::WireMsg::Typing { sender: sender_pk, is_typing: r.is_typing }
            .encode()
            .map_err(|_| Status::internal("failed to encode typing"))?;
        let mut pm = transport.lock().await;
        if pm.has_session(&contact_id) {
            let _ = pm.send_message(&contact_id, String::new(), bytes::Bytes::from(payload));
        }
        Ok(Response::new(Empty {}))
    }

    async fn toggle_reaction(
        &self, req: Request<ReactionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();
        let contact_id = r.contact_id.clone();
        let address = {
            let s = self.0.lock();
            s.contacts.iter().find(|c| c.id == contact_id)
                .and_then(|c| c.address.clone())
        };
        let transport = self.0.lock().transport.clone();
        ensure_contact_session(&self.0, &contact_id, address.as_deref()).await;

        let sender_pk = self.0.lock().identity.as_ref().map(|i| i.public_key.clone()).unwrap_or_default();
        // Apply locally (toggle), then notify the peer.
        {
            let mut s = self.0.lock();
            s.toggle_reaction(&sender_pk, &r.target_msg_id, &r.emoji);
        }
        let payload = crate::wire::WireMsg::Reaction {
            sender: sender_pk,
            target_msg_id: r.target_msg_id.clone(),
            emoji: r.emoji,
        }
        .encode()
        .map_err(|_| Status::internal("failed to encode reaction"))?;
        let mut pm = transport.lock().await;
        if pm.has_session(&contact_id) {
            let _ = pm.send_message(&contact_id, String::new(), bytes::Bytes::from(payload));
        }
        Ok(Response::new(Empty {}))
    }
}

// ---------------------------------------------------------------------------
// UpdateServiceImpl (manual, opt-in — never runs in the background)
// ---------------------------------------------------------------------------

pub struct UpdateServiceImpl;

#[tonic::async_trait]
impl UpdateService for UpdateServiceImpl {
    async fn check_for_updates(
        &self, _: Request<Empty>,
    ) -> Result<Response<UpdateReply>, Status> {
        use crate::update::{UpdateCheckResult, CURRENT_VERSION};
        match crate::update::check_for_updates().await {
            UpdateCheckResult::UpToDate => Ok(Response::new(UpdateReply {
                current_version: CURRENT_VERSION.to_string(),
                has_update: false,
                new_version: String::new(),
                release_notes: String::new(),
                download_url: String::new(),
                error: String::new(),
            })),
            UpdateCheckResult::UpdateAvailable(info) => Ok(Response::new(UpdateReply {
                current_version: CURRENT_VERSION.to_string(),
                has_update: true,
                new_version: info.version,
                release_notes: info.release_notes,
                download_url: info.download_url,
                error: String::new(),
            })),
            UpdateCheckResult::Error(e) => Ok(Response::new(UpdateReply {
                current_version: CURRENT_VERSION.to_string(),
                has_update: false,
                new_version: String::new(),
                release_notes: String::new(),
                download_url: String::new(),
                error: e,
            })),
        }
    }

    async fn apply_update(
        &self, _: Request<Empty>,
    ) -> Result<Response<Empty>, Status> {
        match crate::update::check_for_updates().await {
            crate::update::UpdateCheckResult::UpdateAvailable(info) => {
                let path = crate::update::download_update(&info)
                    .await
                    .map_err(|e| Status::internal(format!("download failed: {e}")))?;
                crate::update::install_update(&path)
                    .map_err(|e| Status::internal(format!("install failed: {e}")))?;
                Ok(Response::new(Empty {}))
            }
            crate::update::UpdateCheckResult::UpToDate => {
                Err(Status::failed_precondition("already up to date"))
            }
            crate::update::UpdateCheckResult::Error(e) => Err(Status::unavailable(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// TransferServiceImpl
// ---------------------------------------------------------------------------

pub struct TransferServiceImpl(pub State);

#[tonic::async_trait]
impl TransferService for TransferServiceImpl {
    async fn get_transfers(&self, _: Request<Empty>) -> Result<Response<TransferList>, Status> {
        let s = self.0.lock();
        let transfers = s.transfers.iter().map(|t| TransferReply {
            id:               t.id.clone(),
            contact_name:     t.contact_name.clone(),
            file_name:        t.file_name.clone(),
            size_bytes:       t.size_bytes,
            transferred_bytes: t.xferd_bytes,
            outbound:         t.outbound,
            lanes_active:     t.lanes_active,
            bps:              t.bps,
        }).collect();
        Ok(Response::new(TransferList { transfers }))
    }

    async fn send_file(
        &self, req: Request<SendFileRequest>,
    ) -> Result<Response<MessageReply>, Status> {
        let r = req.into_inner();
        if r.contact_id.is_empty() {
            return Err(Status::invalid_argument("contact_id required"));
        }

        // Read the file into memory (bounded). Larger files will stream from
        // disk in a future iteration; this covers the common transfer size.
        let data = std::fs::read(&r.file_path)
            .map_err(|e| Status::not_found(format!("cannot read '{}': {e}", r.file_path)))?;
        if data.len() > 200 * 1024 * 1024 {
            return Err(Status::resource_exhausted(
                "files over 200 MB need chunked disk streaming (coming soon)",
            ));
        }
        let size_bytes = data.len() as u64;

        // 0. Outbound limit check: classify the MIME → content type, then apply
        //    the peer's advertised cap (tighter) or our own message cap.
        let content_type = relayd::limits::ContentType::from_mime(&r.mime_type);
        let outbound = crate::limits::daemon_limits_with(&self.0.lock().settings.clone());
        let peer_limits = {
            let s = self.0.lock();
            s.contacts.iter().find(|c| c.id == r.contact_id).and_then(|c| c.limits.clone())
        };
        let cap = crate::limits::peer_cap(peer_limits.as_ref(), content_type)
            .unwrap_or_else(|| outbound.cap_for(content_type).unwrap_or(u64::MAX));
        if size_bytes > cap {
            return Err(Status::failed_precondition(crate::limits::refusal_reason(
                content_type,
                size_bytes,
                cap,
            )));
        }

        let contact_id = r.contact_id.clone();
        let file_name = r.file_name.clone();
        let mime = r.mime_type.clone();

        // 1. Resolve the contact's direct address (short state lock).
        let address = {
            let s = self.0.lock();
            s.contacts.iter().find(|c| c.id == contact_id)
                .and_then(|c| c.address.clone())
        };

        // 2. Establish a lane session (direct TCP or relay) if we know the address
        //    and none exists.
        let transport = self.0.lock().transport.clone();
        ensure_contact_session(&self.0, &contact_id, address.as_deref()).await;

        // 3. Store the message + transfer record locally.
        let reply;
        let msg_id;
        let sender_pk;
        {
            let mut s = self.0.lock();
            let id = s.next_id();
            let msg = crate::state::StoredMessage {
                id: id.clone(),
                contact_id: contact_id.clone(),
                outbound: true,
                content_type: "file".into(),
                text: String::new(),
                file_name: file_name.clone(),
                file_size: size_bytes,
                file_xferd: 0,
                file_mime: mime.clone(),
                timestamp_ts: now_secs(),
                status: "pending".into(),
                group_id: None,
                sender_pk: String::new(),
                reply_to: None,
                reactions: Vec::new(),
            };
            reply = stored_to_reply(&msg);
            s.messages.entry(contact_id.clone()).or_default().push(msg);
            let tid = s.next_id();
            s.transfers.push(crate::state::Transfer {
                id: tid,
                contact_name: contact_id.clone(),
                file_name: file_name.clone(),
                size_bytes,
                xferd_bytes: 0,
                outbound: true,
                lanes_active: 1,
                bps: 0,
            });
            s.try_save();
            sender_pk = s.identity.as_ref().map(|i| i.public_key.clone()).unwrap_or_default();
            msg_id = id;
        }

        // 4. Split into wire chunks and enqueue for lane delivery.
        const CHUNK: usize = 30 * 1024;
        let total = data.len().div_ceil(CHUNK).max(1) as u32;
        {
            let mut pm = transport.lock().await;
            if pm.has_session(&contact_id) {
                for (i, part) in data.chunks(CHUNK).enumerate() {
                    let wire = crate::wire::WireMsg::File {
                        sender: sender_pk.clone(),
                        msg_id: msg_id.clone(),
                        file_name: file_name.clone(),
                        file_size: size_bytes,
                        mime: mime.clone(),
                        ts: now_secs(),
                        seq: i as u32,
                        total_chunks: total,
                        data: part.to_vec(),
                    };
                    match wire.encode() {
                        Ok(payload) => { let _ = pm.send_message(&contact_id, msg_id.clone(), bytes::Bytes::from(payload)); }
                        Err(_) => break,
                    }
                }
                tracing::info!("[grpc] send_file to {contact_id}: {file_name} ({size_bytes} B, {total} chunks) queued");
            } else {
                tracing::debug!("[grpc] send_file: queued locally only (no session) for {contact_id}");
            }
        }

        Ok(Response::new(reply))
    }

    async fn cancel_transfer(&self, req: Request<CancelTransferRequest>) -> Result<Response<Empty>, Status> {
        let tid = req.into_inner().transfer_id;
        let mut s = self.0.lock();
        s.transfers.retain(|t| t.id != tid);
        tracing::info!("[grpc] cancelled transfer {tid}");
        Ok(Response::new(Empty {}))
    }

    async fn pause_transfer(&self, req: Request<CancelTransferRequest>) -> Result<Response<Empty>, Status> {
        let tid = req.into_inner().transfer_id;
        tracing::info!("[grpc] pause transfer {tid} — stub");
        Ok(Response::new(Empty {}))
    }

    async fn resume_transfer(&self, req: Request<CancelTransferRequest>) -> Result<Response<Empty>, Status> {
        let tid = req.into_inner().transfer_id;
        tracing::info!("[grpc] resume transfer {tid} — stub");
        Ok(Response::new(Empty {}))
    }
}

// ---------------------------------------------------------------------------
// SettingsServiceImpl
// ---------------------------------------------------------------------------

pub struct SettingsServiceImpl(pub State);

#[tonic::async_trait]
impl SettingsService for SettingsServiceImpl {
    async fn get_setting(
        &self, req: Request<GetSettingRequest>,
    ) -> Result<Response<SettingReply>, Status> {
        let key = req.into_inner().key;
        let s = self.0.lock();

        // Synthesise relay.status from the live engine rather than stored settings.
        if key == "relay.status" {
            let value = match &s.relay_engine {
                Some(eng) => {
                    let st = eng.status();
                    format!("running,sessions={},port={}", st.active_sessions, st.port)
                }
                None => "stopped".to_string(),
            };
            return Ok(Response::new(SettingReply { value, found: true }));
        }

        // Synthesise transfer-limit reads from the effective (env + settings)
        // limits so a settings UI can display the actual caps.
        if key.starts_with("limits.") {
            let limits = crate::limits::daemon_limits_with(&s.settings);
            let value = match key.as_str() {
                "limits.summary" => crate::limits::summarize(&limits),
                "limits.message_bytes" => limits.message_bytes.label(),
                "limits.photo_bytes" => limits.photo_bytes.label(),
                "limits.video_bytes" => limits.video_bytes.label(),
                "limits.voice_bytes" => limits.voice_bytes.label(),
                "limits.file_bytes" => limits.file_bytes.label(),
                "limits.call_kbps" => limits.call_kbps.to_string(),
                "limits.daily_mb" => format_mb(limits.daily_bytes.bytes()),
                "limits.weekly_mb" => format_mb(limits.weekly_bytes.bytes()),
                "limits.monthly_mb" => format_mb(limits.monthly_bytes.bytes()),
                _ => return Ok(Response::new(SettingReply { value: String::new(), found: false })),
            };
            return Ok(Response::new(SettingReply { value, found: true }));
        }

        match s.settings.get(&key) {
            Some(v) => Ok(Response::new(SettingReply { value: v.clone(), found: true })),
            None    => Ok(Response::new(SettingReply { value: String::new(), found: false })),
        }
    }

    async fn set_setting(
        &self, req: Request<SetSettingRequest>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();

        if r.key == "relay.enabled" {
            let enable = r.value == "true" || r.value == "1";
            let state_clone = self.0.clone();
            tokio::spawn(async move {
                apply_relay_enabled(state_clone, enable).await;
            });
            // Also persist the intent.
            let s = &mut *self.0.lock();
            s.settings.insert(r.key, r.value);
            s.try_save();
            return Ok(Response::new(Empty {}));
        }

        let s = &mut *self.0.lock();
        s.settings.insert(r.key.clone(), r.value);
        s.try_save();

        // A limit change must re-advertise the peer's caps to the DHT.
        if r.key.starts_with("limits.") {
            let state = self.0.clone();
            tokio::spawn(async move {
                crate::peer_discovery::publish_endpoint_if_ready(&state).await;
            });
        }
        Ok(Response::new(Empty {}))
    }
}

fn format_mb(bytes: Option<u64>) -> String {
    match bytes {
        Some(b) => format!("{}", b >> 20),
        None => "0".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Relay helpers
// ---------------------------------------------------------------------------

async fn apply_relay_enabled(state: State, enable: bool) {
    if enable {
        // Build settings from current stored values.
        let settings = {
            let s = state.lock();
            let port = s.settings.get("relay.port")
                .and_then(|v| v.parse().ok())
                .unwrap_or(7777u16);
            let bandwidth_kbps = s.settings.get("relay.bandwidth_kbps")
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000u64);
            let difficulty = s.settings.get("relay.difficulty")
                .and_then(|v| v.parse().ok())
                .unwrap_or(14u32);
            transferd_relay::RelaySettings {
                enabled: true,
                port,
                difficulty,
                bandwidth_kbps,
                max_sessions: 256,
                auth_policy: transferd_relay::AuthPolicy::Public,
                ..transferd_relay::RelaySettings::default()
            }
        };
        match transferd_relay::RelayEngine::start(settings).await {
            Ok(engine) => {
                state.lock().relay_engine = Some(engine);
            }
            Err(e) => {
                tracing::error!("[relay] failed to start: {e}");
            }
        }
    } else {
        // Dropping the Arc stops the engine via Drop.
        state.lock().relay_engine = None;
    }
}

// ---------------------------------------------------------------------------
// CallServiceImpl
// ---------------------------------------------------------------------------

pub struct CallServiceImpl {
    pub state:  State,
    pub events: broadcast::Sender<CallEvent>,
}

impl CallServiceImpl {
    pub fn new(state: State) -> Self {
        let (events, _) = broadcast::channel(64);
        Self { state, events }
    }
}

#[tonic::async_trait]
impl CallService for CallServiceImpl {
    type StreamCallEventsStream = BoxStream<CallEvent>;

    async fn start_call(
        &self, req: Request<CallStartRequest>,
    ) -> Result<Response<CallStartResponse>, Status> {
        let r = req.into_inner();
        if r.conv_id.is_empty() {
            return Err(Status::invalid_argument("conv_id required"));
        }
        let call_id = {
            let mut s = self.state.lock();
            let id = s.next_id();
            s.calls.insert(id.clone(), CallRecord {
                conv_id:   r.conv_id.clone(),
                video:     r.video,
                local_sdp: r.local_sdp.clone(),
                state:     "calling".into(),
            });
            id
        };
        let _ = self.events.send(CallEvent {
            call_id:    call_id.clone(),
            event_type: "invite".into(),
            payload:    r.local_sdp,
            conv_id:    r.conv_id,
            video:      r.video,
        });
        Ok(Response::new(CallStartResponse { call_id }))
    }

    async fn accept_call(
        &self, req: Request<CallAcceptRequest>,
    ) -> Result<Response<CallAcceptResponse>, Status> {
        let r = req.into_inner();
        let mut s = self.state.lock();
        match s.calls.get_mut(&r.call_id) {
            Some(rec) if rec.state == "calling" => {
                let remote_sdp = rec.local_sdp.clone();
                let conv_id = rec.conv_id.clone();
                let video = rec.video;
                rec.state = "active".into();
                let _ = self.events.send(CallEvent {
                    call_id:    r.call_id,
                    event_type: "accepted".into(),
                    payload:    r.answer_sdp,
                    conv_id,
                    video,
                });
                Ok(Response::new(CallAcceptResponse { accepted: true, remote_sdp }))
            }
            Some(_) => Err(Status::failed_precondition("call not in calling state")),
            None    => Err(Status::not_found("call not found")),
        }
    }

    async fn reject_call(
        &self, req: Request<CallRejectRequest>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();
        let mut s = self.state.lock();
        match s.calls.get_mut(&r.call_id) {
            Some(rec) => {
                let conv_id = rec.conv_id.clone();
                rec.state = "rejected".into();
                let _ = self.events.send(CallEvent {
                    call_id: r.call_id, event_type: "rejected".into(),
                    payload: String::new(), conv_id, video: false,
                });
                Ok(Response::new(Empty {}))
            }
            None => Err(Status::not_found("call not found")),
        }
    }

    async fn end_call(
        &self, req: Request<CallEndRequest>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();
        let mut s = self.state.lock();
        match s.calls.get_mut(&r.call_id) {
            Some(rec) => {
                let conv_id = rec.conv_id.clone();
                rec.state = "ended".into();
                let _ = self.events.send(CallEvent {
                    call_id: r.call_id, event_type: "ended".into(),
                    payload: String::new(), conv_id, video: false,
                });
                Ok(Response::new(Empty {}))
            }
            None => Err(Status::not_found("call not found")),
        }
    }

    async fn send_ice_candidate(
        &self, req: Request<IceCandidateMsg>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();
        let s = self.state.lock();
        if !s.calls.contains_key(&r.call_id) {
            return Err(Status::not_found("call not found"));
        }
        let _ = self.events.send(CallEvent {
            call_id:    r.call_id,
            event_type: "ice_candidate".into(),
            payload:    r.candidate_json,
            conv_id:    String::new(),
            video:      false,
        });
        Ok(Response::new(Empty {}))
    }

    async fn stream_call_events(
        &self, _: Request<Empty>,
    ) -> Result<Response<Self::StreamCallEventsStream>, Status> {
        let rx = self.events.subscribe();
        let stream = BroadcastStream::new(rx).filter_map(|r| match r {
            Ok(e)  => Some(Ok(e)),
            Err(_) => None,
        });
        Ok(Response::new(Box::pin(stream)))
    }
}

// ---------------------------------------------------------------------------
// TelemetryServiceImpl
// ---------------------------------------------------------------------------

pub struct TelemetryServiceImpl(pub State);

fn event_to_msg(event: &transferd_telemetry::TelemetryEvent) -> TelemetryEventMsg {
    use transferd_telemetry::TelemetryEvent;
    use transferd_api::proto::telemetry_event_msg::Event;
    TelemetryEventMsg {
        event: Some(match event {
            TelemetryEvent::SystemHealth(e) => Event::SystemHealth(SystemHealthMsg {
                ts:              e.ts,
                cpu_pct:         e.cpu_pct,
                mem_rss_kb:      e.mem_rss_kb,
                uptime_secs:     e.uptime_secs,
                active_sessions: e.active_sessions,
            }),
            TelemetryEvent::AteLane(e) => Event::AteLane(AteLaneMsg {
                ts:            e.ts,
                session_hash:  e.session_id_hash.to_vec(),
                gsn:           e.gsn,
                selected_lane: e.selected_lane,
                rtt_ms:        e.rtt_ms,
                bandwidth_bps: e.bandwidth_bps,
                active_chunks: e.active_chunks,
                total_lanes:   e.total_lanes,
            }),
        }),
    }
}

#[tonic::async_trait]
impl TelemetryService for TelemetryServiceImpl {
    type StreamTelemetryStream = BoxStream<TelemetryEventMsg>;

    async fn stream_telemetry(
        &self, _: Request<Empty>,
    ) -> Result<Response<Self::StreamTelemetryStream>, Status> {
        let telemetry = {
            let s = self.0.lock();
            s.telemetry.clone()
        };
        let Some(col) = telemetry else {
            return Err(Status::unavailable("telemetry collector not started"));
        };
        let rx = col.subscribe();
        let stream = BroadcastStream::new(rx).filter_map(|r| match r {
            Ok(ev) => Some(Ok(event_to_msg(&ev))),
            Err(_) => None,
        });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_snapshot(
        &self, _: Request<Empty>,
    ) -> Result<Response<TelemetrySnapshot>, Status> {
        let telemetry = {
            let s = self.0.lock();
            s.telemetry.clone()
        };
        let Some(col) = telemetry else {
            return Ok(Response::new(TelemetrySnapshot { events: vec![] }));
        };
        let events = col.replay().await.iter().map(event_to_msg).collect();
        Ok(Response::new(TelemetrySnapshot { events }))
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn fresh_account_svc() -> AccountServiceImpl {
        use std::sync::Arc;
        use parking_lot::Mutex;
        AccountServiceImpl(Arc::new(Mutex::new(crate::state::DaemonState::default())))
    }

    #[tokio::test]
    async fn create_identity_generates_unique_phrases_and_keys() {
        let svc = fresh_account_svc();
        let mut phrases: HashSet<String> = HashSet::new();
        let mut pubkeys: HashSet<String> = HashSet::new();

        for i in 0..10 {
            let req = tonic::Request::new(CreateIdentityRequest {
                display_name: format!("user-{i}"),
            });
            let resp = svc.create_identity(req).await.unwrap().into_inner();

            // Phrase must be exactly 12 BIP-39 words.
            assert_eq!(
                resp.phrase.split_whitespace().count(), 12,
                "Expected 12 words, got: {}", resp.phrase
            );

            // Each phrase must be unique.
            assert!(
                phrases.insert(resp.phrase.clone()),
                "Duplicate recovery phrase on iteration {i}: {}", resp.phrase
            );

            // Public key stored must be 64 hex chars.
            let pk = svc.0.lock().identity.as_ref().unwrap().public_key.clone();
            assert_eq!(pk.len(), 64, "Public key must be 64 hex chars, got {}", pk.len());

            // Each public key must be unique.
            assert!(
                pubkeys.insert(pk.clone()),
                "Duplicate public key on iteration {i}: {pk}"
            );
        }
    }

    #[tokio::test]
    async fn restore_identity_reproduces_same_key() {
        let svc = fresh_account_svc();

        // Create a fresh identity.
        let create_resp = svc
            .create_identity(tonic::Request::new(CreateIdentityRequest {
                display_name: "Alice".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        let original_pk = svc.0.lock().identity.as_ref().unwrap().public_key.clone();

        // Wipe the identity to simulate a fresh daemon start.
        svc.0.lock().identity = None;

        // Restore from the phrase.
        let restore_resp = svc
            .restore_identity(tonic::Request::new(RestoreIdentityRequest {
                phrase: create_resp.phrase.clone(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(restore_resp.has_identity);
        assert_eq!(
            restore_resp.public_key, original_pk,
            "Restored public key must match the original"
        );
    }

    #[tokio::test]
    async fn restore_identity_rejects_invalid_phrase() {
        let svc = fresh_account_svc();
        let result = svc
            .restore_identity(tonic::Request::new(RestoreIdentityRequest {
                phrase: "not a real bip39 phrase with enough words here abc".into(),
            }))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn create_identity_rejects_empty_name() {
        let svc = fresh_account_svc();
        let result = svc
            .create_identity(tonic::Request::new(CreateIdentityRequest {
                display_name: "  ".into(),
            }))
            .await;
        assert!(result.is_err());
    }
}

// ---------------------------------------------------------------------------
// GroupServiceImpl
// ---------------------------------------------------------------------------

pub struct GroupServiceImpl(pub State);

fn group_role_to_proto(role: u8) -> transferd_api::GroupRole {
    match role {
        crate::state::group_role::OWNER => transferd_api::GroupRole::Owner,
        crate::state::group_role::ADMIN => transferd_api::GroupRole::Admin,
        _ => transferd_api::GroupRole::Member,
    }
}

fn group_to_reply(g: &crate::state::Group) -> transferd_api::GroupReply {
    transferd_api::GroupReply {
        group_id:   g.id.clone(),
        name:       g.name.clone(),
        owner:      g.owner.clone(),
        members: g.members.iter().map(|m| transferd_api::GroupMember {
            public_key: m.public_key.clone(),
            role: group_role_to_proto(m.role).into(),
        }).collect(),
        created_at: g.created_at,
    }
}

#[tonic::async_trait]
impl GroupService for GroupServiceImpl {
    async fn create_group(
        &self, req: Request<transferd_api::CreateGroupRequest>,
    ) -> Result<Response<transferd_api::GroupReply>, Status> {
        let r = req.into_inner();
        if r.name.trim().is_empty() {
            return Err(Status::invalid_argument("group name required"));
        }
        let mut s = self.0.lock();
        let my_pk = s.identity.as_ref().map(|i| i.public_key.clone())
            .ok_or_else(|| Status::failed_precondition("no identity"))?;
        let gid = s.next_id();
        let mut members = vec![crate::state::GroupMember {
            public_key: my_pk.clone(),
            role: crate::state::group_role::OWNER,
        }];
        for mid in &r.member_ids {
            if mid == &my_pk { continue; }
            if !members.iter().any(|m| &m.public_key == mid) {
                members.push(crate::state::GroupMember {
                    public_key: mid.clone(),
                    role: crate::state::group_role::MEMBER,
                });
            }
        }
        let group = crate::state::Group {
            id: gid,
            name: r.name,
            owner: my_pk,
            members,
            created_at: now_secs(),
        };
        s.groups.insert(group.id.clone(), group.clone());
        s.try_save();
        Ok(Response::new(group_to_reply(&group)))
    }

    async fn get_groups(&self, _: Request<Empty>) -> Result<Response<transferd_api::GroupList>, Status> {
        let s = self.0.lock();
        Ok(Response::new(transferd_api::GroupList {
            groups: s.groups.values().map(group_to_reply).collect(),
        }))
    }

    async fn get_group(
        &self, req: Request<transferd_api::GetGroupRequest>,
    ) -> Result<Response<transferd_api::GroupReply>, Status> {
        let gid = req.into_inner().group_id;
        let s = self.0.lock();
        let g = s.groups.get(&gid).ok_or_else(|| Status::not_found("group not found"))?;
        Ok(Response::new(group_to_reply(g)))
    }

    async fn rename_group(
        &self, req: Request<transferd_api::RenameGroupRequest>,
    ) -> Result<Response<transferd_api::GroupReply>, Status> {
        let r = req.into_inner();
        if r.name.trim().is_empty() {
            return Err(Status::invalid_argument("group name required"));
        }
        let mut s = self.0.lock();
        let reply = {
            let g = s.groups.get_mut(&r.group_id)
                .ok_or_else(|| Status::not_found("group not found"))?;
            g.name = r.name;
            group_to_reply(g)
        };
        s.try_save();
        Ok(Response::new(reply))
    }

    async fn add_members(
        &self, req: Request<transferd_api::GroupMembersRequest>,
    ) -> Result<Response<transferd_api::GroupReply>, Status> {
        let r = req.into_inner();
        let mut s = self.0.lock();
        let reply = {
            let g = s.groups.get_mut(&r.group_id)
                .ok_or_else(|| Status::not_found("group not found"))?;
            for mid in r.member_ids {
                if !g.members.iter().any(|m| m.public_key == mid) {
                    g.members.push(crate::state::GroupMember {
                        public_key: mid,
                        role: crate::state::group_role::MEMBER,
                    });
                }
            }
            group_to_reply(g)
        };
        s.try_save();
        Ok(Response::new(reply))
    }

    async fn remove_members(
        &self, req: Request<transferd_api::GroupMembersRequest>,
    ) -> Result<Response<transferd_api::GroupReply>, Status> {
        let r = req.into_inner();
        let mut s = self.0.lock();
        let reply = {
            let g = s.groups.get_mut(&r.group_id)
                .ok_or_else(|| Status::not_found("group not found"))?;
            g.members.retain(|m| !r.member_ids.contains(&m.public_key));
            group_to_reply(g)
        };
        s.try_save();
        Ok(Response::new(reply))
    }

    async fn set_member_role(
        &self, req: Request<transferd_api::SetMemberRoleRequest>,
    ) -> Result<Response<transferd_api::GroupReply>, Status> {
        let r = req.into_inner();
        let mut s = self.0.lock();
        let reply = {
            let g = s.groups.get_mut(&r.group_id)
                .ok_or_else(|| Status::not_found("group not found"))?;
            let member = g.members.iter_mut().find(|m| m.public_key == r.member_id)
                .ok_or_else(|| Status::not_found("member not in group"))?;
            member.role = match r.role {
                x if x == transferd_api::GroupRole::Owner as i32 => crate::state::group_role::OWNER,
                x if x == transferd_api::GroupRole::Admin as i32 => crate::state::group_role::ADMIN,
                _ => crate::state::group_role::MEMBER,
            };
            group_to_reply(g)
        };
        s.try_save();
        Ok(Response::new(reply))
    }

    async fn leave_group(
        &self, req: Request<transferd_api::GetGroupRequest>,
    ) -> Result<Response<Empty>, Status> {
        let gid = req.into_inner().group_id;
        let mut s = self.0.lock();
        let my_pk = s.identity.as_ref().map(|i| i.public_key.clone())
            .ok_or_else(|| Status::failed_precondition("no identity"))?;
        {
            let g = s.groups.get_mut(&gid)
                .ok_or_else(|| Status::not_found("group not found"))?;
            g.members.retain(|m| m.public_key != my_pk);
        }
        s.try_save();
        Ok(Response::new(Empty {}))
    }

    async fn delete_group(
        &self, req: Request<transferd_api::GetGroupRequest>,
    ) -> Result<Response<Empty>, Status> {
        let gid = req.into_inner().group_id;
        let mut s = self.0.lock();
        let my_pk = s.identity.as_ref().map(|i| i.public_key.clone())
            .ok_or_else(|| Status::failed_precondition("no identity"))?;
        // Only the owner can delete a group.
        let owner = s.groups.get(&gid).map(|g| g.owner.clone())
            .ok_or_else(|| Status::not_found("group not found"))?;
        if owner != my_pk {
            return Err(Status::permission_denied("only the owner can delete the group"));
        }
        s.groups.remove(&gid);
        s.messages.remove(&gid);
        s.try_save();
        Ok(Response::new(Empty {}))
    }

    async fn send_group_text(
        &self, req: Request<transferd_api::SendGroupTextRequest>,
    ) -> Result<Response<MessageReply>, Status> {
        let r = req.into_inner();
        if r.text.trim().is_empty() {
            return Err(Status::invalid_argument("message text required"));
        }

        // Store locally under the group id and capture member list.
        let (reply, my_pk, members, payload, local_msg_id) = {
            let mut s = self.0.lock();
            let my_pk = s.identity.as_ref().map(|i| i.public_key.clone())
                .ok_or_else(|| Status::failed_precondition("no identity"))?;
            let g = s.groups.get(&r.group_id)
                .ok_or_else(|| Status::not_found("group not found"))?;
            let members = g.members.iter().map(|m| m.public_key.clone()).collect::<Vec<_>>();

            let id = s.next_id();
            let local_msg_id = id.clone();
            let mut msg = crate::state::StoredMessage::new_text(
                id, r.group_id.clone(), true, r.text.clone(),
            );
            msg.status = "pending".into();
            msg.group_id = Some(r.group_id.clone());
            msg.sender_pk = my_pk.clone();
            let reply = stored_to_reply(&msg);
            s.messages.entry(r.group_id.clone()).or_default().push(msg);
            s.try_save();

            let payload = crate::wire::WireMsg::Text {
                sender: my_pk.clone(),
                msg_id: local_msg_id.clone(),
                text: r.text.clone(),
                ts: now_secs(),
                group_id: Some(r.group_id.clone()),
                reply_to: None,
            }
            .encode()
            .map_err(|_| Status::internal("failed to encode message"))?;

            (reply, my_pk, members, payload, local_msg_id)
        };

        // Fan out to each other member (best-effort; explicit address or DHT discovery).
        let transport = self.0.lock().transport.clone();
        for member in members {
            if member == my_pk { continue; }
            let addr = {
                let s = self.0.lock();
                s.contacts.iter().find(|c| c.id == member).and_then(|c| c.address.clone())
            };
            ensure_contact_session(&self.0, &member, addr.as_deref()).await;
            let mut pm = transport.lock().await;
            if pm.has_session(&member) {
                let _ = pm.send_message(&member, local_msg_id.clone(), bytes::Bytes::from(payload.clone()));
            }
        }

        Ok(Response::new(reply))
    }

    async fn get_group_messages(
        &self, req: Request<transferd_api::GetGroupRequest>,
    ) -> Result<Response<MessageList>, Status> {
        let gid = req.into_inner().group_id;
        let s = self.0.lock();
        let messages = s.messages.get(&gid)
            .map(|v| v.iter().map(stored_to_reply).collect())
            .unwrap_or_default();
        Ok(Response::new(MessageList { messages }))
    }
}

/// Attach all seven TransferDaemon gRPC services to a tonic `Server::builder`.
///
/// When the daemon has an `auth_token` configured, every request must present
/// `Authorization: Bearer <token>` or it is rejected with `UNAUTHENTICATED`.
pub fn add_all_services(
    mut builder: tonic::transport::Server,
    state: State,
) -> tonic::transport::server::Router {
    use transferd_api::{
        AccountServiceServer, FriendServiceServer, MessageServiceServer,
        TransferServiceServer, SettingsServiceServer, CallServiceServer,
        TelemetryServiceServer, GroupServiceServer, ConnectionServiceServer,
    };

    // Build a cloneable interceptor that validates the bearer token.
    let token = state.lock().auth_token.clone();
    // `Status` is large (176 bytes); required by the tonic interceptor type.
    #[allow(clippy::result_large_err)]
    let interceptor = move |request: tonic::Request<()>| {
        let authorized = token
            .as_ref()
            .map(|expected| {
                request
                    .metadata()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v == format!("Bearer {expected}"))
                    .unwrap_or(false)
            })
            .unwrap_or(true); // no token configured → allow
        if authorized {
            Ok(request)
        } else {
            Err(tonic::Status::unauthenticated("missing or invalid auth token"))
        }
    };

    let call_svc = CallServiceImpl::new(state.clone());
    builder
        .add_service(AccountServiceServer::with_interceptor(
            AccountServiceImpl(state.clone()), interceptor.clone()))
        .add_service(FriendServiceServer::with_interceptor(
            FriendServiceImpl(state.clone()), interceptor.clone()))
        .add_service(MessageServiceServer::with_interceptor(
            MessageServiceImpl(state.clone()), interceptor.clone()))
        .add_service(TransferServiceServer::with_interceptor(
            TransferServiceImpl(state.clone()), interceptor.clone()))
        .add_service(SettingsServiceServer::with_interceptor(
            SettingsServiceImpl(state.clone()), interceptor.clone()))
        .add_service(CallServiceServer::with_interceptor(call_svc, interceptor.clone()))
        .add_service(GroupServiceServer::with_interceptor(
            GroupServiceImpl(state.clone()), interceptor.clone()))
        .add_service(ConnectionServiceServer::with_interceptor(
            crate::connections::ConnectionServiceImpl(state.clone()), interceptor.clone()))
        .add_service(UpdateServiceServer::with_interceptor(
            UpdateServiceImpl, interceptor.clone()))
        .add_service(TelemetryServiceServer::with_interceptor(
            TelemetryServiceImpl(state), interceptor))
}
