//! GrpcDaemon — DaemonApi backed by a live transferd gRPC server.

use crate::daemon::{DaemonApi, DaemonError};
use crate::types::{Connection, Contact, Group, GroupMember, Identity, Message, MessageContent, MessageStatus, TransferStatus, UpdateStatus};
use async_trait::async_trait;
use transferd_api::{
    AccountServiceClient, FriendServiceClient, MessageServiceClient,
    TransferServiceClient, SettingsServiceClient, GroupServiceClient, ConnectionServiceClient,
    UpdateServiceClient,
    AddContactRequest, CancelTransferRequest, CreateIdentityRequest, Empty,
    GetMessagesRequest, RestoreIdentityRequest, SendTextRequest,
    GetSettingRequest, SetSettingRequest, SendFileRequest, SearchMessagesRequest,
    SendTypingRequest, ReactionRequest,
};
use tonic::transport::Channel;
use transferd_api::auth::{AuthChannel, resolve_token};

#[derive(Clone)]
pub struct GrpcDaemon {
    channel: AuthChannel,
}

impl GrpcDaemon {
    pub async fn connect(addr: &str) -> Result<Self, DaemonError> {
        let channel = Channel::from_shared(addr.to_owned())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))?
            .connect()
            .await
            .map_err(|e| DaemonError::NotReachable(e.to_string()))?;
        let token = resolve_token().unwrap_or_default();
        Ok(Self { channel: AuthChannel::new(channel, &token) })
    }

    pub async fn try_connect(addr: &str) -> Option<Self> {
        let channel = Channel::from_shared(addr.to_owned()).ok()?
            .connect_timeout(std::time::Duration::from_millis(500))
            .connect()
            .await
            .ok()?;
        let token = resolve_token().unwrap_or_default();
        Some(Self { channel: AuthChannel::new(channel, &token) })
    }

    fn account(&self) -> AccountServiceClient<AuthChannel> { AccountServiceClient::new(self.channel.clone()) }
    fn friends(&self) -> FriendServiceClient<AuthChannel> { FriendServiceClient::new(self.channel.clone()) }
    fn messages(&self) -> MessageServiceClient<AuthChannel> { MessageServiceClient::new(self.channel.clone()) }
    fn transfers(&self) -> TransferServiceClient<AuthChannel> { TransferServiceClient::new(self.channel.clone()) }
    fn settings(&self) -> SettingsServiceClient<AuthChannel> { SettingsServiceClient::new(self.channel.clone()) }
    fn groups(&self) -> GroupServiceClient<AuthChannel> { GroupServiceClient::new(self.channel.clone()) }
    fn connections(&self) -> ConnectionServiceClient<AuthChannel> { ConnectionServiceClient::new(self.channel.clone()) }
    fn updates(&self) -> UpdateServiceClient<AuthChannel> { UpdateServiceClient::new(self.channel.clone()) }
}

fn proto_to_group(r: transferd_api::GroupReply) -> Group {
    Group {
        id: r.group_id,
        name: r.name,
        owner: r.owner,
        members: r.members.into_iter().map(|m| GroupMember {
            public_key: m.public_key,
            role: m.role as u8,
        }).collect(),
        created_at: r.created_at,
    }
}

fn map_status(s: &str) -> MessageStatus {
    match s {
        "sent"      => MessageStatus::Sent,
        "delivered" => MessageStatus::Delivered,
        "read"      => MessageStatus::Read,
        "failed"    => MessageStatus::Failed,
        _           => MessageStatus::Pending,
    }
}

fn proto_to_message(r: transferd_api::MessageReply) -> Message {
    let content = if r.content_type == "file" {
        MessageContent::File {
            name: r.file_name,
            size_bytes: r.file_size_bytes,
            transferred_bytes: r.file_transferred,
            mime: if r.file_mime.is_empty() { None } else { Some(r.file_mime) },
        }
    } else {
        MessageContent::Text(r.text)
    };
    Message {
        id: r.id,
        contact_id: r.contact_id,
        outbound: r.outbound,
        content,
        timestamp_ts: r.timestamp_ts,
        status: map_status(&r.status),
        group_id: if r.group_id.is_empty() { None } else { Some(r.group_id) },
        sender_pk: if r.sender_pk.is_empty() { None } else { Some(r.sender_pk) },
        reply_to: if r.reply_to.is_empty() { None } else { Some(r.reply_to) },
        reactions: r.reactions.iter().map(|x| (x.emoji.clone(), x.sender.clone())).collect(),
    }
}

fn proto_to_contact(r: transferd_api::ContactReply) -> Contact {
    Contact {
        id: r.id,
        name: r.name,
        nickname: None, // nicknames are stored locally; merged after load
        last_seen_ts: if r.last_seen_ts == 0 { None } else { Some(r.last_seen_ts) },
        online: r.online,
        blocked: r.blocked,
        typing: r.typing,
    }
}

fn proto_to_transfer(r: transferd_api::TransferReply) -> TransferStatus {
    TransferStatus {
        id: r.id,
        contact_name: r.contact_name,
        file_name: r.file_name,
        size_bytes: r.size_bytes,
        transferred_bytes: r.transferred_bytes,
        outbound: r.outbound,
        lanes_active: r.lanes_active as u8,
        bps: r.bps,
        paused: false,
    }
}

#[async_trait]
impl DaemonApi for GrpcDaemon {
    async fn get_identity(&self) -> Option<Identity> {
        let reply = self.account().get_identity(Empty {}).await.ok()?.into_inner();
        if reply.has_identity {
            Some(Identity {
                public_key: reply.public_key,
                display_name: reply.display_name,
                phrase: String::new(),
            })
        } else {
            None
        }
    }

    async fn create_identity(&self, display_name: String) -> Result<String, DaemonError> {
        self.account()
            .create_identity(CreateIdentityRequest { display_name })
            .await
            .map(|r| r.into_inner().phrase)
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn restore_identity(&self, phrase: String) -> Result<Identity, DaemonError> {
        let reply = self.account()
            .restore_identity(RestoreIdentityRequest { phrase })
            .await
            .map_err(|e| DaemonError::NotReachable(e.to_string()))?
            .into_inner();
        if reply.has_identity {
            Ok(Identity {
                public_key: reply.public_key,
                display_name: reply.display_name,
                phrase: String::new(),
            })
        } else {
            Err(DaemonError::InvalidInput("restore failed".into()))
        }
    }

    async fn get_contacts(&self) -> Vec<Contact> {
        self.friends()
            .get_contacts(Empty {})
            .await
            .map(|r| r.into_inner().contacts.into_iter().map(proto_to_contact).collect())
            .unwrap_or_default()
    }

    async fn add_contact(&self, public_key: String, name: String, address: Option<String>) -> Result<Contact, DaemonError> {
        let result = self.friends()
            .add_contact(AddContactRequest { public_key, name })
            .await
            .map(|r| proto_to_contact(r.into_inner()))
            .map_err(|e| {
                if e.code() == tonic::Code::InvalidArgument {
                    DaemonError::InvalidInput(e.message().to_owned())
                } else {
                    DaemonError::NotReachable(e.to_string())
                }
            });

        // If we have an address and the contact was created successfully, log it
        if let (Ok(_), Some(addr)) = (&result, &address) {
            tracing::info!("Contact added with address: {addr}");
        }

        result
    }

    async fn rename_contact(&self, contact_id: &str, name: String) -> Result<Contact, DaemonError> {
        self.friends()
            .rename_contact(transferd_api::RenameContactRequest {
                contact_id: contact_id.to_owned(),
                name,
            })
            .await
            .map(|r| proto_to_contact(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn remove_contact(&self, contact_id: &str) -> Result<(), DaemonError> {
        self.friends()
            .remove_contact(transferd_api::RemoveContactRequest {
                contact_id: contact_id.to_owned(),
            })
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn block_contact(&self, contact_id: &str) -> Result<Contact, DaemonError> {
        self.friends()
            .block_contact(transferd_api::BlockContactRequest {
                contact_id: contact_id.to_owned(),
            })
            .await
            .map(|r| proto_to_contact(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn unblock_contact(&self, contact_id: &str) -> Result<Contact, DaemonError> {
        self.friends()
            .unblock_contact(transferd_api::BlockContactRequest {
                contact_id: contact_id.to_owned(),
            })
            .await
            .map(|r| proto_to_contact(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn get_messages(&self, contact_id: &str) -> Vec<Message> {
        self.messages()
            .get_messages(GetMessagesRequest { contact_id: contact_id.to_owned() })
            .await
            .map(|r| r.into_inner().messages.into_iter().map(proto_to_message).collect())
            .unwrap_or_default()
    }

    async fn search_messages(&self, contact_id: &str, query: &str) -> Vec<Message> {
        self.messages()
            .search_messages(SearchMessagesRequest {
                contact_id: contact_id.to_owned(),
                query: query.to_owned(),
            })
            .await
            .map(|r| r.into_inner().messages.into_iter().map(proto_to_message).collect())
            .unwrap_or_default()
    }

    async fn send_text(&self, contact_id: &str, text: String) -> Result<Message, DaemonError> {
        self.messages()
            .send_text(SendTextRequest { contact_id: contact_id.to_owned(), text, reply_to: String::new() })
            .await
            .map(|r| proto_to_message(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn send_reply(&self, contact_id: &str, text: String, reply_to: String) -> Result<Message, DaemonError> {
        self.messages()
            .send_text(SendTextRequest { contact_id: contact_id.to_owned(), text, reply_to })
            .await
            .map(|r| proto_to_message(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn send_typing(&self, contact_id: &str, is_typing: bool) {
        let _ = self.messages()
            .send_typing(SendTypingRequest { contact_id: contact_id.to_owned(), is_typing })
            .await;
    }

    async fn toggle_reaction(&self, contact_id: &str, target_msg_id: &str, emoji: &str) {
        let _ = self.messages()
            .toggle_reaction(ReactionRequest {
                contact_id: contact_id.to_owned(),
                target_msg_id: target_msg_id.to_owned(),
                emoji: emoji.to_owned(),
            })
            .await;
    }

    async fn get_transfers(&self) -> Vec<TransferStatus> {
        self.transfers()
            .get_transfers(Empty {})
            .await
            .map(|r| r.into_inner().transfers.into_iter().map(proto_to_transfer).collect())
            .unwrap_or_default()
    }

    async fn send_file(&self, contact_id: &str, path: String) -> Result<Message, DaemonError> {
        let p = std::path::Path::new(&path);
        let file_name = p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let file_size = std::fs::metadata(p)
            .map(|m| m.len())
            .map_err(|e| DaemonError::InvalidInput(format!("cannot read file: {e}")))?;
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        let mime_type = match ext {
            "png" | "jpg" | "jpeg" | "gif" | "webp" => format!("image/{ext}"),
            "pdf" => "application/pdf".into(),
            "mp4" | "mov" => format!("video/{ext}"),
            "mp3" | "ogg" => format!("audio/{ext}"),
            "txt" | "md" => "text/plain".into(),
            _ => "application/octet-stream".into(),
        };
        self.transfers()
            .send_file(SendFileRequest {
                contact_id: contact_id.to_owned(),
                file_path: path,
                file_name,
                file_size,
                mime_type,
            })
            .await
            .map(|r| proto_to_message(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn cancel_transfer(&self, transfer_id: &str) -> Result<(), DaemonError> {
        self.transfers()
            .cancel_transfer(CancelTransferRequest { transfer_id: transfer_id.to_owned() })
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn pause_transfer(&self, transfer_id: &str) -> Result<(), DaemonError> {
        self.transfers()
            .pause_transfer(CancelTransferRequest { transfer_id: transfer_id.to_owned() })
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn resume_transfer(&self, transfer_id: &str) -> Result<(), DaemonError> {
        self.transfers()
            .resume_transfer(CancelTransferRequest { transfer_id: transfer_id.to_owned() })
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn get_public_key_hex(&self) -> Option<String> {
        let reply = self.account()
            .get_public_key_hex(Empty {})
            .await.ok()?.into_inner();
        if reply.hex.is_empty() { None } else { Some(reply.hex) }
    }

    async fn get_setting(&self, key: &str) -> Option<String> {
        let r = self.settings()
            .get_setting(GetSettingRequest { key: key.to_owned() })
            .await.ok()?.into_inner();
        if r.found { Some(r.value) } else { None }
    }

    async fn set_setting(&self, key: &str, value: &str) -> Result<(), DaemonError> {
        self.settings()
            .set_setting(SetSettingRequest { key: key.to_owned(), value: value.to_owned() })
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn get_groups(&self) -> Vec<Group> {
        self.groups()
            .get_groups(Empty {})
            .await
            .map(|r| r.into_inner().groups.into_iter().map(proto_to_group).collect())
            .unwrap_or_default()
    }

    async fn create_group(&self, name: String, member_ids: Vec<String>) -> Result<Group, DaemonError> {
        self.groups()
            .create_group(transferd_api::CreateGroupRequest { name, member_ids })
            .await
            .map(|r| proto_to_group(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn rename_group(&self, group_id: &str, name: String) -> Result<Group, DaemonError> {
        self.groups()
            .rename_group(transferd_api::RenameGroupRequest { group_id: group_id.to_owned(), name })
            .await
            .map(|r| proto_to_group(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn add_group_members(&self, group_id: &str, member_ids: Vec<String>) -> Result<Group, DaemonError> {
        self.groups()
            .add_members(transferd_api::GroupMembersRequest { group_id: group_id.to_owned(), member_ids })
            .await
            .map(|r| proto_to_group(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn remove_group_members(&self, group_id: &str, member_ids: Vec<String>) -> Result<Group, DaemonError> {
        self.groups()
            .remove_members(transferd_api::GroupMembersRequest { group_id: group_id.to_owned(), member_ids })
            .await
            .map(|r| proto_to_group(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn leave_group(&self, group_id: &str) -> Result<(), DaemonError> {
        self.groups()
            .leave_group(transferd_api::GetGroupRequest { group_id: group_id.to_owned() })
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn delete_group(&self, group_id: &str) -> Result<(), DaemonError> {
        self.groups()
            .delete_group(transferd_api::GetGroupRequest { group_id: group_id.to_owned() })
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn get_group_messages(&self, group_id: &str) -> Vec<Message> {
        self.groups()
            .get_group_messages(transferd_api::GetGroupRequest { group_id: group_id.to_owned() })
            .await
            .map(|r| r.into_inner().messages.into_iter().map(proto_to_message).collect())
            .unwrap_or_default()
    }

    async fn send_group_text(&self, group_id: &str, text: String) -> Result<Message, DaemonError> {
        self.groups()
            .send_group_text(transferd_api::SendGroupTextRequest { group_id: group_id.to_owned(), text })
            .await
            .map(|r| proto_to_message(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn get_connections(&self) -> Vec<Connection> {
        self.connections()
            .list_connections(Empty {})
            .await
            .map(|r| r.into_inner().connections.into_iter().map(proto_to_connection).collect())
            .unwrap_or_default()
    }

    async fn set_connection_policy(&self, connection_id: &str, policy: &str) -> Result<(), DaemonError> {
        self.connections()
            .set_connection_policy(transferd_api::SetConnectionPolicyRequest {
                connection_id: connection_id.to_owned(),
                policy: policy.to_owned(),
            })
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn get_safety_number(&self, contact_id: &str) -> (String, bool) {
        self.friends()
            .get_safety_number(transferd_api::SafetyNumberRequest { contact_id: contact_id.to_owned() })
            .await
            .map(|r| {
                let r = r.into_inner();
                (r.safety_number, r.verified)
            })
            .unwrap_or_default()
    }

    async fn check_for_updates(&self) -> UpdateStatus {
        self.updates()
            .check_for_updates(Empty {})
            .await
            .map(|r| {
                let r = r.into_inner();
                UpdateStatus {
                    current_version: r.current_version,
                    has_update: r.has_update,
                    new_version: r.new_version,
                    release_notes: r.release_notes,
                    error: r.error,
                }
            })
            .unwrap_or_default()
    }

    async fn apply_update(&self) -> Result<(), DaemonError> {
        self.updates()
            .apply_update(Empty {})
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }
}

fn proto_to_connection(r: transferd_api::Connection) -> Connection {
    Connection {
        id: r.id,
        name: r.name,
        kind: r.kind,
        enabled: r.enabled,
        online: r.online,
        link_speed_bps: r.link_speed_bps,
        rtt_ms: r.rtt_ms,
        bandwidth_bps: r.bandwidth_bps,
        policy: r.policy,
    }
}
