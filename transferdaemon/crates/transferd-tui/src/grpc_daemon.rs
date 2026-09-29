use crate::daemon::{DaemonApi, DaemonError};
use crate::types::*;
use async_trait::async_trait;
use transferd_api::{
    AccountServiceClient, FriendServiceClient, MessageServiceClient,
    TransferServiceClient, AddContactRequest, CreateIdentityRequest, Empty,
    GetMessagesRequest, RestoreIdentityRequest, SendTextRequest, SendFileRequest,
};
use tonic::transport::Channel;
use transferd_api::auth::{AuthChannel, resolve_token};

#[derive(Clone)]
pub struct GrpcDaemon {
    channel: AuthChannel,
}

impl GrpcDaemon {
    pub async fn try_connect(addr: &str) -> Option<Self> {
        let channel = Channel::from_shared(addr.to_owned()).ok()?
            .connect_timeout(std::time::Duration::from_millis(500))
            .connect()
            .await
            .ok()?;
        let token = resolve_token().unwrap_or_default();
        Some(Self { channel: AuthChannel::new(channel, &token) })
    }

    fn account(&self) -> AccountServiceClient<AuthChannel> {
        AccountServiceClient::new(self.channel.clone())
    }
    fn friends(&self) -> FriendServiceClient<AuthChannel> {
        FriendServiceClient::new(self.channel.clone())
    }
    fn messages(&self) -> MessageServiceClient<AuthChannel> {
        MessageServiceClient::new(self.channel.clone())
    }
    fn transfers(&self) -> TransferServiceClient<AuthChannel> {
        TransferServiceClient::new(self.channel.clone())
    }
    fn groups(&self) -> transferd_api::GroupServiceClient<AuthChannel> {
        transferd_api::GroupServiceClient::new(self.channel.clone())
    }
    fn settings(&self) -> transferd_api::SettingsServiceClient<AuthChannel> {
        transferd_api::SettingsServiceClient::new(self.channel.clone())
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

fn proto_msg(r: transferd_api::MessageReply) -> Message {
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
    }
}

fn proto_contact(r: transferd_api::ContactReply) -> Contact {
    Contact {
        id: r.id,
        name: r.name,
        last_seen_ts: if r.last_seen_ts == 0 { None } else { Some(r.last_seen_ts) },
        online: r.online,
        blocked: r.blocked,
    }
}

fn proto_transfer(r: transferd_api::TransferReply) -> TransferStatus {
    TransferStatus {
        id: r.id,
        contact_name: r.contact_name,
        file_name: r.file_name,
        size_bytes: r.size_bytes,
        transferred_bytes: r.transferred_bytes,
        outbound: r.outbound,
        lanes_active: r.lanes_active as u8,
        bps: r.bps,
    }
}

#[async_trait]
impl DaemonApi for GrpcDaemon {
    async fn get_identity(&self) -> Option<Identity> {
        let r = self.account().get_identity(Empty {}).await.ok()?.into_inner();
        if r.has_identity {
            Some(Identity { public_key: r.public_key, display_name: r.display_name })
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
        let r = self.account()
            .restore_identity(RestoreIdentityRequest { phrase })
            .await
            .map_err(|e| DaemonError::NotReachable(e.to_string()))?
            .into_inner();
        if r.has_identity {
            Ok(Identity { public_key: r.public_key, display_name: r.display_name })
        } else {
            Err(DaemonError::InvalidInput("restore failed".into()))
        }
    }

    async fn get_contacts(&self) -> Vec<Contact> {
        self.friends().get_contacts(Empty {}).await
            .map(|r| r.into_inner().contacts.into_iter().map(proto_contact).collect())
            .unwrap_or_default()
    }

    async fn add_contact(&self, public_key: String, name: String) -> Result<Contact, DaemonError> {
        self.friends()
            .add_contact(AddContactRequest { public_key, name, ..Default::default() })
            .await
            .map(|r| proto_contact(r.into_inner()))
            .map_err(|e| {
                if e.code() == tonic::Code::InvalidArgument {
                    DaemonError::InvalidInput(e.message().to_owned())
                } else {
                    DaemonError::NotReachable(e.to_string())
                }
            })
    }

    // Full rename UI lives in the egui app; the TUI wires block/unblock/delete.
    #[allow(dead_code)]
    async fn rename_contact(&self, contact_id: String, name: String) -> Result<Contact, DaemonError> {
        self.friends()
            .rename_contact(transferd_api::RenameContactRequest { contact_id, name })
            .await
            .map(|r| proto_contact(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn remove_contact(&self, contact_id: String) -> Result<(), DaemonError> {
        self.friends()
            .remove_contact(transferd_api::RemoveContactRequest { contact_id })
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn block_contact(&self, contact_id: String) -> Result<Contact, DaemonError> {
        self.friends()
            .block_contact(transferd_api::BlockContactRequest { contact_id })
            .await
            .map(|r| proto_contact(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn unblock_contact(&self, contact_id: String) -> Result<Contact, DaemonError> {
        self.friends()
            .unblock_contact(transferd_api::BlockContactRequest { contact_id })
            .await
            .map(|r| proto_contact(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn get_messages(&self, contact_id: &str) -> Vec<Message> {
        self.messages()
            .get_messages(GetMessagesRequest { contact_id: contact_id.to_owned() })
            .await
            .map(|r| r.into_inner().messages.into_iter().map(proto_msg).collect())
            .unwrap_or_default()
    }

    async fn send_text(&self, contact_id: &str, text: String) -> Result<Message, DaemonError> {
        self.messages()
            .send_text(SendTextRequest { contact_id: contact_id.to_owned(), text, reply_to: String::new() })
            .await
            .map(|r| proto_msg(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn get_transfers(&self) -> Vec<TransferStatus> {
        self.transfers().get_transfers(Empty {}).await
            .map(|r| r.into_inner().transfers.into_iter().map(proto_transfer).collect())
            .unwrap_or_default()
    }

    async fn send_file(&self, contact_id: &str, path: String) -> Result<Message, DaemonError> {
        let p = std::path::Path::new(&path);
        let file_name = p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let file_size = std::fs::metadata(p)
            .map(|m| m.len())
            .map_err(|e| DaemonError::InvalidInput(format!("cannot read: {e}")))?;
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        let mime_type = match ext {
            "png" | "jpg" | "jpeg" => format!("image/{ext}"),
            "pdf" => "application/pdf".into(),
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
            .map(|r| proto_msg(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn start_call(&self, _contact_id: &str) -> Result<String, DaemonError> {
        // Placeholder — call service RPC would go here.
        Ok("grpc-call-unsupported".into())
    }

    async fn end_call(&self, _call_id: &str) -> Result<(), DaemonError> {
        Ok(())
    }

    async fn get_groups(&self) -> Vec<Group> {
        self.groups().get_groups(Empty {}).await
            .map(|r| r.into_inner().groups.into_iter().map(proto_group).collect())
            .unwrap_or_default()
    }

    async fn create_group(&self, name: String, member_ids: Vec<String>) -> Result<Group, DaemonError> {
        self.groups()
            .create_group(transferd_api::CreateGroupRequest { name, member_ids })
            .await
            .map(|r| proto_group(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn send_group_text(&self, group_id: &str, text: String) -> Result<Message, DaemonError> {
        self.groups()
            .send_group_text(transferd_api::SendGroupTextRequest { group_id: group_id.to_owned(), text })
            .await
            .map(|r| proto_msg(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn get_group_messages(&self, group_id: &str) -> Vec<Message> {
        self.groups()
            .get_group_messages(transferd_api::GetGroupRequest { group_id: group_id.to_owned() })
            .await
            .map(|r| r.into_inner().messages.into_iter().map(proto_msg).collect())
            .unwrap_or_default()
    }

    async fn get_setting(&self, key: &str) -> Option<String> {
        self.settings()
            .get_setting(transferd_api::GetSettingRequest { key: key.to_owned() })
            .await
            .ok()
            .map(|r| r.into_inner())
            .filter(|r| r.found)
            .map(|r| r.value)
    }

    async fn set_setting(&self, key: &str, value: &str) -> Result<(), DaemonError> {
        self.settings()
            .set_setting(transferd_api::SetSettingRequest { key: key.to_owned(), value: value.to_owned() })
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }
}

fn proto_group(r: transferd_api::GroupReply) -> Group {
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
