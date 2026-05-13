//! GrpcDaemon — DaemonApi implementation backed by a live transferd gRPC server.
//!
//! Connects to `127.0.0.1:50051` (configurable via `TRANSFERD_ADDR` env var).
//! Each method opens no persistent connection state beyond the shared channel;
//! tonic handles HTTP/2 multiplexing internally.

use crate::daemon::{DaemonApi, DaemonError};
use crate::types::{Contact, Identity, Message, MessageContent, MessageStatus, TransferStatus};
use async_trait::async_trait;
use transferd_api::{
    AccountServiceClient, FriendServiceClient, MessageServiceClient,
    TransferServiceClient, SettingsServiceClient,
    AddContactRequest, CreateIdentityRequest, Empty,
    GetMessagesRequest, RestoreIdentityRequest, SendTextRequest,
    GetSettingRequest, SetSettingRequest,
};
use tonic::transport::Channel;

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// Clones cheaply — shares the underlying HTTP/2 connection pool.
#[derive(Clone)]
pub struct GrpcDaemon {
    channel: Channel,
}

impl GrpcDaemon {
    /// Connect to the transferd daemon.
    /// `addr` example: `"http://127.0.0.1:50051"`
    pub async fn connect(addr: &str) -> Result<Self, DaemonError> {
        let channel = Channel::from_shared(addr.to_owned())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))?
            .connect()
            .await
            .map_err(|e| DaemonError::NotReachable(e.to_string()))?;
        Ok(Self { channel })
    }

    /// Try to connect with a short timeout; returns `None` if the daemon is not running.
    pub async fn try_connect(addr: &str) -> Option<Self> {
        let channel = Channel::from_shared(addr.to_owned()).ok()?
            .connect_timeout(std::time::Duration::from_millis(500))
            .connect()
            .await
            .ok()?;
        Some(Self { channel })
    }

    fn account(&self) -> AccountServiceClient<Channel> {
        AccountServiceClient::new(self.channel.clone())
    }
    fn friends(&self) -> FriendServiceClient<Channel> {
        FriendServiceClient::new(self.channel.clone())
    }
    fn messages(&self) -> MessageServiceClient<Channel> {
        MessageServiceClient::new(self.channel.clone())
    }
    fn transfers(&self) -> TransferServiceClient<Channel> {
        TransferServiceClient::new(self.channel.clone())
    }
    fn settings(&self) -> SettingsServiceClient<Channel> {
        SettingsServiceClient::new(self.channel.clone())
    }
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

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
    }
}

fn proto_to_contact(r: transferd_api::ContactReply) -> Contact {
    Contact {
        id: r.id,
        name: r.name,
        last_seen_ts: if r.last_seen_ts == 0 { None } else { Some(r.last_seen_ts) },
        online: r.online,
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
    }
}

// ---------------------------------------------------------------------------
// DaemonApi impl
// ---------------------------------------------------------------------------

#[async_trait]
impl DaemonApi for GrpcDaemon {
    async fn get_identity(&self) -> Option<Identity> {
        let reply = self.account().get_identity(Empty {}).await.ok()?.into_inner();
        if reply.has_identity {
            Some(Identity {
                public_key: reply.public_key,
                display_name: reply.display_name,
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

    async fn add_contact(&self, public_key: String, name: String) -> Result<Contact, DaemonError> {
        self.friends()
            .add_contact(AddContactRequest { public_key, name })
            .await
            .map(|r| proto_to_contact(r.into_inner()))
            .map_err(|e| {
                if e.code() == tonic::Code::InvalidArgument {
                    DaemonError::InvalidInput(e.message().to_owned())
                } else {
                    DaemonError::NotReachable(e.to_string())
                }
            })
    }

    async fn get_messages(&self, contact_id: &str) -> Vec<Message> {
        self.messages()
            .get_messages(GetMessagesRequest { contact_id: contact_id.to_owned() })
            .await
            .map(|r| r.into_inner().messages.into_iter().map(proto_to_message).collect())
            .unwrap_or_default()
    }

    async fn send_text(&self, contact_id: &str, text: String) -> Result<Message, DaemonError> {
        self.messages()
            .send_text(SendTextRequest { contact_id: contact_id.to_owned(), text })
            .await
            .map(|r| proto_to_message(r.into_inner()))
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }

    async fn get_transfers(&self) -> Vec<TransferStatus> {
        self.transfers()
            .get_transfers(Empty {})
            .await
            .map(|r| r.into_inner().transfers.into_iter().map(proto_to_transfer).collect())
            .unwrap_or_default()
    }

    async fn get_public_key_hex(&self) -> Option<String> {
        let reply = self.account()
            .get_public_key_hex(Empty {})
            .await
            .ok()?
            .into_inner();
        if reply.hex.is_empty() { None } else { Some(reply.hex) }
    }
}

// ---------------------------------------------------------------------------
// Settings helpers (not part of DaemonApi — directly usable by settings page)
// ---------------------------------------------------------------------------

impl GrpcDaemon {
    pub async fn get_setting(&self, key: &str) -> Option<String> {
        let r = self.settings()
            .get_setting(GetSettingRequest { key: key.to_owned() })
            .await.ok()?.into_inner();
        if r.found { Some(r.value) } else { None }
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> Result<(), DaemonError> {
        self.settings()
            .set_setting(SetSettingRequest { key: key.to_owned(), value: value.to_owned() })
            .await
            .map(|_| ())
            .map_err(|e| DaemonError::NotReachable(e.to_string()))
    }
}
