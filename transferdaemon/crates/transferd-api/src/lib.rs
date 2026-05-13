//! Generated gRPC types and service clients/servers for TransferDaemon.

pub mod proto {
    tonic::include_proto!("transferd");
}

// Message types.
pub use proto::{
    AddContactRequest, ContactList, ContactReply,
    CreateIdentityRequest, Empty,
    GetMessagesRequest, GetSettingRequest, IdentityReply,
    MessageList, MessageReply, PublicKeyReply, RecoveryPhraseReply,
    RestoreIdentityRequest, SendTextRequest, SetSettingRequest, SettingReply,
    SendFileRequest, TransferList, TransferReply,
    // Call types (Phase 8)
    CallStartRequest, CallStartResponse,
    CallAcceptRequest, CallAcceptResponse,
    CallRejectRequest, CallEndRequest,
    IceCandidateMsg, CallEvent,
};

// Service clients.
pub use proto::account_service_client::AccountServiceClient;
pub use proto::friend_service_client::FriendServiceClient;
pub use proto::message_service_client::MessageServiceClient;
pub use proto::transfer_service_client::TransferServiceClient;
pub use proto::settings_service_client::SettingsServiceClient;
pub use proto::call_service_client::CallServiceClient;

// Service server traits (used by the daemon binary and integration tests).
pub use proto::account_service_server::{AccountService, AccountServiceServer};
pub use proto::friend_service_server::{FriendService, FriendServiceServer};
pub use proto::message_service_server::{MessageService, MessageServiceServer};
pub use proto::transfer_service_server::{TransferService, TransferServiceServer};
pub use proto::settings_service_server::{SettingsService, SettingsServiceServer};
pub use proto::call_service_server::{CallService, CallServiceServer};
