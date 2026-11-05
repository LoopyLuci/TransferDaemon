//! Generated gRPC types and service clients/servers for TransferDaemon.

pub mod auth;

pub mod proto {
    // Prost/tonic generated code is not our source; clippy lints (unwrap_used,
    // result_large_err, ...) don't apply meaningfully to it.
    #![allow(clippy::all, clippy::unwrap_used)]
    tonic::include_proto!("transferd");
}

// Message types.
pub use proto::{
    AddContactRequest,
    AteLaneMsg,
    BlockContactRequest,
    CallAcceptRequest,
    CallAcceptResponse,
    CallEndRequest,
    CallEvent,
    CallRejectRequest,
    // Call types (Phase 8)
    CallStartRequest,
    CallStartResponse,
    CancelTransferRequest,
    ContactList,
    ContactReply,
    CreateIdentityRequest,
    Empty,
    GetMessagesRequest,
    GetSettingRequest,
    IceCandidateMsg,
    IdentityReply,
    MessageList,
    MessageReply,
    PublicKeyReply,
    Reaction,
    ReactionRequest,
    RecoveryPhraseReply,
    RemoveContactRequest,
    RenameContactRequest,
    RestoreIdentityRequest,
    SafetyNumberReply,
    SafetyNumberRequest,
    SearchMessagesRequest,
    SendFileRequest,
    SendTextRequest,
    SendTypingRequest,
    SetContactAddressRequest,
    SetSettingRequest,
    SettingReply,
    // Telemetry types
    SystemHealthMsg,
    TelemetryEventMsg,
    TelemetrySnapshot,
    TransferList,
    TransferReply,
};

// Service clients.
pub use proto::account_service_client::AccountServiceClient;
pub use proto::call_service_client::CallServiceClient;
pub use proto::connection_service_client::ConnectionServiceClient;
pub use proto::friend_service_client::FriendServiceClient;
pub use proto::group_service_client::GroupServiceClient;
pub use proto::message_service_client::MessageServiceClient;
pub use proto::settings_service_client::SettingsServiceClient;
pub use proto::telemetry_service_client::TelemetryServiceClient;
pub use proto::transfer_service_client::TransferServiceClient;

// Service server traits (used by the daemon binary and integration tests).
pub use proto::account_service_server::{AccountService, AccountServiceServer};
pub use proto::call_service_server::{CallService, CallServiceServer};
pub use proto::connection_service_server::{ConnectionService, ConnectionServiceServer};
pub use proto::friend_service_server::{FriendService, FriendServiceServer};
pub use proto::group_service_server::{GroupService, GroupServiceServer};
pub use proto::message_service_server::{MessageService, MessageServiceServer};
pub use proto::settings_service_server::{SettingsService, SettingsServiceServer};
pub use proto::telemetry_service_server::{TelemetryService, TelemetryServiceServer};
pub use proto::transfer_service_server::{TransferService, TransferServiceServer};
pub use proto::update_service_client::UpdateServiceClient;
pub use proto::update_service_server::{UpdateService, UpdateServiceServer};

// Connection types.
pub use proto::UpdateReply;
pub use proto::{Connection, ConnectionList, ConnectionStatusMsg, SetConnectionPolicyRequest};

// Group types.
pub use proto::{
    CreateGroupRequest, GetGroupRequest, GroupList, GroupMember, GroupMembersRequest, GroupReply,
    GroupRole, RenameGroupRequest, SendGroupTextRequest, SetMemberRoleRequest,
};
