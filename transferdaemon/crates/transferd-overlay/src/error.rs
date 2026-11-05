//! What can go wrong in the overlay, in one place.

use std::net::SocketAddr;

/// Errors surfaced by overlay operations and by the background tasks.
#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    /// The peer's protocol range does not overlap ours, or it refused ours.
    #[error("no common protocol version with {node}: it speaks {theirs}")]
    NoCommonVersion { node: String, theirs: String },

    /// A peer answered, but not with the identity we expected.
    #[error("identity mismatch for {node}: {reason}")]
    IdentityMismatch { node: String, reason: String },

    /// The node id is not a 64-character hex Ed25519 public key.
    #[error("{0} is not a node id (64 hex characters)")]
    BadNodeId(String),

    /// Nothing reachable: no relay, no direct address, no hole punch.
    #[error("no route to {node}: no relay in common, no reachable address, hole punch failed")]
    Unreachable { node: String },

    /// The named service is not exposed here.
    #[error("no service {service:?} is exposed on this node")]
    NoSuchService { service: String },

    /// The connecting node is not in the service's access list.
    #[error("{node} may not use service {service:?}")]
    Denied { node: String, service: String },

    /// The node is not paired with this one, so there is nothing to forget.
    #[error("{node} is not paired with this node")]
    NotPaired { node: String },

    /// The service's rate limit refused the connection.
    #[error("service {service:?} is rate limited ({reason})")]
    RateLimited { service: String, reason: String },

    /// A service group has no live member offering the service.
    #[error("no node in group {group:?} offers service {service:?}")]
    GroupEmpty { group: String, service: String },

    /// The local listener could not be bound.
    #[error("cannot listen on {addr}: {source}")]
    Listen {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// A relay refused to register us, or could not be reached.
    #[error("relay {addr}: {reason}")]
    Relay { addr: String, reason: String },

    /// Something on the wire did not parse, or violated the protocol.
    #[error("protocol: {0}")]
    Protocol(String),

    /// The peer closed the session, or a stream ended early.
    #[error("session closed: {0}")]
    Closed(String),

    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl OverlayError {
    /// A short, stable machine-readable code for the control hub and the CLI.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoCommonVersion { .. } => "no_common_version",
            Self::IdentityMismatch { .. } => "identity_mismatch",
            Self::BadNodeId(_) => "bad_node_id",
            Self::Unreachable { .. } => "unreachable",
            Self::NoSuchService { .. } => "no_such_service",
            Self::Denied { .. } => "denied",
            Self::NotPaired { .. } => "not_paired",
            Self::RateLimited { .. } => "rate_limited",
            Self::GroupEmpty { .. } => "group_empty",
            Self::Listen { .. } => "listen_failed",
            Self::Relay { .. } => "relay_failed",
            Self::Protocol(_) => "protocol",
            Self::Closed(_) => "closed",
            Self::Io(_) => "io",
            Self::Other(_) => "failed",
        }
    }

    /// Build a protocol error.
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }
}

/// The result type used across the crate.
pub type Result<T> = std::result::Result<T, OverlayError>;
