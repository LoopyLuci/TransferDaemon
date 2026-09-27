//! Error types shared across the harbor workspace.

use std::io;

use serde::Serialize;
use thiserror::Error;

pub type CapResult<T> = Result<T, CapError>;

/// A capability invocation error. Each variant carries a stable `code` string
/// the MCP layer maps onto a JSON-RPC error, and the audit log records it.
#[derive(Debug, Error)]
pub enum CapError {
    #[error("denied by policy (rule: {0})")]
    Denied(String),

    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    #[error("timed out after {0}ms")]
    Timeout(u64),

    #[error("output exceeded {0} bytes; truncated")]
    OutputExceeded(usize),

    #[error("path is outside the allowed roots: {0}")]
    PathOutOfBounds(String),

    #[error("path is on the deny list: {0}")]
    PathDenied(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("approval was not granted (expired or denied)")]
    ApprovalRejected,

    #[error("approval server error: {0}")]
    ApprovalServer(String),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

impl CapError {
    /// Stable, machine-readable identifier for the failure class.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Denied(_) => "denied",
            Self::InvalidParams(_) => "invalid_params",
            Self::Timeout(_) => "timeout",
            Self::OutputExceeded(_) => "output_exceeded",
            Self::PathOutOfBounds(_) => "path_out_of_bounds",
            Self::PathDenied(_) => "path_denied",
            Self::NotFound(_) => "not_found",
            Self::ApprovalRejected => "approval_rejected",
            Self::ApprovalServer(_) => "approval_server",
            Self::Io(_) => "io",
            Self::Internal(_) => "internal",
        }
    }
}

/// The machine-readable envelope for an error, for JSON responses.
#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    pub code: &'static str,
    pub message: String,
}

impl From<&CapError> for ErrorEnvelope {
    fn from(e: &CapError) -> Self {
        Self { code: e.code(), message: e.to_string() }
    }
}