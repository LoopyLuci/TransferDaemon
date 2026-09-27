//! harbor-core — the protocol-forward heart of Harbor.
//!
//! Nothing in this crate knows about PowerShell, filesystems, or MCP. It
//! defines the *capability* abstraction (the 100-year interface), the *policy
//! engine* (the gate), the *audit log* (the truth), *sessions* (isolation) and
//! *redaction* (secret safety). Providers and the MCP server build on this.
#![deny(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::panic))]

pub mod audit;
pub mod capability;
pub mod errors;
pub mod policy;
pub mod redact;
pub mod session;

pub use audit::AuditLog;
pub use capability::{Capability, CapabilityContext, CapabilityManifest, ResourceBudget, Risk};
pub use errors::{CapError, CapResult};
pub use policy::{Decision, PolicyEngine, PolicyRule};
pub use redact::Redactor;
pub use session::Session;