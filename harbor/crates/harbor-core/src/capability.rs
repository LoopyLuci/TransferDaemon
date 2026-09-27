//! The capability abstraction — the interface that must outlive every backend.

use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;

use crate::session::Session;

/// How dangerous a capability is. Drives sensible defaults and audit
/// prominence, and lets an operator grep the audit log for the risky stuff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

/// Resource limits the server enforces around a single capability invocation.
/// These are enforced by the SERVER, never delegated to the command.
#[derive(Debug, Clone, Copy)]
pub struct ResourceBudget {
    /// Hard wall-clock timeout for the whole invocation.
    pub timeout: Duration,
    /// Maximum bytes of output returned to the client (before redaction).
    pub max_output_bytes: usize,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self { timeout: Duration::from_secs(60), max_output_bytes: 1 << 20 }
    }
}

/// Immutable description of a capability. Registration order is stable: the
/// MCP tool list, the audit schema, and policy matching are all derived from
/// these manifests, so adding a capability touches no core code.
#[derive(Debug, Clone)]
pub struct CapabilityManifest {
    /// Permanent, additive-only identifier: `"pwsh.run"`, `"fs.read"`, ...
    /// The meaning of a capability id NEVER changes. New behavior = new id.
    pub id: &'static str,
    /// Informational version; bump on behavior change, never break old ids.
    pub version: u32,
    pub risk: Risk,
    /// JSON Schema for the parameters this capability accepts.
    pub input_schema: serde_json::Value,
    pub description: &'static str,
    /// If true, outputs may contain secrets and MUST pass through a Redactor
    /// before being returned to the client.
    pub secret_sensitive: bool,
    pub budget: ResourceBudget,
}

/// The context a provider needs to execute safely inside a session.
#[derive(Debug, Clone)]
pub struct CapabilityContext {
    /// The session this invocation belongs to (isolation + audit correlation).
    pub session: Session,
    /// Current redactor configured for this invocation.
    pub redactor: crate::redact::Redactor,
}

#[async_trait]
pub trait Capability: Send + Sync {
    fn manifest(&self) -> &'static CapabilityManifest;

    /// Execute the capability. Must honor `manifest.budget` (or fail fast with
    /// `CapError::Timeout` / `CapError::OutputExceeded`).
    async fn invoke(
        &self,
        ctx: &CapabilityContext,
        params: serde_json::Value,
    ) -> crate::CapResult<serde_json::Value>;

    /// The resource string policy matches on for this capability. For `fs.*`
    /// this is the canonicalized path; for `pwsh.run` the command text. The
    /// default is the raw params serialized — providers should override.
    fn resource(&self, params: &serde_json::Value) -> Option<String> {
        params.as_str().map(str::to_owned)
    }
}