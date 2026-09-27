//! Harbor — a capability-gated MCP server for safe, audit-trailed computer
//! control. Speak MCP over stdio; every capability is policy-gated, budgeted,
//! redacted, and audited.

use std::path::PathBuf;
use std::sync::Arc;

use globset::Glob;
use harbor_core::policy::{Decision, PolicyEngine, PolicyRule};
use harbor_core::redact::Redactor;
use harbor_providers::fs::FsCore;
use harbor_providers::pwsh::PwshConfig;
use serde::Deserialize;

/// Top-level configuration, loaded from `harbor.toml`. Fail closed: missing
/// roots → no fs capabilities; missing rules → deny.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HarborConfig {
    pub policy: PolicyConfig,
    pub pwsh: PwshSection,
    pub fs: FsSection,
    pub sandbox: SandboxSection,
    pub approval: ApprovalSection,
    pub audit: AuditSection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// "allow" | "deny" | "ask"
    pub default: String,
    pub rules: Vec<RuleEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RuleEntry {
    /// `"<capability-id>:<resource-glob>"` or `"<capability-id>"`.
    pub pattern: String,
    pub decision: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PwshSection {
    pub binary: String,
    pub constrained: bool,
    pub env_remove: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FsSection {
    /// Absolute allowed roots. Empty → fs capabilities denied entirely.
    pub roots: Vec<String>,
    /// Glob patterns denied even inside roots (e.g. `**/.ssh/**`).
    pub deny: Vec<String>,
    pub max_read_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SandboxSection {
    /// Default working directory for pwsh.run when a call omits `cwd`.
    pub cwd: Option<String>,
    pub scratch_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ApprovalSection {
    pub enabled: bool,
    /// 127.0.0.1 bind port for the approval server (0 = ephemeral).
    pub port: u16,
    /// Seconds a pending approval stays valid.
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuditSection {
    pub path: String,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self { default: "deny".into(), rules: Vec::new() }
    }
}

impl Default for RuleEntry {
    fn default() -> Self {
        Self { pattern: String::new(), decision: "deny".into() }
    }
}

impl Default for PwshSection {
    fn default() -> Self {
        Self { binary: "pwsh".into(), constrained: false, env_remove: Vec::new() }
    }
}

impl Default for FsSection {
    fn default() -> Self {
        Self { roots: Vec::new(), deny: Vec::new(), max_read_bytes: 4 << 20 }
    }
}

impl Default for SandboxSection {
    fn default() -> Self {
        Self {
            cwd: None,
            scratch_dir: std::env::temp_dir().join("harbor").to_string_lossy().into_owned(),
        }
    }
}

impl Default for ApprovalSection {
    fn default() -> Self {
        Self { enabled: true, port: 0, ttl_secs: 60 }
    }
}

impl Default for AuditSection {
    fn default() -> Self {
        Self { path: std::env::temp_dir().join("harbor-audit.log").to_string_lossy().into_owned() }
    }
}

/// Load config from a path; env vars override the fail-closed defaults.
pub fn load(path: Option<&PathBuf>) -> HarborConfig {
    let mut cfg: HarborConfig = match path {
        Some(p) => {
            let raw = std::fs::read_to_string(p)
                .unwrap_or_else(|e| panic!("cannot read config {}: {e}", p.display()));
            toml::from_str(&raw).unwrap_or_else(|e| panic!("invalid config {}: {e}", p.display()))
        }
        None => HarborConfig::default(),
    };
    apply_env_overrides(&mut cfg);
    cfg
}

fn apply_env_overrides(cfg: &mut HarborConfig) {
    if let Ok(v) = std::env::var("HARBOR_POLICY_DEFAULT") {
        cfg.policy.default = v;
    }
    if let Ok(v) = std::env::var("HARBOR_AUDIT_PATH") {
        cfg.audit.path = v;
    }
    if let Ok(v) = std::env::var("HARBOR_APPROVAL_PORT") {
        if let Ok(port) = v.parse() {
            cfg.approval.port = port;
        }
    }
    if let Ok(v) = std::env::var("HARBOR_APPROVAL_TTL") {
        if let Ok(ttl) = v.parse() {
            cfg.approval.ttl_secs = ttl;
        }
    }
    if let Ok(v) = std::env::var("HARBOR_FS_MAX_READ") {
        if let Ok(n) = v.parse() {
            cfg.fs.max_read_bytes = n;
        }
    }
}

pub fn parse_decision(s: &str) -> Decision {
    match s.to_lowercase().as_str() {
        "allow" => Decision::Allow,
        "ask" => Decision::Ask,
        _ => Decision::Deny,
    }
}

/// Build the policy engine from config (fail closed on bad input).
pub fn build_policy(cfg: &PolicyConfig) -> PolicyEngine {
    let mut engine = PolicyEngine::new(parse_decision(&cfg.default));
    for r in &cfg.rules {
        let decision = parse_decision(&r.decision);
        engine.add_rule(PolicyRule::new(r.pattern.clone(), decision));
    }
    engine
}

pub fn build_redactor(_cfg: &HarborConfig) -> Redactor {
    let secrets: Vec<String> = std::env::var("HARBOR_SECRETS")
        .map(|s| s.split(',').map(str::trim).map(str::to_owned).collect())
        .unwrap_or_default();
    Redactor::new(secrets)
}

pub fn build_fs_core(cfg: &FsSection) -> FsCore {
    let roots: Vec<PathBuf> = cfg.roots.iter().map(PathBuf::from).collect();
    let deny: Vec<_> = cfg.deny.iter().filter_map(|p| Glob::new(p).ok()).map(|g| g.compile_matcher()).collect();
    FsCore::new(roots, deny, cfg.max_read_bytes)
}

pub fn build_pwsh_cfg(cfg: &PwshSection) -> PwshConfig {
    PwshConfig {
        binary: cfg.binary.clone(),
        constrained_default: cfg.constrained,
        env_remove: cfg.env_remove.clone(),
    }
}

/// Wiring bundle the MCP server needs.
pub struct HarborRuntime {
    pub policy: PolicyEngine,
    pub redactor: Redactor,
    pub pwsh: Arc<dyn harbor_core::capability::Capability>,
    pub fs: Vec<Arc<dyn harbor_core::capability::Capability>>,
    pub audit: Arc<harbor_core::audit::AuditLog>,
    pub scratch_dir: PathBuf,
    pub default_cwd: Option<String>,
}

pub fn build_runtime(cfg: &HarborConfig) -> HarborRuntime {
    let policy = build_policy(&cfg.policy);
    let redactor = build_redactor(cfg);
    let pwsh = Arc::new(harbor_providers::pwsh::PwshProvider::new(build_pwsh_cfg(&cfg.pwsh)));
    let fs: Vec<Arc<dyn harbor_core::capability::Capability>> = harbor_providers::fs::fs_provider(build_fs_core(&cfg.fs)).into_iter().map(Arc::from).collect();
    let audit = Arc::new(
        harbor_core::audit::AuditLog::open(std::path::Path::new(&cfg.audit.path))
            .unwrap_or_else(|e| panic!("cannot open audit log {}: {e}", cfg.audit.path)),
    );
    HarborRuntime { policy, redactor, pwsh, fs, audit, scratch_dir: PathBuf::from(&cfg.sandbox.scratch_dir), default_cwd: cfg.sandbox.cwd.clone() }
}