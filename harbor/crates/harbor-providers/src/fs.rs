//! The file-system capability provider: `fs.read`, `fs.write`, `fs.list`,
//! `fs.stat`. Every path is canonicalized (symlinks resolved) and must stay
//! inside a configured root; a deny-glob list is checked on the resolved path.

use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use globset::GlobMatcher;
use harbor_core::capability::{Capability, CapabilityContext, CapabilityManifest, ResourceBudget, Risk};
use harbor_core::errors::{CapError, CapResult};
use serde_json::{json, Value};
use tokio::fs;

fn norm(path: &Path) -> String {
    let mut s = path.to_string_lossy().replace('\\', "/");
    // Windows canonicalize returns the `\\?\` verbatim prefix; strip it so
    // root matching sees plain `C:/...` (and UNC shares become `//host/share`).
    if let Some(rest) = s.strip_prefix("//?/UNC/") {
        s = format!("//{rest}");
    } else if let Some(rest) = s.strip_prefix("//?/") {
        s = rest.to_string();
    }
    s
}

/// Shared root-confined path resolution. One instance per provider; the four
/// capabilities all funnel through it.
#[derive(Debug, Clone)]
pub struct FsCore {
    roots: Vec<PathBuf>,
    deny: Vec<GlobMatcher>,
    max_read_bytes: usize,
}

impl FsCore {
    /// Resolve `raw` inside the roots. Canonicalizes (symlink-safe), rejects
    /// traversal, then checks the deny globs. Returns the resolved path.
    async fn confine(&self, raw: &str) -> CapResult<PathBuf> {
        let p = Path::new(raw);
        if p.is_relative() {
            return Err(CapError::PathOutOfBounds(raw.to_string()));
        }
        for c in p.components() {
            if matches!(c, Component::ParentDir) {
                return Err(CapError::PathOutOfBounds(raw.to_string()));
            }
        }
        let resolved = fs::canonicalize(&p).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CapError::NotFound(raw.to_string())
            } else {
                CapError::Io(e)
            }
        })?;
        self.check(&resolved)
    }

    /// Like `confine` but tolerates a missing FINAL component (for writes that
    /// create a new file): canonicalizes the parent, then re-appends the leaf.
    async fn confine_create(&self, raw: &str) -> CapResult<PathBuf> {
        let p = Path::new(raw);
        if p.is_relative() {
            return Err(CapError::PathOutOfBounds(raw.to_string()));
        }
        for c in p.components() {
            if matches!(c, Component::ParentDir) {
                return Err(CapError::PathOutOfBounds(raw.to_string()));
            }
        }
        let parent = p.parent().ok_or_else(|| CapError::PathOutOfBounds(raw.to_string()))?;
        let leaf = p.file_name().ok_or_else(|| CapError::PathOutOfBounds(raw.to_string()))?;
        let canonical_parent = fs::canonicalize(parent).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CapError::NotFound(raw.to_string())
            } else {
                CapError::Io(e)
            }
        })?;
        let resolved = canonical_parent.join(leaf);
        self.check(&resolved)
    }

    /// Root-containment + deny-glob check on an already-resolved path.
    fn check(&self, resolved: &Path) -> CapResult<PathBuf> {
        let n = norm(resolved);
        let inside = self.roots.iter().any(|r| {
            let root = norm(r);
            let root = root.trim_end_matches('/');
            n.starts_with(root) && (n.len() == root.len() || n[root.len()..].starts_with('/'))
        });
        if !inside {
            return Err(CapError::PathOutOfBounds(n));
        }
        for d in &self.deny {
            if d.is_match(&n) {
                return Err(CapError::PathDenied(n));
            }
        }
        Ok(resolved.to_path_buf())
    }
}

fn manifest(id: &'static str, risk: Risk, desc: &'static str, budget: ResourceBudget, schema: Value) -> CapabilityManifest {
    CapabilityManifest { id, version: 1, risk, description: desc, secret_sensitive: false, budget, input_schema: schema }
}

fn fs_manifest(id: &'static str) -> CapabilityManifest {
    let path = json!({ "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] });
    let write = json!({ "type": "object", "properties": {
        "path": { "type": "string" },
        "content": { "type": "string" },
        "append": { "type": "boolean", "default": false }
    }, "required": ["path", "content"] });
    match id {
        "fs.read" => manifest("fs.read", Risk::Medium, "Read a file's text content (size-capped; binary files return metadata only)",
            ResourceBudget { timeout: std::time::Duration::from_secs(30), max_output_bytes: 4 << 20 }, path),
        "fs.write" => manifest("fs.write", Risk::High, "Create or overwrite a file inside an allowed root",
            ResourceBudget { timeout: std::time::Duration::from_secs(30), max_output_bytes: 64 << 10 }, write),
        "fs.list" => manifest("fs.list", Risk::Low, "List a directory's entries (name, type, size, mtime)",
            ResourceBudget { timeout: std::time::Duration::from_secs(30), max_output_bytes: 1 << 20 }, path),
        "fs.stat" => manifest("fs.stat", Risk::Low, "Metadata for one path (type, size, mtime, permissions)",
            ResourceBudget { timeout: std::time::Duration::from_secs(30), max_output_bytes: 64 << 10 }, path),
        _ => unreachable!("unknown fs capability id"),
    }
}

// ── fs.read ─────────────────────────────────────────────────────────────────

pub struct FsRead {
    core: FsCore,
    manifest: &'static CapabilityManifest,
}

// ── fs.write ────────────────────────────────────────────────────────────────

pub struct FsWrite {
    core: FsCore,
    manifest: &'static CapabilityManifest,
}

// ── fs.list ─────────────────────────────────────────────────────────────────

pub struct FsList {
    core: FsCore,
    manifest: &'static CapabilityManifest,
}

// ── fs.stat ─────────────────────────────────────────────────────────────────

pub struct FsStat {
    core: FsCore,
    manifest: &'static CapabilityManifest,
}

fn leak(manifest: CapabilityManifest) -> &'static CapabilityManifest {
    Box::leak(Box::new(manifest))
}

impl FsRead {
    pub fn new(core: FsCore) -> Self {
        Self { core, manifest: leak(fs_manifest("fs.read")) }
    }
}

impl FsWrite {
    pub fn new(core: FsCore) -> Self {
        Self { core, manifest: leak(fs_manifest("fs.write")) }
    }
}

impl FsList {
    pub fn new(core: FsCore) -> Self {
        Self { core, manifest: leak(fs_manifest("fs.list")) }
    }
}

impl FsStat {
    pub fn new(core: FsCore) -> Self {
        Self { core, manifest: leak(fs_manifest("fs.stat")) }
    }
}

// The macro approach fights the trait's `&'static` requirement; implement each
// impl block directly instead for clarity.
#[async_trait]
impl Capability for FsRead {
    fn manifest(&self) -> &'static CapabilityManifest {
        // Each capability owns its manifest via a leaked Box; documented
        // tradeoff (a handful of bytes per process) for a `'static` ref.
        self.manifest
    }
    fn resource(&self, params: &Value) -> Option<String> {
        params.get("path").and_then(Value::as_str).map(str::to_owned)
    }
    async fn invoke(&self, _ctx: &CapabilityContext, params: Value) -> CapResult<Value> {
        let raw = params.get("path").and_then(Value::as_str).ok_or_else(|| CapError::InvalidParams("'path' required".into()))?;
        let resolved = self.core.confine(raw).await?;
        let meta = fs::metadata(&resolved).await?;
        if !meta.is_file() {
            return Err(CapError::InvalidParams(format!("not a file: {}", norm(&resolved))));
        }
        let size = meta.len();
        if size > self.core.max_read_bytes as u64 {
            return Ok(json!({ "path": norm(&resolved), "size": size, "binary": null, "truncated": true, "content": null }));
        }
        let data = fs::read(&resolved).await?;
        let binary = data.contains(&0u8);
        let content = if binary { Value::Null } else { Value::String(String::from_utf8_lossy(&data).into_owned()) };
        Ok(json!({ "path": norm(&resolved), "size": size, "binary": binary, "truncated": false, "content": content }))
    }
}

#[async_trait]
impl Capability for FsWrite {
    fn manifest(&self) -> &'static CapabilityManifest {
        self.manifest
    }
    fn resource(&self, params: &Value) -> Option<String> {
        params.get("path").and_then(Value::as_str).map(str::to_owned)
    }
    async fn invoke(&self, _ctx: &CapabilityContext, params: Value) -> CapResult<Value> {
        let raw = params.get("path").and_then(Value::as_str).ok_or_else(|| CapError::InvalidParams("'path' required".into()))?;
        let content = params.get("content").and_then(Value::as_str).ok_or_else(|| CapError::InvalidParams("'content' required".into()))?;
        let append = params.get("append").and_then(Value::as_bool).unwrap_or(false);
        let resolved = self.core.confine_create(raw).await?;
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true).append(append).truncate(!append);
        let mut f = opts.open(&resolved).await?;
        use tokio::io::AsyncWriteExt;
        f.write_all(content.as_bytes()).await?;
        f.flush().await?;
        Ok(json!({ "path": norm(&resolved), "bytes": content.len(), "append": append }))
    }
}

#[async_trait]
impl Capability for FsList {
    fn manifest(&self) -> &'static CapabilityManifest {
        self.manifest
    }
    fn resource(&self, params: &Value) -> Option<String> {
        params.get("path").and_then(Value::as_str).map(str::to_owned)
    }
    async fn invoke(&self, _ctx: &CapabilityContext, params: Value) -> CapResult<Value> {
        let raw = params.get("path").and_then(Value::as_str).ok_or_else(|| CapError::InvalidParams("'path' required".into()))?;
        let resolved = self.core.confine(raw).await?;
        let mut entries = fs::read_dir(&resolved).await?;
        let mut out = Vec::new();
        while let Some(ent) = entries.next_entry().await? {
            let name = ent.file_name().to_string_lossy().into_owned();
            let meta = ent.metadata().await?;
            out.push(json!({
                "name": name,
                "kind": if meta.is_dir() { "dir" } else if meta.is_file() { "file" } else { "other" },
                "size": meta.len(),
                "mtime": meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()),
            }));
        }
        out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        Ok(json!({ "path": norm(&resolved), "entries": out }))
    }
}

#[async_trait]
impl Capability for FsStat {
    fn manifest(&self) -> &'static CapabilityManifest {
        self.manifest
    }
    fn resource(&self, params: &Value) -> Option<String> {
        params.get("path").and_then(Value::as_str).map(str::to_owned)
    }
    async fn invoke(&self, _ctx: &CapabilityContext, params: Value) -> CapResult<Value> {
        let raw = params.get("path").and_then(Value::as_str).ok_or_else(|| CapError::InvalidParams("'path' required".into()))?;
        let resolved = self.core.confine(raw).await?;
        let meta = fs::metadata(&resolved).await?;
        Ok(json!({
            "path": norm(&resolved),
            "kind": if meta.is_dir() { "dir" } else if meta.is_file() { "file" } else { "other" },
            "size": meta.len(),
            "readonly": meta.permissions().readonly(),
            "mtime": meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()),
        }))
    }
}

/// Assemble all four fs capabilities sharing one confinement core.
pub fn fs_provider(core: FsCore) -> Vec<Box<dyn Capability>> {
    vec![
        Box::new(FsRead::new(core.clone())),
        Box::new(FsWrite::new(core.clone())),
        Box::new(FsList::new(core.clone())),
        Box::new(FsStat::new(core)),
    ]
}

impl FsCore {
    pub fn new(roots: Vec<PathBuf>, deny: Vec<GlobMatcher>, max_read_bytes: usize) -> Self {
        Self { roots, deny, max_read_bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use globset::Glob;
    use harbor_core::redact::Redactor;
    use harbor_core::session::Session;

    fn ctx() -> CapabilityContext {
        CapabilityContext { session: Session::new(std::path::Path::new(".")), redactor: Redactor::default() }
    }

    fn core(root: &Path) -> FsCore {
        FsCore::new(
            vec![root.to_path_buf()],
            vec![Glob::new("**/.secret/**").unwrap().compile_matcher()],
            4096,
        )
    }

    #[tokio::test]
    async fn read_write_list_within_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let caps = fs_provider(core(root));
        let f = root.join("hello.txt");
        let write = caps.iter().find(|c| c.manifest().id == "fs.write").unwrap();
        let read = caps.iter().find(|c| c.manifest().id == "fs.read").unwrap();
        let list = caps.iter().find(|c| c.manifest().id == "fs.list").unwrap();
        write.invoke(&ctx(), json!({ "path": f.to_string_lossy(), "content": "hi there" })).await.unwrap();
        let r = read.invoke(&ctx(), json!({ "path": f.to_string_lossy() })).await.unwrap();
        assert_eq!(r["content"], "hi there");
        let l = list.invoke(&ctx(), json!({ "path": root.to_string_lossy() })).await.unwrap();
        assert!(l["entries"].as_array().unwrap().iter().any(|e| e["name"] == "hello.txt"));
    }

    #[tokio::test]
    async fn traversal_outside_root_is_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let caps = fs_provider(core(root));
        let read = caps.iter().find(|c| c.manifest().id == "fs.read").unwrap();
        let outside = root.parent().unwrap().join("evil.txt");
        let err = read.invoke(&ctx(), json!({ "path": outside.to_string_lossy() })).await.unwrap_err();
        assert!(matches!(err, CapError::PathOutOfBounds(_) | CapError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn deny_glob_is_checked_on_resolved_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let secret = root.join(".secret");
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::write(secret.join("k.txt"), "s3cr3t").unwrap();
        let caps = fs_provider(core(root));
        let read = caps.iter().find(|c| c.manifest().id == "fs.read").unwrap();
        let err = read.invoke(&ctx(), json!({ "path": secret.join("k.txt").to_string_lossy() })).await.unwrap_err();
        assert!(matches!(err, CapError::PathDenied(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn binary_files_return_no_content() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let b = root.join("blob.bin");
        std::fs::write(&b, [0u8, 159, 146, 150]).unwrap();
        let caps = fs_provider(core(root));
        let read = caps.iter().find(|c| c.manifest().id == "fs.read").unwrap();
        let r = read.invoke(&ctx(), json!({ "path": b.to_string_lossy() })).await.unwrap();
        assert_eq!(r["binary"], true);
        assert!(r["content"].is_null());
    }

    #[tokio::test]
    async fn relative_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let caps = fs_provider(core(dir.path()));
        let read = caps.iter().find(|c| c.manifest().id == "fs.read").unwrap();
        let err = read.invoke(&ctx(), json!({ "path": "foo/bar" })).await.unwrap_err();
        assert!(matches!(err, CapError::PathOutOfBounds(_)));
    }
}