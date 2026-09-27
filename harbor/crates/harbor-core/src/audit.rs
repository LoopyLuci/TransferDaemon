//! Tamper-evident append-only audit log.
//!
//! One JSON object per line. Every entry embeds `prev_hash` = sha256 of the
//! PREVIOUS line's raw bytes, forming a hash chain. Recomputing the chain over
//! the file detects any retroactive insertion, deletion, or edit. This is the
//! operator's ground truth for "what did the agent actually do".

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::{CapError, CapResult};
use crate::policy::Decision;

/// One immutable audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unix seconds.
    pub ts: u64,
    pub session_id: String,
    pub request_id: String,
    pub capability: String,
    /// The resource string policy matched on (path / command text). Redacted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(rename = "decision")]
    pub decision: String,
    /// "human" when approved via the approval URL, "policy" when allowed by a
    /// rule, "timeout" when the Ask expired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// sha256 of the (redacted) output returned to the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// sha256 of the previous line's raw bytes ("" for the first entry).
    pub prev_hash: String,
}

/// Append-only, hash-chained audit log.
pub struct AuditLog {
    file: Mutex<File>,
    prev_hash: Mutex<String>,
}

impl AuditLog {
    /// Open (or create) the log at `path` and, if the file already has
    /// entries, load the last entry's hash to continue the chain.
    pub fn open(path: &Path) -> CapResult<Self> {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        let prev_hash = last_hash(path)?;
        // Writes are line-buffered at the OS level; force a flush boundary so
        // a crash never leaves a torn line behind.
        file.write_all(b"\n")?;
        Ok(Self {
            file: Mutex::new(file),
            prev_hash: Mutex::new(prev_hash),
        })
    }

    /// Append an entry to the chain. The entry's `prev_hash` is the hash of
    /// the previous raw line; the returned entry carries the new hash for the
    /// next append.
    pub fn append(&self, mut entry: AuditEntry) -> CapResult<String> {
        let mut prev = self.prev_hash.lock().expect("audit mutex poisoned");
        entry.prev_hash = prev.clone();
        let mut raw = serde_json::to_vec(&entry)
            .map_err(|e| CapError::Internal(format!("audit serialize: {e}")))?;
        raw.push(b'\n');
        let hash = hex(&Sha256::digest(&raw));
        {
            let mut f = self.file.lock().expect("audit mutex poisoned");
            f.write_all(&raw)?;
            f.flush()?;
        }
        *prev = hash.clone();
        Ok(hash)
    }

    /// Verify the chain integrity of the whole file. Returns true iff every
    /// entry's prev_hash matches the hash of the preceding line.
    pub fn verify(path: &Path) -> bool {
        let Ok(lines) = read_lines(path) else {
            return false;
        };
        let mut expect = String::new();
        for line in lines {
            let raw = format!("{line}\n");
            let hash = hex(&Sha256::digest(raw.as_bytes()));
            let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) else {
                return false;
            };
            if entry.prev_hash != expect {
                return false;
            }
            expect = hash;
        }
        true
    }
}

fn read_lines(path: &Path) -> std::io::Result<Vec<String>> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    let mut lines = Vec::new();
    let mut buf = String::new();
    while reader.read_line(&mut buf)? > 0 {
        let trimmed = buf.trim_end_matches(['\n', '\r']).to_string();
        if !trimmed.is_empty() {
            lines.push(trimmed);
        }
        buf.clear();
    }
    Ok(lines)
}

/// The hash the next appended line must reference ("" if the file is empty).
fn last_hash(path: &Path) -> CapResult<String> {
    let lines = read_lines(path)?;
    match lines.last() {
        Some(line) => Ok(hex(&Sha256::digest(format!("{line}\n").as_bytes()))),
        None => Ok(String::new()),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Convenience builder so providers/servers don't have to hand-assemble entries.
pub struct EntryBuilder {
    pub session_id: String,
    pub request_id: String,
}

impl EntryBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        &self,
        capability: &str,
        resource: Option<String>,
        decision: Decision,
        approver: Option<&str>,
        exit: Option<i32>,
        duration_ms: Option<u64>,
        out_sha256: Option<String>,
        error: Option<String>,
    ) -> AuditEntry {
        AuditEntry {
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            session_id: self.session_id.clone(),
            request_id: self.request_id.clone(),
            capability: capability.to_string(),
            resource,
            decision: format!("{decision:?}").to_lowercase(),
            approver: approver.map(str::to_owned),
            exit,
            duration_ms,
            out_sha256,
            error,
            prev_hash: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Decision;

    #[test]
    fn chain_is_append_only_and_verifiable() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.log");
        let log = AuditLog::open(&p).unwrap();
        let b = EntryBuilder {
            session_id: "s1".into(),
            request_id: "r1".into(),
        };
        let e1 = b.build(
            "fs.read",
            Some("Z:/x".into()),
            Decision::Allow,
            Some("policy"),
            None,
            None,
            None,
            None,
        );
        let h1 = log.append(e1).unwrap();
        assert!(!h1.is_empty());
        let e2 = b.build(
            "pwsh.run",
            Some("whoami".into()),
            Decision::Allow,
            Some("policy"),
            Some(0),
            Some(3),
            Some("abc".into()),
            None,
        );
        let h2 = log.append(e2).unwrap();
        assert_ne!(h1, h2);
        drop(log);
        assert!(AuditLog::verify(&p), "untouched chain must verify");

        // A retroactive edit (tamper) must break the chain.
        let mut lines = read_lines(&p).unwrap();
        lines[0] = lines[0].replace("Z:/x", "Z:/evil");
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        assert!(!AuditLog::verify(&p), "edited chain must FAIL verification");
    }

    #[test]
    fn reopens_and_continues_chain() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.log");
        let log = AuditLog::open(&p).unwrap();
        let b = EntryBuilder {
            session_id: "s".into(),
            request_id: "r".into(),
        };
        log.append(b.build("a.b", None, Decision::Deny, None, None, None, None, None))
            .unwrap();
        drop(log);
        let log2 = AuditLog::open(&p).unwrap();
        log2.append(b.build(
            "c.d",
            None,
            Decision::Ask,
            Some("human"),
            None,
            None,
            None,
            None,
        ))
        .unwrap();
        drop(log2);
        assert!(AuditLog::verify(&p));
    }
}
