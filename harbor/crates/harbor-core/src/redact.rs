//! Secret redaction. Every capability output passes through a Redactor before
//! it is returned to the client; secret-sensitive capabilities are redacted
//! even when the caller didn't ask.

use regex::Regex;
use serde::Serialize;

/// Redacts likely secrets from text. The patterns cover common assignment
/// forms plus a few well-known secret shapes. Configured literal secrets are
/// matched case-insensitively and replaced.
#[derive(Debug, Clone)]
pub struct Redactor {
    /// (pattern, replacement) pairs — replacement may reference group 1.
    patterns: Vec<(Regex, &'static str)>,
    secrets: Vec<(String, String)>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl Redactor {
    pub fn new(configured_secrets: Vec<String>) -> Self {
        let patterns = vec![
            // Bearer token: keep the prefix for context, mask the token.
            (Regex::new(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+").expect("static regex"), "${1}[REDACTED]"),
            // name = value / name: value for the classic secret keys.
            (Regex::new(r#"(?i)\b(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|session[_-]?token|authorization|private[_-]?key)\b\s*[:=]\s*[^\s"'`,;]+"#)
                .expect("static regex"), "[REDACTED]"),
            // AWS access key + secret pair.
            (Regex::new(r"(?i)\bAKIA[0-9A-Z]{16}\b").expect("static regex"), "[REDACTED]"),
            (Regex::new(r"(?i)\b(?:aws_secret_access_key)\s*[:=]\s*\S+").expect("static regex"), "[REDACTED]"),
            // Long hex/base64 blobs that look like keys.
            (Regex::new(r"\b[0-9a-fA-F]{32,}\b").expect("static regex"), "[REDACTED]"),
            (Regex::new(r"\b[A-Za-z0-9+/]{40,}={0,2}\b").expect("static regex"), "[REDACTED]"),
            // Connection strings / URIs with embedded credentials (keep the scheme).
            (Regex::new(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@").expect("static regex"), "${1}[REDACTED]"),
        ];
        let secrets = configured_secrets
            .into_iter()
            .map(|s| (s.clone(), s.to_lowercase()))
            .collect();
        Self { patterns, secrets }
    }

    /// Replace matched secrets with `[REDACTED]`. `visible` labels what's being
    /// redacted (e.g. "a secret") for the marker.
    pub fn redact(&self, input: &str) -> String {
        let mut out = input.to_string();
        for (p, replacement) in &self.patterns {
            out = p.replace_all(&out, *replacement).into_owned();
        }
        for (original, lower) in &self.secrets {
            if lower.is_empty() {
                continue;
            }
            if out.to_lowercase().contains(lower) {
                out = out.replace(original, "[REDACTED]");
                // Also catch case variants without being quadratic.
                let mut it = out.to_lowercase();
                while it.contains(lower) {
                    let idx = it.find(lower).expect("contains checked");
                    let end = idx + original.len();
                    out.replace_range(idx..end, "[REDACTED]");
                    it = out.to_lowercase();
                }
            }
        }
        out
    }
}

/// The redaction report for one output.
#[derive(Debug, Clone, Serialize)]
pub struct RedactionReport {
    /// Total bytes of the ORIGINAL output.
    pub input_bytes: usize,
    /// Bytes after redaction (informational).
    pub output_bytes: usize,
    /// sha256 of the redacted output — what the audit log records.
    pub out_sha256: String,
}

impl Redactor {
    pub fn report(&self, input: &str) -> RedactionReport {
        let redacted = self.redact(input);
        RedactionReport {
            input_bytes: input.len(),
            output_bytes: redacted.len(),
            out_sha256: sha256(redacted.as_bytes()),
        }
    }
}

pub fn sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(data);
    d.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_named_secrets() {
        let r = Redactor::default();
        assert_eq!(r.redact("password=hunter2 next"), "[REDACTED] next");
        assert_eq!(
            r.redact("Bearer abc1234567890123456789012345678xyz"),
            "Bearer [REDACTED]"
        );
    }

    #[test]
    fn redacts_uri_credentials() {
        let r = Redactor::default();
        assert_eq!(
            r.redact("postgres://user:supersecret@db:5432/x"),
            "postgres://[REDACTED]db:5432/x"
        );
    }

    #[test]
    fn redacts_configured_secrets() {
        let r = Redactor::new(vec!["s3cr3t-TOKEN-xyz".into()]);
        assert_eq!(
            r.redact("the value is s3cr3t-TOKEN-xyz ok"),
            "the value is [REDACTED] ok"
        );
        assert_eq!(r.redact("S3cr3t-token-xyz in caps"), "[REDACTED] in caps");
    }

    #[test]
    fn long_hex_blobs_are_masked() {
        let r = Redactor::default();
        let hexish = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(!r
            .redact(hexish)
            .contains("1234567890abcdef1234567890abcdef"));
    }
}
