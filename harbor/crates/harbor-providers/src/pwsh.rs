//! The PowerShell capability provider: `pwsh.run`.
//!
//! Executes a script in a detached `pwsh` child with server-enforced budgets:
//! wall-clock timeout (kill the whole process tree), output byte cap, and
//! optional Constrained Language Mode. Output is returned structurally
//! (`exit_code`, `stdout`, `stderr`, ...) so the client never parses text.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use harbor_core::capability::{
    Capability, CapabilityContext, CapabilityManifest, ResourceBudget, Risk,
};
use harbor_core::errors::{CapError, CapResult};
use harbor_core::redact::sha256;
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;

fn manifest() -> &'static CapabilityManifest {
    static M: OnceLock<CapabilityManifest> = OnceLock::new();
    M.get_or_init(|| CapabilityManifest {
        id: "pwsh.run",
        version: 1,
        risk: Risk::Critical,
        description: "Run a PowerShell script in a sandboxed child process with a timeout and output cap",
        secret_sensitive: true,
        budget: ResourceBudget { timeout: Duration::from_secs(120), max_output_bytes: 2 << 20 },
        input_schema: json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "PowerShell script to execute" },
                "cwd": { "type": "string", "description": "Working directory (default: server cwd)" },
                "timeout_ms": { "type": "integer", "description": "Override the timeout in ms" },
                "max_output": { "type": "integer", "description": "Override the output cap in bytes" },
                "stdin": { "type": "string", "description": "Optional text to pipe to the child's stdin" },
                "constrained": { "type": "boolean", "description": "Run in Constrained Language Mode" }
            },
            "required": ["command"]
        }),
    })
}

/// Configuration for the pwsh provider.
#[derive(Debug, Clone)]
pub struct PwshConfig {
    /// Path to `pwsh` (or just "pwsh" to use PATH).
    pub binary: String,
    /// Default for `constrained` when a call doesn't specify it.
    pub constrained_default: bool,
    /// Env vars REMOVED from the child's environment (secrets etc.).
    pub env_remove: Vec<String>,
}

impl Default for PwshConfig {
    fn default() -> Self {
        Self {
            binary: "pwsh".into(),
            constrained_default: false,
            env_remove: Vec::new(),
        }
    }
}

pub struct PwshProvider {
    cfg: PwshConfig,
}

impl PwshProvider {
    pub fn new(cfg: PwshConfig) -> Self {
        Self { cfg }
    }

    fn script_with_clm(command: &str, constrained: bool) -> String {
        if constrained {
            format!(
                "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage';\n{command}"
            )
        } else {
            command.to_string()
        }
    }
}

#[async_trait]
impl Capability for PwshProvider {
    fn manifest(&self) -> &'static CapabilityManifest {
        manifest()
    }

    fn resource(&self, params: &Value) -> Option<String> {
        params
            .get("command")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    async fn invoke(&self, _ctx: &CapabilityContext, params: Value) -> CapResult<Value> {
        let command = params
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| CapError::InvalidParams("'command' is required".into()))?
            .to_string();

        let cwd = params.get("cwd").and_then(Value::as_str);
        let constrained = params
            .get("constrained")
            .and_then(Value::as_bool)
            .unwrap_or(self.cfg.constrained_default);
        let stdin = params.get("stdin").and_then(Value::as_str);
        let timeout = params
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .map(Duration::from_millis)
            .unwrap_or(manifest().budget.timeout)
            .min(manifest().budget.timeout);
        let max_output = params
            .get("max_output")
            .and_then(Value::as_u64)
            .map(|v| v as usize)
            .unwrap_or(manifest().budget.max_output_bytes)
            .min(manifest().budget.max_output_bytes);

        let script = Self::script_with_clm(&command, constrained);
        let encoded = encode_command(&script);

        let mut cmd = tokio::process::Command::new(&self.cfg.binary);
        cmd.args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .kill_on_drop(true);
        if let Some(d) = cwd {
            cmd.current_dir(d);
        }
        if stdin.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        for key in &self.cfg.env_remove {
            cmd.env_remove(key);
        }

        let start = Instant::now();
        let mut child = cmd
            .spawn()
            .map_err(|e| CapError::Internal(format!("failed to spawn {}: {e}", self.cfg.binary)))?;

        let mut stdin_task = None;
        if let Some(text) = stdin {
            let mut child_stdin = child
                .stdin
                .take()
                .ok_or_else(|| CapError::Internal("no stdin pipe".into()))?;
            let text = text.to_string();
            stdin_task = Some(tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let _ = child_stdin.write_all(text.as_bytes()).await;
                let _ = child_stdin.flush().await;
            }));
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CapError::Internal("no stdout pipe".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| CapError::Internal("no stderr pipe".into()))?;
        let out_task = tokio::spawn(read_capped(stdout, max_output));
        let err_task = tokio::spawn(read_capped(stderr, max_output));

        let wait = child.wait();
        let status = match tokio::time::timeout(timeout, wait).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(CapError::from(e)),
            Err(_) => {
                kill_tree(&mut child, &self.cfg.binary).await;
                let _ = child.wait().await;
                return Err(CapError::Timeout(timeout.as_millis() as u64));
            }
        };

        if let Some(t) = stdin_task {
            let _ = t.await;
        }
        let (out, out_trunc) = out_task
            .await
            .map_err(|e| CapError::Internal(format!("stdout task: {e}")))?;
        let (err, err_trunc) = err_task
            .await
            .map_err(|e| CapError::Internal(format!("stderr task: {e}")))?;

        let stdout_text = String::from_utf8_lossy(&out).into_owned();
        let stderr_text = String::from_utf8_lossy(&err).into_owned();
        let duration_ms = start.elapsed().as_millis() as u64;
        let exit_code = status.code();

        let output_json = json!({
            "exit_code": exit_code,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "duration_ms": duration_ms,
            "truncated": out_trunc || err_trunc,
            "out_sha256": sha256(&out),
        });

        tracing::debug!(
            capability = "pwsh.run",
            duration_ms,
            exit_code,
            "pwsh invocation complete"
        );

        Ok(output_json)
    }
}

/// Encode a script for `pwsh -EncodedCommand`: base64 of UTF-16LE.
fn encode_command(script: &str) -> String {
    let utf16: Vec<u16> = script.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for u in utf16 {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Read a pipe into a Vec, stopping at `cap` bytes then draining (discarding)
/// the rest so the child never blocks on a full pipe while memory stays bounded.
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(mut r: R, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(cap.min(1 << 16));
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if out.len() + n > cap {
            truncated = true;
            // Drain-discard the rest.
            let mut sink = [0u8; 8192];
            loop {
                match r.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    (out, truncated)
}

/// Kill the whole process tree. On Windows use `taskkill /T` (kills children
/// too); on Unix the child is killed directly and, because we spawn without a
/// process group change, grandchildren may linger — acceptable for v1, noted in
/// DESIGN.md roadmap (process-group isolation).
async fn kill_tree(child: &mut tokio::process::Child, binary: &str) {
    #[cfg(windows)]
    {
        if let Some(pid) = child.id() {
            let _ = tokio::process::Command::new("taskkill")
                .args(["/T", "/F", "/PID", &pid.to_string()])
                .output()
                .await;
        }
        let _ = child.kill().await;
    }
    #[cfg(not(windows))]
    {
        let _ = child.kill().await;
    }
    let _ = binary;
}

#[cfg(test)]
mod tests {
    use super::*;
    use harbor_core::redact::Redactor;
    use harbor_core::session::Session;

    fn ctx() -> CapabilityContext {
        CapabilityContext {
            session: Session::new(std::path::Path::new(".")),
            redactor: Redactor::default(),
        }
    }

    #[tokio::test]
    async fn runs_a_script_and_returns_exit_code() {
        if std::process::Command::new("pwsh")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("exit 0")
            .status()
            .is_err()
        {
            eprintln!("pwsh not available; skipping");
            return;
        }
        let p = PwshProvider::new(PwshConfig::default());
        let out = p
            .invoke(
                &ctx(),
                json!({ "command": "'1+1' | Write-Output; Write-Output 'ok'" }),
            )
            .await
            .unwrap();
        assert_eq!(out["exit_code"], 0);
        assert!(out["stdout"].as_str().unwrap().contains("ok"));
    }

    #[tokio::test]
    async fn timeout_kills_the_process() {
        if std::process::Command::new("pwsh")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("exit 0")
            .status()
            .is_err()
        {
            return;
        }
        let p = PwshProvider::new(PwshConfig::default());
        let err = p
            .invoke(
                &ctx(),
                json!({ "command": "Start-Sleep -Seconds 30; exit 0", "timeout_ms": 200 }),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, CapError::Timeout(_)),
            "expected Timeout, got {err:?}"
        );
    }

    #[tokio::test]
    async fn output_cap_truncates() {
        if std::process::Command::new("pwsh")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("exit 0")
            .status()
            .is_err()
        {
            return;
        }
        let p = PwshProvider::new(PwshConfig::default());
        let out = p
            .invoke(&ctx(), json!({ "command": "1..100000 | ForEach-Object { 'x' * 80 }", "max_output": 1024, "timeout_ms": 20000 }))
            .await
            .unwrap();
        assert!(
            out["truncated"].as_bool().unwrap(),
            "output should be truncated"
        );
        assert!(out["stdout"].as_str().unwrap().len() <= 4096);
    }

    #[test]
    fn encoded_command_is_base64_utf16le() {
        let e = encode_command("Get-Process");
        // Decode and confirm it's UTF-16LE "Get-Process".
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&e)
            .unwrap();
        let utf16: Vec<u16> = bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let s: String = char::decode_utf16(utf16)
            .map(|r| r.unwrap_or('?'))
            .collect();
        assert_eq!(s, "Get-Process");
    }
}
