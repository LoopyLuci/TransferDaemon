# Harbor — a safe harbor for agents

A local, **capability-gated MCP server** that lets an AI agent (OpenCode, or any
MCP client) use PowerShell and other computer features *safely*: every
operation is a named, versioned **capability**; every invocation is checked by a
**policy engine** (fail-closed by default), run under a **resource budget**,
through **secret redaction**, and recorded in a **tamper-evident audit log**.

This document records the non-obvious design decisions and the constraint that
drove each one — read it before changing anything. It is the contract of the
system.

---

## 0. The goal and what "100 years" means

The system must be **safe, secure, effective, modular, scalable** — and
designed to survive a century of tooling churn. Concretely, that last property
means:

1. **The MCP surface is stable.** `tools/list` returns tools derived from
   *capability manifests*. Adding PowerShell-on-Linux, a WSL provider, a remote
   agent, or an entirely new execution backend must not change the MCP
   contract, the policy grammar, or the audit format.
2. **Additive-only evolution.** A capability's meaning never mutates. New
   behavior = a new capability ID (`pwsh.run` stays `pwsh.run` forever). Old
   clients keep working; old audit entries stay valid. Deprecation is
   documented, never breaking.
3. **No protocol dependency rot.** The MCP layer is a hand-rolled, spec-strict
   JSON-RPC 2.0 module (~300 lines) with version *range* negotiation. The
   runtime dependency closure of the core is intentionally tiny (tokio, serde,
   thiserror). A dependency that vanishes does not take the system down.
4. **Fail closed, always.** The default policy is **deny**. Security
   properties are conservative: a crash, a misconfiguration, or an unknown
   client yields *less* capability, never more.

---

## 1. Architecture

```
                 ┌────────────────────────────────────────────────┐
                 │                 harbor (binary)                 │
                 │                                                │
  MCP client     │  ┌───────────────┐   ┌────────────────────────┐ │
 (OpenCode)      │  │  mcp.rs       │   │  registry.rs           │ │
 ─── stdio ─────▶│  │ JSON-RPC 2.0  │──▶│  tool ← capability     │ │
 JSON-RPC 2.0    │  │ version range │   │  + policy + budget     │ │
                 │  └───────┬───────┘   └──────────┬─────────────┘ │
                 │          │                      │               │
                 │          v                      v               │
                 │  ┌────────────────────────────────────────────┐ │
                 │  │  POLICY ENGINE  (default deny, rules, ask) │ │
                 │  └──────────────┬─────────────────────────────┘ │
                 │                 v                                │
                 │  ┌────────────────────────────────────────────┐ │
                 │  │  CAPABILITY PROVIDERS (self-describing)    │ │
                 │  │  pwsh.run   fs.read  fs.write  fs.list     │ │
                 │  │  ... (extensible)                          │ │
                 │  └──────────────┬─────────────────────────────┘ │
                 │                 │            ┌───────────────┐ │
                 │                 │            │ approval.rs   │ │
                 │                 v            │ loopback HTTP │ │
                 │  ┌────────────────────────┐  │ (Ask decision)│ │
                 │  │ session.rs + audit.rs  │  └───────────────┘ │
                 │  │ isolation + audit log  │                    │
                 │  └────────────────────────┘                    │
                 └────────────────────────────────────────────────┘
```

- **mcp.rs** — the protocol boundary. Speaks MCP over stdio; newline-delimited
  JSON-RPC 2.0. Negotiates a *range* of MCP protocol versions.
- **registry.rs** — builds the MCP tool list from capability manifests; routes
  `tools/call` through policy, budget, and the provider.
- **policy.rs** — the authorization gate. Decides `Allow | Deny | Ask` per
  `(capability_id, resource)`.
- **providers** — `harbor-providers` crate: `pwsh` and `fs`. Each implements
  the `Capability` trait. New providers plug in without touching the core.
- **approval.rs** — loopback-only HTTP endpoint implementing the `Ask` branch
  with a human in the loop.
- **audit.rs** — append-only, hash-chained log of every decision and result.
- **session.rs** — per-connection isolation and resource accounting.

---

## 2. Security model (the top concern)

An MCP server that runs PowerShell *is* remote code execution. The model is
defense in depth:

1. **Fail-closed policy** — default `deny`. Nothing runs until an explicit
   `harbor.toml` rule allows it.
2. **Least privilege at every layer** — the capability IDs are narrow
   (`fs.read` vs `fs.write` vs `pwsh.run`); policy can allow one without the
   others.
3. **Resource budgets** — per-invocation timeouts, output byte caps, and
   process-tree kill on timeout. No unbounded memory, disk, or CPU from a
   single call. Budgets are enforced by the *server*, not the command.
4. **Human approval** — the `Ask` decision pauses the call until a human
   approves via a loopback URL (see §4). Approvals are audited, TTL-bounded,
   and never delegated to the agent.
5. **Redaction** — outputs pass through a `Redactor` (common secret patterns +
   configured secrets) before returning to the client. Secret-bearing
   capabilities are flagged `secret_sensitive` and redacted by default.
6. **Path confinement** — the fs provider canonicalizes every path (resolving
   symlinks) and requires it to stay inside configured roots. Traversal and
   symlink escapes are denied even if a rule glob would allow them.
7. **Audit** — every call: capability, resource, decision, approver, exit
   code, duration, output hash. Hash-chained so retroactive edits are
   detectable.
8. **stdout is protocol-only** — diagnostics go to stderr (JSON lines); stdout
   is reserved for MCP frames, so a chatty provider can never corrupt the
   protocol stream.

### Threats considered

| Threat | Mitigation |
|---|---|
| Agent asks for `pwsh.run` of anything | default `deny`; explicit rules only; `Ask` for the rest |
| Agent encodes a payload in a *benign-looking* `fs.write` to a config file | policy per capability id + path glob; `Ask` default on writes |
| Symlink points `fs.read` outside the root | canonicalize + root check on the *resolved* path |
| Command never returns | per-call timeout → kill process tree |
| Command floods output | byte cap + truncation marker |
| Command exfiltrates a secret in stdout | redaction before the response is formed |
| Attacker injects a second JSON-RPC request mid-stream | strict newline framing + `id` tracking; malformed frames are errors |
| Approval URL sniffed | loopback bind only; URL contains a 128-bit random token |
| Audit log edited after the fact | sha256 hash chain; recompute on read and verify |
| Core dependency disappears upstream | tiny core closure; MCP layer hand-rolled |

---

## 3. The capability model (the 100-year abstraction)

```rust
pub struct CapabilityManifest {
    pub id: &'static str,          // "pwsh.run" — permanent, additive-only
    pub version: u32,              // bumps on behavior change; old versions keep working
    pub risk: Risk,                // Low | Medium | High | Critical
    pub input_schema: Value,       // JSON Schema for params
    pub description: &'static str,
    pub secret_sensitive: bool,    // outputs may contain secrets → redact
    pub budget: ResourceBudget,    // timeout, max_output_bytes
}

pub trait Capability: Send + Sync {
    fn manifest(&self) -> &'static CapabilityManifest;
    fn invoke(&self, ctx: &CapabilityContext, params: Value)
        -> BoxFuture<Result<Value, CapError>>;
}
```

**Evolution rules** (the 100-year contract):

- A capability's `id` and the *meaning* of its parameters never change. If a
  behavior must change, ship a NEW id (`fs.read` → `fs.read2`) and keep the
  old one. The MCP tool list exposes whatever is registered.
- `version` is informational + auditable. The server never silently upgrades a
  call: it always invokes the capability the manifest advertises.
- Providers are self-describing. The tool registry, the audit schema, and the
  policy grammar are all derived from manifests — adding a capability touches
  **no** core code.
- The MCP layer negotiates a protocol version *range*: an ancient client that
  only speaks an old subset still works; a future client gets whatever the
  server supports. Unsupported methods return proper JSON-RPC errors, not
  crashes.

---

## 4. Policy and approval

### Policy grammar

Patterns are `"<capability-id>:<resource-glob>"`. A rule with no resource
matches any call of that capability. Rules are evaluated **last-match-wins**,
so order matters: put broad rules first, narrow overrides last.

```toml
[policy]
default = "deny"          # allow | deny | ask   (fail closed)

[[policy.rules]]
pattern = "fs.read:Z:/Projects/**"
decision = "allow"

[[policy.rules]]
pattern = "pwsh.run:*"    # agent can run anything ...
decision = "deny"         # ... except nothing — explicit deny wins (last)
```

`resource` is a capability-chosen string: the resolved path for `fs.*`, the
command text for `pwsh.run`. It lets policy distinguish "read my code" from
"read my `.ssh` directory" and "run `git status`" from "run `Remove-Item -Recurse`".

### The `Ask` decision

When policy says `ask` (or the default is `ask`), the server:

1. Opens an approval record keyed by a 128-bit random token; returns a
   `pending_approval` envelope to the agent (`{ status, request_id, capability,
   resource, hint }`).
2. Prints the approval URL to **stderr** — the human's terminal shows it:
   `harbor: approval required for pwsh.run — open http://127.0.0.1:48693/approve/<token> (60s)`.
3. Blocks the `tools/call` until the human hits the URL (grant) or the TTL
   expires (deny-with-timeout). The approval server is loopback-only, so only
   the local user can reach it; the token is the bearer secret.
4. Audits the decision, the approver (URL choice is indistinguishable — the
   approval IS the human's action), and the eventual result.

Approval is never a capability the agent can call: it is a human-only channel.
This is what makes `ask` safe — an agent cannot approve its own requests.

---

## 5. Providers

### `pwsh` (PowerShell)

- Executes `pwsh -NoProfile -NonInteractive -EncodedCommand <base64>` (UTF-16LE
  encoded, immune to quoting issues).
- Per-call: `cwd`, timeout (default 60 s), max output bytes (default 1 MiB),
  optional stdin, optional **Constrained Language Mode** (`$ExecutionContext
  SessionState.LanguageMode = 'ConstrainedLanguage'` — blocks most reflection/
  Add-Type abuse; off by default because it breaks many legit scripts).
- On timeout: kill the *tree* (`taskkill /T /F` on Windows, process-group kill
  on Unix). Captures `exit_code`, `stdout`, `stderr`, `duration_ms`, and
  `truncated`/`redacted` flags.
- Environment: inherits the server's env minus nothing; adding `[sandbox]
  env_remove` lets an operator strip secrets from the child's environment.

### `fs` (file system)

- `fs.read`, `fs.write`, `fs.list`, `fs.stat`.
- **Root confinement**: canonicalize (symlink-resolve) and require the result
  to stay under a configured root. `fs.write` is High risk (creates/overwrites
  files); `fs.read` is Medium. Reads are size-capped; binary files are
  detected and returned as `{ binary: true, size }` without content.
- A deny-glob list (`~/.ssh/**`, `*\.key`, ...) is checked *after* canonicalize.

---

## 6. Config, session, audit

### `harbor.toml`

One file, fail-closed: `[policy]`, `[[policy.rules]]`, `[pwsh]`, `[fs]`,
`[sandbox]`, `[approval]`, `[audit]`. Environment variables override (e.g.
`HARBOR_POLICY_DEFAULT`, `HARBOR_AUDIT_PATH`). No config file → the server
starts with default `deny` and an empty allow-list: safe out of the box.

### Sessions

Each MCP connection is a `Session` with its own id, scratch dir, and running
budget (concurrent capability invocations, total output). Sessions cannot see
each other's state; the audit log correlates entries by `session_id` +
`request_id`.

### Audit log

Append-only text file, one JSON object per line:

```json
{"ts":1727300000,"session":"...","request":"...","capability":"pwsh.run",
 "resource":"...","decision":"allow","approver":null,"exit":0,
 "duration_ms":412,"out_sha256":"...","redacted":true}
```

Each entry embeds `prev_hash` = sha256 of the previous entry → a hash chain.
Recomputing the chain over the file detects any retroactive edit. The audit
path is configurable and is the operator's ground truth for "what did the agent
actually do".

---

## 7. Scalability

- **Concurrency**: tokio; invocations are independent async tasks. Budgets and
  the approval server handle many simultaneous requests.
- **Isolation**: per-session scratch + resource accounting; a runaway session
  cannot starve others.
- **Composability**: because capabilities are self-describing, an operator can
  run multiple harbor instances (different policies per role) behind different
  MCP entries, or add a provider crate. Nothing is hard-wired to one host.

---

## 8. Roadmap (designed, not built)

- `net` provider (listen/connect, gated) and `registry`/`wmi` providers.
- Approval channel hardening: signed one-time tokens, optional TOTP.
- Audit HMAC keying + log rotation; optional remote (append-only) audit sink.
- WSL/bash provider (same capability ids, new backend) — the model is
  provider-swappable by design.
- Constrained sandbox execution (AppContainer / OS containers) when the OS
  provides it — same capability surface, stronger isolation.

---

*The design rule in one sentence: **capabilities are the interface, policy is
the gate, audit is the truth, and everything is additive.***