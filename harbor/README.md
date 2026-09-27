# Harbor — a capability-gated MCP server for safe computer control

Build + test:

```sh
cd harbor
cargo build --release
cargo test                       # 37 tests
cargo clippy --workspace --all-targets -- -D warnings
```

Run as an MCP **local** server for OpenCode. Copy `harbor.toml.example` to a
real config first — it is fail-closed (default `deny`), so edit it to grant
exactly the capabilities you trust, e.g.:

```sh
cp harbor.toml.example harbor.toml   # then edit the rules
```

Then add a local MCP server to opencode's config
(`~/.config/opencode/opencode.jsonc`):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "harbor": {
      "type": "local",
      "command": ["Z:/Projects/TransferDaemon/harbor/target/release/harbor.exe", "--config", "Z:/Projects/TransferDaemon/harbor/harbor.toml"],
      "enabled": true
    }
  }
}
```

Restart opencode. The agent then sees five tools: `fs_read`, `fs_write`,
`fs_list`, `fs_stat`, `pwsh_run`. Every call is policy-gated; `ask` decisions
print a loopback approval URL on harbor's stderr for you to click.

## What you get

- **Capability-gated**: nothing runs without an explicit rule (default deny).
- **Human approval**: `ask` decisions pause the call until you hit a loopback
  URL; the agent can never approve its own requests.
- **Budgeted**: every invocation has a timeout and an output byte cap, enforced
  by the server; runaway pwsh processes are tree-killed.
- **Redacted**: secret patterns + `HARBOR_SECRETS` are masked before output
  reaches the agent.
- **Audited**: every decision and result lands in a tamper-evident, hash-chained
  log — the ground truth for "what did the agent actually do".

See `DESIGN.md` for the architecture, security model, and the 100-year
evolution rules.