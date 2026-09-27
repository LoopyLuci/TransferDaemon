//! Harbor entry point.
//!
//! Run as an MCP *local* server: OpenCode config
//!   "harbor": { "type": "local", "command": ["<path>/harbor"] }
//! Everything capability-gated by harbor.toml; stdout is reserved for MCP.

mod approval;
mod config;
mod mcp;

use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    init_tracing();
    let cfg_path = parse_args();
    let cfg = config::load(cfg_path.as_ref());

    if !cfg.policy.rules.is_empty() {
        tracing::info!(rules = cfg.policy.rules.len(), "policy loaded");
    } else {
        tracing::warn!("policy has NO rules — every capability is denied by default");
    }

    let runtime = Arc::new(config::build_runtime(&cfg));

    let approval = if cfg.approval.enabled {
        match approval::ApprovalServer::start(cfg.approval.port, cfg.approval.ttl_secs).await {
            Ok(s) => {
                tracing::info!(
                    port = s.port(),
                    ttl = cfg.approval.ttl_secs,
                    "approval server on 127.0.0.1"
                );
                Some(Arc::new(s))
            }
            Err(e) => {
                // Fail closed: without an approval channel, `ask` cannot be
                // satisfied — log loudly and continue (deny still works).
                tracing::error!(
                    "approval server failed to start: {e} — 'ask' decisions will be denied"
                );
                None
            }
        }
    } else {
        None
    };

    mcp::run(runtime, approval).await
}

fn init_tracing() {
    use tracing_subscriber::prelude::*;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "harbor=info".into());
    // JSON lines on stderr; stdout stays protocol-pure.
    let fmt = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(std::io::stderr);
    tracing_subscriber::registry().with(filter).with(fmt).init();
}

fn parse_args() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    let mut config: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config = args.next().map(PathBuf::from),
            "--version" | "-V" => {
                println!("harbor {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                eprintln!("harbor: unknown argument '{other}'");
                print_help();
                std::process::exit(2);
            }
        }
    }
    config
}

fn print_help() {
    println!(
        "harbor — capability-gated MCP server for safe computer control\n\n\
         USAGE:\n  harbor [--config <path>]\n\n\
         Run as an MCP 'local' server (stdio). Every capability is policy-gated\n\
         (harbor.toml, fail-closed), budgeted, redacted, and audit-logged.\n\n\
         OPTIONS:\n  --config <path>   path to harbor.toml (default: env/config discovery)\n  -V, --version     print version\n  -h, --help        show this help"
    );
}
