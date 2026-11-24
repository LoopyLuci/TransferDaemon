//! `transferd-cli dns <host>`: resolve a host name the way TransferDaemon does, and say which resolver
//! answered and whether that answer was checked against DNSSEC.
//!
//! This is the same chain the daemon uses to find a relay, so the output is the operational answer to
//! "whose address is my relay using, and can I trust it?" — not a second, different resolver.

use transferd_dns::{lookup, DnsError};

/// `dns <host> [--port N]` — resolve and report.
pub fn run(rest: &[String]) -> Result<serde_json::Value, String> {
    let mut host: Option<&str> = None;
    let mut port: u16 = 0;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--port" => {
                let v = rest.get(i + 1).ok_or("--port needs a number")?;
                port = v
                    .parse()
                    .map_err(|_| format!("--port {v} is not a number"))?;
                i += 2;
            }
            other => {
                host = Some(other);
                i += 1;
            }
        }
    }
    let host = host.ok_or("usage: transferd-cli dns <host> [--port N]")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let r = rt.block_on(lookup(host, port)).map_err(|e| explain(&e))?;
    Ok(serde_json::json!({
        "host": r.host,
        "port": port,
        "resolver": r.resolver,
        "validated": r.validated,
        "cached": r.cached,
        "addresses": r.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
    }))
}

/// Turn an error into something that says what to do about it. The two fail-closed cases are worth
/// spelling out: an address exists, we just will not use it.
fn explain(e: &DnsError) -> String {
    match e {
        DnsError::Bogus { .. } => format!(
            "{e} — a validating resolver says the DNSSEC signatures do not check out, so the address is not used"
        ),
        DnsError::NotValidated { .. } => format!(
            "{e} — use a resolver that validates (TRANSFERD_DNS=ironroot,quad9), or clear \
             TRANSFERD_DNS_REQUIRE_VALIDATED to accept the answer anyway"
        ),
        DnsError::NoValidatedResolver(_) => e.to_string(),
        other => other.to_string(),
    }
}
