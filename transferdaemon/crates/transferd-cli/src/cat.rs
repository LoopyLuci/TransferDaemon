//! `transferd-cli cat`: netcat over TransferD (transferd_cat), between any two machines, no accounts.
//!
//!   transferd-cli cat listen [--relay host:port] [--wait seconds]
//!       prints a one-time tdcat: address (to stderr), then pipes stdin to the other side and the other side to stdout
//!   transferd-cli cat <tdcat:address> [--wait seconds]
//!       dials it and does the same
//!
//! The relay defaults to TRANSFERD_CAT_RELAY when set; without one, only direct paths are tried.

use std::time::Duration;
use transferd_cat::{dial, CatAddress, Listener};

pub fn run(rest: &[String]) -> Result<serde_json::Value, String> {
    let flag = |name: &str| rest.iter().position(|a| a == name).and_then(|i| rest.get(i + 1)).cloned();
    let wait = Duration::from_secs(flag("--wait").and_then(|w| w.parse().ok()).unwrap_or(600));
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let session = match rest.first().map(String::as_str) {
            Some("listen") => {
                let relay = flag("--relay").or_else(|| std::env::var("TRANSFERD_CAT_RELAY").ok());
                let relay = match relay {
                    Some(r) => Some(tokio::net::lookup_host(&r).await.map_err(|e| format!("relay {r}: {e}"))?
                        .next().ok_or_else(|| format!("relay {r}: no address"))?),
                    None => None,
                };
                let l = Listener::bind(relay).await.map_err(|e| e.to_string())?;
                eprintln!("{}", l.address.to_text());
                eprintln!("(give that address to the other side: `transferd-cli cat <address>`; waiting...)");
                l.accept(wait).await.map_err(|e| e.to_string())?
            }
            Some(a) if a.starts_with("tdcat:") => {
                let addr = CatAddress::parse(a).map_err(|e| e.to_string())?;
                dial(&addr, wait).await.map_err(|e| e.to_string())?
            }
            _ => return Err("cat listen [--relay host:port] | cat <tdcat:address>".to_string()),
        };
        eprintln!("(connected {})", if session.direct { "directly" } else { "through the relay" });
        let (sent, received) = session.pipe(tokio::io::stdin(), tokio::io::stdout()).await.map_err(|e| e.to_string())?;
        Ok(serde_json::json!({"sent": sent, "received": received}))
    })
}
