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
                    // The relay carries the traffic, so its address comes from a resolver that checks
                    // DNSSEC (a local Ironroot first, then Quad9 over DoT), not from the OS alone.
                    Some(r) => {
                        let (host, port) = r.rsplit_once(':').ok_or_else(|| format!("relay {r}: host:port"))?;
                        let port: u16 = port.parse().map_err(|_| format!("relay {r}: bad port"))?;
                        // `[::1]:port` is how an IPv6 literal is written in a host:port pair.
                        let host = host.trim_start_matches('[').trim_end_matches(']');
                        let first = transferd_dns::resolve(host, port).await.map_err(|e| format!("relay {r}: {e}"))?
                            .into_iter().next().ok_or_else(|| format!("relay {r}: no address"))?;
                        Some(first)
                    }
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
