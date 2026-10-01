//! `transferd-cli replica ...`: state replicated across your devices with Raft, applied to SQLite (transferd_replica).
//!
//!   replica start --id N --peers 1=host:port,2=host:port,3=host:port [--cluster name] [--data dir]
//!       runs this device's replica (in the foreground; a service manager or `start /b` keeps it running)
//!   replica exec  <host:port> <SQL>        a write, replicated to every device (any replica: followers forward it)
//!   replica query <host:port> <SQL>        a linearizable read (a SELECT)
//!   replica status <host:port>             role, term, leader, commit and applied index
//!
//! Data: --data, else <TRANSFERD_DATA_DIR or the per-user data folder>/replica/<cluster>-<id>.

use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use transferd_replica::node::{parse_peers, request, run as run_node, Config, Reply, Request};

fn flag(rest: &[String], name: &str) -> Option<String> {
    rest.iter().position(|a| a == name).and_then(|i| rest.get(i + 1)).cloned()
}

fn data_dir(cluster: &str, id: u64) -> PathBuf {
    let base = std::env::var_os("TRANSFERD_DATA_DIR").map(PathBuf::from).unwrap_or_else(|| {
        std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("XDG_DATA_HOME")).map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share"))
            .join("transferdaemon")
    });
    base.join("replica").join(format!("{cluster}-{id}"))
}

fn reply_json(r: Reply) -> Result<Value, String> {
    let rows = r.rows();
    match r {
        Reply::Done { index, changed } => Ok(json!({"index": index, "changed": changed})),
        Reply::Rows { columns, .. } => Ok(json!({"columns": columns, "rows": rows.unwrap_or_default()})),
        Reply::Status(s) => serde_json::from_str(&s).map_err(|e| e.to_string()),
        Reply::Error(e) => Err(e),
    }
}

pub fn run(rest: &[String]) -> Result<Value, String> {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    let addr_at = |i: usize| -> Result<SocketAddr, String> {
        rest.get(i).ok_or("which replica? host:port")?.parse().map_err(|_| "a replica is host:port".to_string())
    };
    match rest.first().map(String::as_str) {
        Some("start") => {
            let id: u64 = flag(rest, "--id").ok_or("--id N")?.parse().map_err(|_| "--id is a number")?;
            let peers = parse_peers(&flag(rest, "--peers").ok_or("--peers 1=host:port,2=host:port,...")?).map_err(|e| e.to_string())?;
            let cluster = flag(rest, "--cluster").unwrap_or_else(|| "default".into());
            let dir = flag(rest, "--data").map(PathBuf::from).unwrap_or_else(|| data_dir(&cluster, id));
            eprintln!("replica {id} of {} in cluster {cluster}, data in {}", peers.len(), dir.display());
            rt.block_on(run_node(Config { id, peers, cluster, dir })).map_err(|e| e.to_string())?;
            Ok(json!({"stopped": id}))
        }
        Some(op @ ("exec" | "query")) => {
            let at = addr_at(1)?;
            let sql = rest.get(2..).map(|s| s.join(" ")).filter(|s| !s.is_empty()).ok_or("and the SQL")?;
            let req = if op == "exec" { Request::Exec { sql } } else { Request::Query { sql } };
            reply_json(rt.block_on(request(at, req)).map_err(|e| e.to_string())?)
        }
        Some("status") => reply_json(rt.block_on(request(addr_at(1)?, Request::Status)).map_err(|e| e.to_string())?),
        _ => Err("replica start | exec | query | status (see `transferd-cli help`)".into()),
    }
}
