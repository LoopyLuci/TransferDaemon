//! Three real replicas on this machine (TCP, SQLite files): writes through any node, the leader killed, a write
//! after that, the dead node back from its files and caught up, the same answers from every node.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;
use transferd_replica::node::{request, run, Config, Reply, Request};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(0)
}

async fn status(addr: SocketAddr) -> Option<serde_json::Value> {
    request(addr, Request::Status).await.ok().and_then(|r| r.status())
}

async fn leader(peers: &BTreeMap<u64, SocketAddr>, skip: Option<u64>) -> Option<u64> {
    for _ in 0..200 {
        for (id, a) in peers {
            if Some(*id) == skip {
                continue;
            }
            if let Some(s) = status(*a).await {
                if s["role"] == "Leader" {
                    return Some(*id);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

async fn exec(addr: SocketAddr, sql: &str) -> Reply {
    for _ in 0..50 {
        match request(addr, Request::Exec { sql: sql.into() }).await {
            Ok(Reply::Error(e)) if e.contains("leader") => tokio::time::sleep(Duration::from_millis(100)).await,
            Ok(r) => return r,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    Reply::Error("gave up".into())
}

async fn count(addr: SocketAddr) -> Option<i64> {
    let rows = request(addr, Request::Query { sql: "SELECT COUNT(*) FROM notes".into() }).await.ok()?.rows()?;
    rows.first().and_then(|r| r.first()).and_then(|v| v.as_i64())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_replicas_survive_losing_the_leader() {
    let root = tempfile::tempdir().expect("tmp");
    let peers: BTreeMap<u64, SocketAddr> = (1..=3).map(|i| (i, SocketAddr::from(([127, 0, 0, 1], free_port())))).collect();
    let start = |id: u64| {
        let cfg = Config { id, peers: peers.clone(), cluster: "test".into(), dir: root.path().join(format!("n{id}")) };
        tokio::spawn(async move { run(cfg).await })
    };
    let mut tasks: BTreeMap<u64, tokio::task::JoinHandle<_>> = (1..=3).map(|i| (i, start(i))).collect();
    let l = match leader(&peers, None).await {
        Some(l) => l,
        None => {
            for (id, a) in &peers {
                eprintln!("node {id} at {a}: {:?}", request(*a, Request::Status).await.map_err(|e| e.to_string()));
            }
            for (id, t) in &tasks {
                eprintln!("node {id} task finished: {}", t.is_finished());
            }
            for (id, t) in tasks {
                if t.is_finished() {
                    eprintln!("node {id} returned {:?}", t.await);
                }
            }
            panic!("no leader was elected");
        }
    };
    let follower = *peers.keys().find(|i| **i != l).expect("a follower");
    // a write sent to a follower is forwarded to the leader
    assert!(matches!(exec(peers[&follower], "CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT)").await, Reply::Done { .. }));
    for i in 0..20 {
        let r = exec(peers[&((i % 3) + 1)], &format!("INSERT INTO notes (text) VALUES ('note {i}')")).await;
        assert!(matches!(r, Reply::Done { changed: 1, .. }), "{r:?}");
    }
    // a statement that fails fails everywhere the same way, and the log goes on
    assert!(matches!(exec(peers[&l], "INSERT INTO nowhere VALUES (1)").await, Reply::Error(_)));
    // the leader dies
    tasks.remove(&l).expect("task").abort();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let l2 = leader(&peers, Some(l)).await.expect("a new leader among the two left");
    assert_ne!(l2, l);
    for i in 20..30 {
        assert!(matches!(exec(peers[&l2], &format!("INSERT INTO notes (text) VALUES ('note {i}')")).await, Reply::Done { .. }));
    }
    assert_eq!(count(peers[&l2]).await, Some(30), "every acknowledged write, after losing the old leader");
    // the dead node comes back from its files and catches up
    tasks.insert(l, start(l));
    let mut caught_up = false;
    for _ in 0..100 {
        let theirs = status(peers[&l2]).await.and_then(|v| v["applied"].as_u64());
        let mine = status(peers[&l]).await.and_then(|v| v["applied"].as_u64());
        if mine.is_some() && mine >= theirs {
            caught_up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(caught_up, "the restarted node applied everything");
    // linearizable reads give the same answer through every node (followers forward reads to the leader)
    for (_, a) in &peers {
        assert_eq!(count(*a).await, Some(30));
    }
    // and its own SQLite file holds all of it
    let db = rusqlite::Connection::open(root.path().join(format!("n{l}")).join("state.sqlite")).expect("db");
    let n: i64 = db.query_row("SELECT COUNT(*) FROM notes", [], |r| r.get(0)).expect("count");
    assert_eq!(n, 30);
    for (_, t) in tasks {
        t.abort();
    }
}
