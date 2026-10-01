//! A device's replica: Raft's durable state on disk, the TCP transport between devices, SQLite as the state machine,
//! and the client API (`exec` writes go through the Raft log, `query` reads are linearizable via ReadIndex).
//!
//! Files in the data folder: `hard.json` (term, vote), `log.bin` (the Raft log: length-prefixed bincode entries,
//! rewritten from the first changed index), `state.sqlite` (the applied state and `_replica_applied`, the last
//! applied index, updated in the same transaction as each statement).
//!
//! Wire: every TCP connection carries length-prefixed bincode frames; a peer's first frame says who it is
//! (`Hello { id, cluster }`), then Raft messages flow. Clients use the same port: `Client { request }` gets one
//! `Reply` and the connection closes. A follower forwards a client's request to the leader it knows.

use crate::raft::{Entry, HardState, Index, Msg, NodeId, Raft, Role};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};

pub const TICK: Duration = Duration::from_millis(50);

#[derive(Debug, thiserror::Error)]
pub enum ReplicaError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    /// A write: SQL statements applied in one transaction on every replica, in log order.
    Exec { sql: String },
    /// A linearizable read on the leader: rows as JSON.
    Query { sql: String },
    Status,
}

/// JSON travels as text (bincode can't carry `serde_json::Value`); `status()` / `rows()` parse it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Reply {
    Done { index: Index, changed: u64 },
    Rows { columns: Vec<String>, rows_json: String },
    Status(String),
    Error(String),
}

impl Reply {
    pub fn status(&self) -> Option<serde_json::Value> {
        match self {
            Reply::Status(j) => serde_json::from_str(j).ok(),
            _ => None,
        }
    }

    pub fn rows(&self) -> Option<Vec<Vec<serde_json::Value>>> {
        match self {
            Reply::Rows { rows_json, .. } => serde_json::from_str(rows_json).ok(),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Frame {
    Hello { id: NodeId, cluster: String },
    Raft(Msg),
    Client(Request),
    Reply(Reply),
}

// ---- durable state ------------------------------------------------------------------------------------------------- //

struct Disk {
    dir: PathBuf,
}

impl Disk {
    fn load(&self) -> Result<(HardState, Vec<Entry>), ReplicaError> {
        let hard = std::fs::read(self.dir.join("hard.json")).ok()
            .and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let mut log = Vec::new();
        if let Ok(mut f) = std::fs::File::open(self.dir.join("log.bin")) {
            let mut len = [0u8; 4];
            while f.read_exact(&mut len).is_ok() {
                let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
                if f.read_exact(&mut buf).is_err() {
                    break; // a torn last write: everything before it stands
                }
                match bincode::deserialize::<Entry>(&buf) {
                    Ok(e) => log.push(e),
                    Err(_) => break,
                }
            }
        }
        Ok((hard, log))
    }

    fn save_hard(&self, h: &HardState) -> Result<(), ReplicaError> {
        let tmp = self.dir.join("hard.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(h).map_err(|e| ReplicaError::Other(e.to_string()))?)?;
        sync_file(&tmp)?;
        std::fs::rename(tmp, self.dir.join("hard.json"))?;
        Ok(())
    }

    /// Rewrite the log from `from` (1-based) with `entries` (the log's tail from there).
    fn save_log_from(&self, from: Index, entries: &[Entry]) -> Result<(), ReplicaError> {
        let path = self.dir.join("log.bin");
        let mut keep: Vec<u8> = Vec::new();
        if from > 1 {
            if let Ok(mut f) = std::fs::File::open(&path) {
                let mut n = 0;
                let mut len = [0u8; 4];
                while n + 1 < from && f.read_exact(&mut len).is_ok() {
                    let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
                    f.read_exact(&mut buf)?;
                    keep.extend_from_slice(&len);
                    keep.extend_from_slice(&buf);
                    n += 1;
                }
            }
        }
        for e in entries {
            let b = bincode::serialize(e).map_err(|e| ReplicaError::Other(e.to_string()))?;
            keep.extend_from_slice(&(b.len() as u32).to_le_bytes());
            keep.extend_from_slice(&b);
        }
        let tmp = self.dir.join("log.bin.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&keep)?;
            f.sync_all()?;
        }
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}

fn sync_file(p: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new().write(true).open(p)?.sync_all()
}

// ---- the state machine (SQLite) ------------------------------------------------------------------------------------- //

fn open_db(dir: &Path) -> Result<Connection, ReplicaError> {
    let db = Connection::open(dir.join("state.sqlite"))?;
    db.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS _replica_applied (one INTEGER PRIMARY KEY CHECK (one = 1), idx INTEGER NOT NULL);
                      INSERT OR IGNORE INTO _replica_applied VALUES (1, 0);")?;
    Ok(db)
}

fn applied_index(db: &Connection) -> Result<Index, ReplicaError> {
    Ok(db.query_row("SELECT idx FROM _replica_applied WHERE one = 1", [], |r| r.get::<_, i64>(0))? as Index)
}

/// Apply one committed entry: its statements and the applied index in one transaction (exactly once, even across
/// crashes). A statement that fails rolls back its own entry only; the error is the result for whoever proposed it.
fn apply(db: &mut Connection, index: Index, e: &Entry) -> Result<u64, String> {
    let tx = db.transaction().map_err(|e| e.to_string())?;
    let mut changed = 0u64;
    let mut err = None;
    if !e.data.is_empty() {
        match bincode::deserialize::<Request>(&e.data) {
            Ok(Request::Exec { sql }) => match tx.execute_batch(&sql) {
                Ok(()) => changed = tx.changes(),
                Err(x) => err = Some(x.to_string()),
            },
            _ => err = Some("not a write".into()),
        }
    }
    if err.is_some() {
        drop(tx);
        // the failed entry still counts as applied (every replica fails it the same way)
        let tx = db.transaction().map_err(|e| e.to_string())?;
        tx.execute("UPDATE _replica_applied SET idx = ?1 WHERE one = 1", [index as i64]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        return Err(err.unwrap_or_default());
    }
    tx.execute("UPDATE _replica_applied SET idx = ?1 WHERE one = 1", [index as i64]).map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(changed)
}

fn query(db: &Connection, sql: &str) -> Result<Reply, String> {
    let mut st = db.prepare(sql).map_err(|e| e.to_string())?;
    if !st.readonly() {
        return Err("query takes a read-only statement (use exec to change data)".into());
    }
    let columns: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
    let n = columns.len();
    let rows = st.query_map([], |r| {
        (0..n).map(|i| {
            Ok(match r.get_ref(i)? {
                rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                rusqlite::types::ValueRef::Integer(v) => serde_json::json!(v),
                rusqlite::types::ValueRef::Real(v) => serde_json::json!(v),
                rusqlite::types::ValueRef::Text(t) => serde_json::json!(String::from_utf8_lossy(t)),
                rusqlite::types::ValueRef::Blob(b) => serde_json::json!(b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
            })
        }).collect::<Result<Vec<_>, rusqlite::Error>>()
    }).map_err(|e| e.to_string())?;
    let rows = rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
    Ok(Reply::Rows { columns, rows_json: serde_json::Value::from(rows).to_string() })
}

// ---- framing ------------------------------------------------------------------------------------------------------- //

async fn write_frame(s: &mut (impl AsyncWriteExt + Unpin), f: &Frame) -> std::io::Result<()> {
    let b = bincode::serialize(f).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    s.write_all(&(b.len() as u32).to_le_bytes()).await?;
    s.write_all(&b).await
}

async fn read_frame(s: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<Frame> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let n = u32::from_le_bytes(len) as usize;
    if n > 64 << 20 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await?;
    bincode::deserialize(&b).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

// ---- the node ------------------------------------------------------------------------------------------------------ //

pub struct Config {
    pub id: NodeId,
    pub peers: BTreeMap<NodeId, SocketAddr>,
    pub cluster: String,
    pub dir: PathBuf,
}

enum Event {
    Peer(NodeId, Msg),
    Client(Request, oneshot::Sender<Reply>),
}

struct Waiting {
    writes: HashMap<Index, oneshot::Sender<Reply>>,
    reads: HashMap<u64, (String, oneshot::Sender<Reply>)>,
    ready_reads: Vec<(Index, String, oneshot::Sender<Reply>)>,
}

/// Aborts the tasks a replica started when it ends or is dropped (an aborted replica leaves nothing behind: not its
/// port, not its connections).
struct Tasks(Vec<tokio::task::JoinHandle<()>>);

impl Drop for Tasks {
    fn drop(&mut self) {
        for t in &self.0 {
            t.abort();
        }
    }
}

/// Run a replica until the process ends: listen on this node's address, connect to peers, drive Raft.
pub async fn run(cfg: Config) -> Result<(), ReplicaError> {
    let mut tasks = Tasks(Vec::new());
    std::fs::create_dir_all(&cfg.dir)?;
    let disk = Disk { dir: cfg.dir.clone() };
    let (hard, log) = disk.load()?;
    let mut db = open_db(&cfg.dir)?;
    let applied = applied_index(&db)?;
    let mut raft = Raft::new(cfg.id, cfg.peers.keys().copied().collect(), hard, log, rand::random());
    raft.set_applied(applied);
    let my_addr = *cfg.peers.get(&cfg.id).ok_or_else(|| ReplicaError::Other("this node is not in its own peer list".into()))?;
    let listener = TcpListener::bind(SocketAddr::new([0, 0, 0, 0].into(), my_addr.port())).await?;
    let (tx, mut rx) = mpsc::channel::<Event>(4096);
    let senders: Arc<Mutex<HashMap<NodeId, mpsc::Sender<Msg>>>> = Arc::new(Mutex::new(HashMap::new()));
    let leader_hint: Arc<Mutex<Option<NodeId>>> = Arc::new(Mutex::new(None));

    // outgoing: one connection per peer, re-dialled when it drops
    for (pid, addr) in cfg.peers.iter().filter(|(p, _)| **p != cfg.id) {
        let (ptx, mut prx) = mpsc::channel::<Msg>(4096);
        senders.lock().await.insert(*pid, ptx);
        let (addr, me, cluster) = (*addr, cfg.id, cfg.cluster.clone());
        tasks.0.push(tokio::spawn(async move {
            loop {
                let Ok(mut s) = TcpStream::connect(addr).await else {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    while prx.try_recv().is_ok() {} // what was meant for a peer that's down is stale
                    continue;
                };
                let _ = s.set_nodelay(true);
                if write_frame(&mut s, &Frame::Hello { id: me, cluster: cluster.clone() }).await.is_err() {
                    continue;
                }
                while let Some(m) = prx.recv().await {
                    if write_frame(&mut s, &Frame::Raft(m)).await.is_err() {
                        break;
                    }
                }
            }
        }));
    }

    // incoming: peers' Raft messages and clients' requests
    {
        let (tx, cluster, peers, leader_hint, me) = (tx.clone(), cfg.cluster.clone(), cfg.peers.clone(), leader_hint.clone(), cfg.id);
        tasks.0.push(tokio::spawn(async move {
            let mut conns = tokio::task::JoinSet::new();   // dropped with the listener task: its connections end too
            while let Ok((mut s, _)) = listener.accept().await {
                let (tx, cluster, peers, leader_hint) = (tx.clone(), cluster.clone(), peers.clone(), leader_hint.clone());
                conns.spawn(async move {
                    let _ = s.set_nodelay(true);
                    match read_frame(&mut s).await {
                        Ok(Frame::Hello { id, cluster: c }) if c == cluster && peers.contains_key(&id) => {
                            while let Ok(Frame::Raft(m)) = read_frame(&mut s).await {
                                if tx.send(Event::Peer(id, m)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(Frame::Client(req)) => {
                            let (otx, orx) = oneshot::channel();
                            let reply = if tx.send(Event::Client(req.clone(), otx)).await.is_ok() {
                                orx.await.unwrap_or(Reply::Error("the replica stopped".into()))
                            } else {
                                Reply::Error("the replica stopped".into())
                            };
                            // a follower forwards writes and reads to the leader it knows
                            let reply = match (&reply, &req) {
                                (Reply::Error(e), Request::Exec { .. } | Request::Query { .. }) if e.starts_with("not the leader") => {
                                    let hint = *leader_hint.lock().await;
                                    match hint.filter(|l| *l != me).and_then(|l| peers.get(&l).copied()) {
                                        Some(addr) => request(addr, req).await.unwrap_or(reply),
                                        None => reply,
                                    }
                                }
                                _ => reply,
                            };
                            let _ = write_frame(&mut s, &Frame::Reply(reply)).await;
                        }
                        _ => {}
                    }
                });
            }
        }));
    }

    let mut waiting = Waiting { writes: HashMap::new(), reads: HashMap::new(), ready_reads: Vec::new() };
    let mut ticker = tokio::time::interval(TICK);
    let mut read_id: u64 = 0;
    loop {
        tokio::select! {
            _ = ticker.tick() => raft.tick(),
            ev = rx.recv() => match ev {
                None => return Ok(()),
                Some(Event::Peer(from, m)) => raft.step(from, m),
                Some(Event::Client(req, reply)) => match req {
                    Request::Exec { .. } => {
                        let data = bincode::serialize(&req).map_err(|e| ReplicaError::Other(e.to_string()))?;
                        match raft.propose(data) {
                            Ok(i) => { waiting.writes.insert(i, reply); }
                            Err(e) => { let _ = reply.send(Reply::Error(e.to_string())); }
                        }
                    }
                    Request::Query { sql } => {
                        read_id += 1;
                        match raft.read_index(read_id) {
                            Ok(()) => { waiting.reads.insert(read_id, (sql, reply)); }
                            Err(e) => { let _ = reply.send(Reply::Error(e.to_string())); }
                        }
                    }
                    Request::Status => {
                        let _ = reply.send(Reply::Status(serde_json::json!({
                            "id": raft.id, "role": format!("{:?}", raft.role), "term": raft.hard.term, "leader": raft.leader,
                            "commit": raft.commit, "last_index": raft.last_index(), "applied": applied_index(&db).unwrap_or(0),
                        }).to_string()));
                    }
                },
            },
        }
        // persist before anything leaves this node
        if let Some(h) = raft.hard_state_changed() {
            disk.save_hard(&h)?;
        }
        if let Some(from) = raft.log_changed_from() {
            disk.save_log_from(from, raft.entries_from(from))?;
        }
        *leader_hint.lock().await = raft.leader;
        let out = raft.take_outbox();
        {
            let s = senders.lock().await;
            for (to, m) in out {
                if let Some(ptx) = s.get(&to) {
                    let _ = ptx.try_send(m);
                }
            }
        }
        for (i, e) in raft.take_committed() {
            let r = apply(&mut db, i, &e);
            if let Some(w) = waiting.writes.remove(&i) {
                let _ = w.send(match r {
                    Ok(changed) => Reply::Done { index: i, changed },
                    Err(err) => Reply::Error(err),
                });
            }
        }
        for (id, at) in raft.take_reads() {
            if let Some((sql, reply)) = waiting.reads.remove(&id) {
                waiting.ready_reads.push((at, sql, reply));
            }
        }
        let now_applied = applied_index(&db).unwrap_or(0);
        let (serve, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut waiting.ready_reads).into_iter().partition(|(at, _, _)| *at <= now_applied);
        waiting.ready_reads = keep;
        for (_, sql, reply) in serve {
            let _ = reply.send(query(&db, &sql).unwrap_or_else(Reply::Error));
        }
        if raft.role != Role::Leader {
            // proposals that can no longer commit through this node: tell their clients
            for (_, w) in waiting.writes.drain() {
                let _ = w.send(Reply::Error("not the leader any more; retry".into()));
            }
            for (_, (_, r)) in waiting.reads.drain() {
                let _ = r.send(Reply::Error("not the leader any more; retry".into()));
            }
        }
    }
}

/// Send one client request to a replica (any: followers forward to the leader).
pub async fn request(addr: SocketAddr, req: Request) -> Result<Reply, ReplicaError> {
    let mut s = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await
        .map_err(|_| ReplicaError::Other(format!("{addr} did not answer")))??;
    write_frame(&mut s, &Frame::Client(req)).await?;
    match tokio::time::timeout(Duration::from_secs(30), read_frame(&mut s)).await
        .map_err(|_| ReplicaError::Other("no reply within 30 s".into()))?? {
        Frame::Reply(r) => Ok(r),
        _ => Err(ReplicaError::Other("unexpected frame".into())),
    }
}

/// `1=host:port,2=host:port,...`
pub fn parse_peers(s: &str) -> Result<BTreeMap<NodeId, SocketAddr>, ReplicaError> {
    s.split(',').filter(|x| !x.trim().is_empty()).map(|kv| {
        let (k, v) = kv.split_once('=').ok_or_else(|| ReplicaError::Other(format!("{kv}: expected id=host:port")))?;
        let id: NodeId = k.trim().parse().map_err(|_| ReplicaError::Other(format!("{k}: not a node id")))?;
        let addr: SocketAddr = v.trim().parse().map_err(|_| ReplicaError::Other(format!("{v}: not host:port")))?;
        Ok((id, addr))
    }).collect()
}
