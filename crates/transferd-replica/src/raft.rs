//! Raft (Ongaro & Ousterhout, "In Search of an Understandable Consensus Algorithm"), as a pure state machine.
//!
//! [`Raft`] does no I/O: feed it [`Raft::tick`] (time), [`Raft::step`] (a message from a peer), [`Raft::propose`]
//! (a client's command) and [`Raft::read_index`] (a linearizable read), and collect what it wants done with
//! [`Raft::take_outbox`] (messages to send), [`Raft::take_committed`] (entries to apply, in order) and
//! [`Raft::take_reads`] (reads that may now be served). Durable state (term, vote, log) must be persisted before the
//! messages produced alongside it are sent: [`Raft::hard_state_changed`] and [`Raft::log_changed_from`] say when.
//!
//! Implemented: leader election with randomized timeouts and the up-to-date-log vote rule; log replication with
//! consistency checks and fast backtracking (the follower's conflict hint); commit only of entries from the current
//! term counted on a majority (§5.4.2); a no-op entry on election so a new leader commits promptly; ReadIndex reads
//! (the leader confirms it still leads with a heartbeat quorum before serving a read at its commit index).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub type NodeId = u64;
pub type Index = u64;
pub type Term = u64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub term: Term,
    /// Empty for the leader's no-op entry.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Msg {
    Vote { term: Term, last_index: Index, last_term: Term },
    VoteResp { term: Term, granted: bool },
    Append { term: Term, prev_index: Index, prev_term: Term, entries: Vec<Entry>, commit: Index, read_seq: u64 },
    AppendResp { term: Term, success: bool, match_index: Index, conflict_hint: Index, read_seq: u64 },
}

impl Msg {
    pub fn term(&self) -> Term {
        match self {
            Msg::Vote { term, .. } | Msg::VoteResp { term, .. } | Msg::Append { term, .. } | Msg::AppendResp { term, .. } => *term,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardState {
    pub term: Term,
    pub voted_for: Option<NodeId>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RaftError {
    #[error("not the leader (the leader is {0:?})")]
    NotLeader(Option<NodeId>),
}

pub struct Raft {
    pub id: NodeId,
    peers: Vec<NodeId>,
    pub hard: HardState,
    /// log[0] is a sentinel (index 0, term 0); entries start at index 1
    log: Vec<Entry>,
    pub commit: Index,
    applied: Index,
    pub role: Role,
    pub leader: Option<NodeId>,
    votes: BTreeSet<NodeId>,
    next: BTreeMap<NodeId, Index>,
    matched: BTreeMap<NodeId, Index>,
    election_elapsed: u32,
    election_timeout: u32,
    heartbeat_elapsed: u32,
    pub election_ticks: u32,
    pub heartbeat_ticks: u32,
    /// Entries per append message (catch-up of a lagging follower takes several).
    pub max_batch: usize,
    outbox: Vec<(NodeId, Msg)>,
    // ReadIndex: pending reads (id, index) waiting for a heartbeat round newer than read_seq_at
    read_seq: u64,
    read_acks: BTreeMap<u64, BTreeSet<NodeId>>,
    pending_reads: Vec<(u64, u64, Index)>,
    ready_reads: Vec<(u64, Index)>,
    hard_dirty: bool,
    log_dirty_from: Option<Index>,
    rng: rand::rngs::StdRng,
}

impl Raft {
    /// A node with its persisted state (a fresh node: `HardState::default()` and an empty log).
    pub fn new(id: NodeId, peers: Vec<NodeId>, hard: HardState, log: Vec<Entry>, seed: u64) -> Self {
        use rand::SeedableRng;
        let mut full = vec![Entry { term: 0, data: Vec::new() }];
        full.extend(log);
        let mut r = Self {
            id,
            peers: peers.into_iter().filter(|p| *p != id).collect(),
            hard,
            log: full,
            commit: 0,
            applied: 0,
            role: Role::Follower,
            leader: None,
            votes: BTreeSet::new(),
            next: BTreeMap::new(),
            matched: BTreeMap::new(),
            election_elapsed: 0,
            election_timeout: 10,
            heartbeat_elapsed: 0,
            election_ticks: 10,
            heartbeat_ticks: 2,
            max_batch: 256,
            outbox: Vec::new(),
            read_seq: 0,
            read_acks: BTreeMap::new(),
            pending_reads: Vec::new(),
            ready_reads: Vec::new(),
            hard_dirty: false,
            log_dirty_from: None,
            rng: rand::rngs::StdRng::seed_from_u64(seed ^ id.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
        };
        r.reset_election_timeout();
        r
    }

    fn quorum(&self) -> usize {
        let members = self.peers.len() + 1;
        members / 2 + 1 // a majority of the members
    }

    pub fn last_index(&self) -> Index {
        (self.log.len() - 1) as Index
    }

    fn term_at(&self, i: Index) -> Option<Term> {
        self.log.get(i as usize).map(|e| e.term)
    }

    pub fn entries_from(&self, i: Index) -> &[Entry] {
        let i = (i as usize).clamp(1, self.log.len());
        &self.log[i..]
    }

    fn reset_election_timeout(&mut self) {
        use rand::Rng;
        self.election_elapsed = 0;
        self.election_timeout = self.election_ticks + self.rng.gen_range(0..self.election_ticks);
    }

    fn become_follower(&mut self, term: Term, leader: Option<NodeId>) {
        if term > self.hard.term {
            self.hard = HardState { term, voted_for: None };
            self.hard_dirty = true;
        }
        self.role = Role::Follower;
        self.leader = leader;
        self.reset_election_timeout();
        self.pending_reads.clear();
        self.read_acks.clear();
    }

    fn campaign(&mut self) {
        self.role = Role::Candidate;
        self.hard = HardState { term: self.hard.term + 1, voted_for: Some(self.id) };
        self.hard_dirty = true;
        self.leader = None;
        self.votes = [self.id].into_iter().collect();
        self.reset_election_timeout();
        if self.votes.len() >= self.quorum() {
            self.become_leader();
            return;
        }
        let (li, lt) = (self.last_index(), self.term_at(self.last_index()).unwrap_or(0));
        for p in self.peers.clone() {
            self.outbox.push((p, Msg::Vote { term: self.hard.term, last_index: li, last_term: lt }));
        }
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.leader = Some(self.id);
        let li = self.last_index();
        self.next = self.peers.iter().map(|p| (*p, li + 1)).collect();
        self.matched = self.peers.iter().map(|p| (*p, 0)).collect();
        // a no-op from this term: entries from earlier terms commit once it does (§5.4.2)
        self.append_local(Vec::new());
        self.broadcast_append();
    }

    fn append_local(&mut self, data: Vec<u8>) -> Index {
        self.log.push(Entry { term: self.hard.term, data });
        let i = self.last_index();
        self.log_dirty_from = Some(self.log_dirty_from.map_or(i, |d| d.min(i)));
        if self.peers.is_empty() {
            self.commit = i;
        }
        i
    }

    fn send_append(&mut self, to: NodeId) {
        let next = *self.next.get(&to).unwrap_or(&1);
        let prev = next.saturating_sub(1);
        let prev_term = self.term_at(prev).unwrap_or(0);
        let entries: Vec<Entry> = self.log[(next as usize).min(self.log.len())..].iter().take(self.max_batch).cloned().collect();
        self.outbox.push((to, Msg::Append { term: self.hard.term, prev_index: prev, prev_term, entries, commit: self.commit,
                                            read_seq: self.read_seq }));
    }

    fn broadcast_append(&mut self) {
        self.heartbeat_elapsed = 0;
        for p in self.peers.clone() {
            self.send_append(p);
        }
    }

    /// One unit of time.
    pub fn tick(&mut self) {
        if self.role == Role::Leader {
            self.heartbeat_elapsed += 1;
            if self.heartbeat_elapsed >= self.heartbeat_ticks {
                self.broadcast_append();
            }
        } else {
            self.election_elapsed += 1;
            if self.election_elapsed >= self.election_timeout {
                self.campaign();
            }
        }
    }

    /// A client's command; its index if this node leads.
    pub fn propose(&mut self, data: Vec<u8>) -> Result<Index, RaftError> {
        if self.role != Role::Leader {
            return Err(RaftError::NotLeader(self.leader));
        }
        let i = self.append_local(data);
        self.broadcast_append();
        Ok(i)
    }

    /// A linearizable read: once [`take_reads`] returns `(id, index)`, state applied up to `index` reflects every
    /// write committed before the read was asked for.
    pub fn read_index(&mut self, id: u64) -> Result<(), RaftError> {
        if self.role != Role::Leader {
            return Err(RaftError::NotLeader(self.leader));
        }
        // a leader may only serve reads once an entry from its term is committed
        if self.peers.is_empty() {
            self.ready_reads.push((id, self.commit));
            return Ok(());
        }
        self.read_seq += 1;
        self.pending_reads.push((id, self.read_seq, self.commit));
        self.read_acks.insert(self.read_seq, [self.id].into_iter().collect());
        self.broadcast_append();
        Ok(())
    }

    fn maybe_commit(&mut self) {
        let mut idx: Vec<Index> = self.matched.values().copied().chain(std::iter::once(self.last_index())).collect();
        idx.sort_unstable_by(|a, b| b.cmp(a));
        let n = idx[self.quorum() - 1];
        if n > self.commit && self.term_at(n) == Some(self.hard.term) {
            self.commit = n;
            self.broadcast_append(); // tell followers promptly
        }
    }

    fn release_reads(&mut self) {
        let term_committed = self.term_at(self.commit) == Some(self.hard.term);
        if !term_committed {
            return;
        }
        let q = self.quorum();
        let confirmed: Vec<u64> = self.read_acks.iter().filter(|(_, a)| a.len() >= q).map(|(s, _)| *s).collect();
        let Some(max_seq) = confirmed.iter().max().copied() else { return };
        let (ready, waiting): (Vec<_>, Vec<_>) = self.pending_reads.drain(..).partition(|(_, s, _)| *s <= max_seq);
        self.pending_reads = waiting;
        for (id, _, at) in ready {
            self.ready_reads.push((id, at.max(self.commit)));
        }
        self.read_acks.retain(|s, _| *s > max_seq);
    }

    /// A message from a peer.
    pub fn step(&mut self, from: NodeId, msg: Msg) {
        if msg.term() > self.hard.term {
            let leader = if matches!(msg, Msg::Append { .. }) { Some(from) } else { None };
            self.become_follower(msg.term(), leader);
        }
        match msg {
            Msg::Vote { term, last_index, last_term } => {
                let my_lt = self.term_at(self.last_index()).unwrap_or(0);
                let up_to_date = last_term > my_lt || (last_term == my_lt && last_index >= self.last_index());
                let can = term == self.hard.term && (self.hard.voted_for.is_none() || self.hard.voted_for == Some(from));
                let granted = can && up_to_date;
                if granted {
                    self.hard.voted_for = Some(from);
                    self.hard_dirty = true;
                    self.reset_election_timeout();
                }
                self.outbox.push((from, Msg::VoteResp { term: self.hard.term, granted }));
            }
            Msg::VoteResp { term, granted } => {
                if self.role == Role::Candidate && term == self.hard.term && granted {
                    self.votes.insert(from);
                    if self.votes.len() >= self.quorum() {
                        self.become_leader();
                    }
                }
            }
            Msg::Append { term, prev_index, prev_term, entries, commit, read_seq } => {
                if term < self.hard.term {
                    self.outbox.push((from, Msg::AppendResp { term: self.hard.term, success: false, match_index: 0,
                                                              conflict_hint: 0, read_seq }));
                    return;
                }
                self.role = Role::Follower;
                self.leader = Some(from);
                self.reset_election_timeout();
                if self.term_at(prev_index) != Some(prev_term) {
                    // a hint: retry from our last index, or the first index of the conflicting term
                    let hint = if prev_index > self.last_index() {
                        self.last_index() + 1
                    } else {
                        let t = self.term_at(prev_index).unwrap_or(0);
                        let mut i = prev_index;
                        while i > 1 && self.term_at(i - 1) == Some(t) {
                            i -= 1;
                        }
                        i
                    };
                    self.outbox.push((from, Msg::AppendResp { term: self.hard.term, success: false, match_index: 0,
                                                              conflict_hint: hint.max(1), read_seq }));
                    return;
                }
                let mut i = prev_index;
                for e in entries {
                    i += 1;
                    match self.term_at(i) {
                        Some(t) if t == e.term => continue,
                        Some(_) => {
                            self.log.truncate(i as usize);
                            self.log.push(e);
                            self.log_dirty_from = Some(self.log_dirty_from.map_or(i, |d| d.min(i)));
                        }
                        None => {
                            self.log.push(e);
                            self.log_dirty_from = Some(self.log_dirty_from.map_or(i, |d| d.min(i)));
                        }
                    }
                }
                if commit > self.commit {
                    self.commit = commit.min(i).max(self.commit);
                }
                self.outbox.push((from, Msg::AppendResp { term: self.hard.term, success: true, match_index: i,
                                                          conflict_hint: 0, read_seq }));
            }
            Msg::AppendResp { term, success, match_index, conflict_hint, read_seq } => {
                if self.role != Role::Leader || term != self.hard.term {
                    return;
                }
                if let Some(acks) = self.read_acks.get_mut(&read_seq) {
                    acks.insert(from);
                }
                // an ack for a later heartbeat confirms earlier reads too
                for (s, acks) in self.read_acks.iter_mut() {
                    if *s <= read_seq {
                        acks.insert(from);
                    }
                }
                if success {
                    let m = self.matched.entry(from).or_insert(0);
                    if match_index > *m {
                        *m = match_index;
                    }
                    self.next.insert(from, match_index + 1);
                    self.maybe_commit();
                    if match_index < self.last_index() {
                        self.send_append(from);
                    }
                } else {
                    let n = self.next.entry(from).or_insert(1);
                    *n = conflict_hint.max(1).min(*n);
                    self.send_append(from);
                }
                self.release_reads();
            }
        }
    }

    pub fn take_outbox(&mut self) -> Vec<(NodeId, Msg)> {
        std::mem::take(&mut self.outbox)
    }

    /// Committed entries not yet applied, in order (index, entry).
    pub fn take_committed(&mut self) -> Vec<(Index, Entry)> {
        let mut out = Vec::new();
        while self.applied < self.commit {
            self.applied += 1;
            out.push((self.applied, self.log[self.applied as usize].clone()));
        }
        out
    }

    pub fn take_reads(&mut self) -> Vec<(u64, Index)> {
        std::mem::take(&mut self.ready_reads)
    }

    /// The term/vote to persist, if they changed since the last call.
    pub fn hard_state_changed(&mut self) -> Option<HardState> {
        std::mem::take(&mut self.hard_dirty).then(|| self.hard.clone())
    }

    /// The first log index that changed since the last call (persist the log from there).
    pub fn log_changed_from(&mut self) -> Option<Index> {
        self.log_dirty_from.take()
    }

    /// Restart from a snapshot of applied state: entries up to `applied` are already in the state machine.
    pub fn set_applied(&mut self, applied: Index) {
        self.applied = applied.min(self.last_index());
        self.commit = self.commit.max(self.applied);
    }
}
