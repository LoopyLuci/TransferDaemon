//! Raft under a hostile simulated network: messages lost, delayed and reordered, partitions, nodes crashing and
//! restarting with only their durable state. Seeded, so a failure reproduces.

use rand::{Rng, SeedableRng};
use std::collections::{BTreeMap, BTreeSet};
use transferd_replica::raft::{Entry, HardState, Msg, NodeId, Raft, Role};

struct Disk {
    hard: HardState,
    log: Vec<Entry>,
}

struct Sim {
    nodes: BTreeMap<NodeId, Option<Raft>>,
    disks: BTreeMap<NodeId, Disk>,
    applied: BTreeMap<NodeId, Vec<Vec<u8>>>,
    net: Vec<(u64, NodeId, NodeId, Msg)>,
    now: u64,
    rng: rand::rngs::StdRng,
    cut: BTreeSet<NodeId>,
    leaders_by_term: BTreeMap<u64, NodeId>,
    loss: f64,
    seed: u64,
}

impl Sim {
    fn new(n: u64, seed: u64, loss: f64) -> Self {
        let ids: Vec<NodeId> = (1..=n).collect();
        let mut s = Sim { nodes: BTreeMap::new(), disks: BTreeMap::new(), applied: BTreeMap::new(), net: Vec::new(), now: 0,
                          rng: rand::rngs::StdRng::seed_from_u64(seed), cut: BTreeSet::new(), leaders_by_term: BTreeMap::new(),
                          loss, seed };
        for id in &ids {
            s.disks.insert(*id, Disk { hard: HardState::default(), log: Vec::new() });
            s.applied.insert(*id, Vec::new());
            let mut r = Raft::new(*id, ids.clone(), HardState::default(), Vec::new(), seed);
            r.max_batch = 2; // catch-up in small pieces: followers often hold only part of what the leader has
            s.nodes.insert(*id, Some(r));
        }
        s
    }

    fn ids(&self) -> Vec<NodeId> {
        self.nodes.keys().copied().collect()
    }

    /// Persist, then send: what a real node does after every step.
    fn flush(&mut self, id: NodeId) {
        let Some(Some(r)) = self.nodes.get_mut(&id) else { return };
        if let Some(h) = r.hard_state_changed() {
            self.disks.get_mut(&id).expect("disk").hard = h;
        }
        if let Some(from) = r.log_changed_from() {
            let d = self.disks.get_mut(&id).expect("disk");
            d.log.truncate((from - 1) as usize);
            d.log.extend_from_slice(r.entries_from(from));
        }
        for (_, e) in r.take_committed() {
            if !e.data.is_empty() {
                self.applied.get_mut(&id).expect("applied").push(e.data);
            }
        }
        if r.role == Role::Leader {
            if let Some(prev) = self.leaders_by_term.insert(r.hard.term, id) {
                assert_eq!(prev, id, "two leaders in term {} (seed {})", r.hard.term, self.seed);
            }
        }
        let out = r.take_outbox();
        for (to, m) in out {
            if self.rng.gen_bool(self.loss) || self.cut.contains(&id) != self.cut.contains(&to) {
                continue; // lost, or across the partition
            }
            let delay = self.rng.gen_range(1..6);
            self.net.push((self.now + delay, id, to, m));
        }
    }

    fn run(&mut self, ticks: u64) {
        for _ in 0..ticks {
            self.now += 1;
            let due: Vec<_> = { let (d, rest): (Vec<_>, Vec<_>) = self.net.drain(..).partition(|m| m.0 <= self.now); self.net = rest; d };
            for (_, from, to, m) in due {
                if let Some(Some(r)) = self.nodes.get_mut(&to) {
                    r.step(from, m);
                    self.flush(to);
                }
            }
            for id in self.ids() {
                if let Some(Some(r)) = self.nodes.get_mut(&id) {
                    r.tick();
                }
                self.flush(id);
            }
        }
    }

    fn leader(&self) -> Option<NodeId> {
        self.nodes.iter().filter_map(|(id, r)| r.as_ref().filter(|r| r.role == Role::Leader).map(|r| (r.hard.term, *id)))
            .max().map(|(_, id)| id)
    }

    fn crash(&mut self, id: NodeId) {
        self.nodes.insert(id, None);
        // what it had applied is gone with its memory; on restart it replays from the log
        self.applied.insert(id, Vec::new());
    }

    fn restart(&mut self, id: NodeId) {
        let d = &self.disks[&id];
        let ids = self.ids();
        let mut r = Raft::new(id, ids, d.hard.clone(), d.log.clone(), self.seed + self.now);
        r.max_batch = 2;
        self.nodes.insert(id, Some(r));
    }

    /// Every node's applied sequence is a prefix of the longest one (state machine safety).
    fn check_prefixes(&self) {
        let longest = self.applied.values().max_by_key(|v| v.len()).cloned().unwrap_or_default();
        for (id, a) in &self.applied {
            assert_eq!(&longest[..a.len()], &a[..], "node {id} applied a different sequence (seed {})", self.seed);
        }
    }
}

#[test]
fn safety_and_liveness_under_loss_partitions_and_crashes() {
    for seed in 0..300u64 {
        let mut s = Sim::new(5, seed, 0.15);
        let mut acked: Vec<Vec<u8>> = Vec::new();
        let mut next = 0u32;
        for round in 0..60 {
            s.run(10);
            if let Some(l) = s.leader() {
                let data = format!("w{next}").into_bytes();
                if let Some(Some(r)) = s.nodes.get_mut(&l) {
                    if let Ok(i) = r.propose(data.clone()) {
                        next += 1;
                        // track: acknowledged once committed on the leader
                        let target = (l, i, data);
                        s.flush(l);
                        for _ in 0..40 {
                            s.run(1);
                            let committed = s.nodes.get(&target.0).and_then(|r| r.as_ref()).is_some_and(|r| r.commit >= target.1
                                && r.entries_from(target.1).first().is_some_and(|e| e.data == target.2));
                            if committed {
                                acked.push(target.2.clone());
                                break;
                            }
                        }
                    }
                }
            }
            // leaders crash right after proposing (the scenario of the paper's Figure 8), nodes come back with only
            // their durable state, and the network splits
            let r: u32 = s.rng.gen_range(0..10);
            if r < 3 {
                if let Some(l) = s.leader() {
                    // propose a few more without waiting, then die with them partly replicated
                    for k in 0..3 {
                        if let Some(Some(n)) = s.nodes.get_mut(&l) {
                            let _ = n.propose(format!("x{round}-{k}").into_bytes());
                        }
                        s.flush(l);
                        s.run(1);
                    }
                    s.crash(l);
                }
            }
            if r == 4 || r == 5 {
                let down: Vec<NodeId> = s.ids().into_iter().filter(|id| s.nodes[id].is_none()).collect();
                if let Some(v) = down.first() {
                    s.restart(*v);
                }
            }
            if r == 6 {
                let a = s.rng.gen_range(1..=5);
                let b = s.rng.gen_range(1..=5);
                s.cut = [a, b].into_iter().collect();
            }
            if r == 7 || r == 8 {
                s.cut.clear();
            }
            // never more than two down at once, so a majority can still make progress
            let down: Vec<NodeId> = s.ids().into_iter().filter(|id| s.nodes[id].is_none()).collect();
            if down.len() > 2 {
                s.restart(down[0]);
            }
            s.check_prefixes();
        }
        // heal everything and let it settle: every acknowledged write is applied everywhere
        s.cut.clear();
        for id in s.ids() {
            if s.nodes[&id].is_none() {
                s.restart(id);
            }
        }
        s.loss = 0.0;
        s.run(400);
        s.check_prefixes();
        for (id, a) in &s.applied {
            for w in &acked {
                assert!(a.contains(w), "node {id} lost acknowledged write {:?} (seed {seed})", String::from_utf8_lossy(w));
            }
        }
        assert!(!acked.is_empty(), "made no progress at all (seed {seed})");
    }
}

#[test]
fn reads_see_every_acknowledged_write() {
    let mut s = Sim::new(3, 7, 0.0);
    s.run(60);
    let l = s.leader().expect("a leader");
    let i = s.nodes.get_mut(&l).and_then(|r| r.as_mut()).expect("leader").propose(b"x=1".to_vec()).expect("propose");
    s.run(30);
    let r = s.nodes.get_mut(&l).and_then(|r| r.as_mut()).expect("leader");
    r.read_index(42).expect("read");
    s.flush(l);
    let mut got = None;
    for _ in 0..30 {
        s.run(1);
        if let Some(Some(r)) = s.nodes.get_mut(&l) {
            if let Some(x) = r.take_reads().into_iter().find(|(id, _)| *id == 42) {
                got = Some(x.1);
                break;
            }
        }
    }
    assert!(got.is_some_and(|at| at >= i), "a read after an acknowledged write must not be served from before it");
    // a follower refuses reads and proposals, naming the leader
    let f = s.ids().into_iter().find(|id| *id != l).expect("a follower");
    let fr = s.nodes.get_mut(&f).and_then(|r| r.as_mut()).expect("follower");
    assert!(fr.read_index(1).is_err() && fr.propose(b"y".to_vec()).is_err());
}

#[test]
fn a_single_node_commits_alone() {
    let mut r = Raft::new(1, vec![1], HardState::default(), Vec::new(), 1);
    for _ in 0..40 {
        r.tick();
    }
    assert_eq!(r.role, Role::Leader);
    let i = r.propose(b"solo".to_vec()).expect("propose");
    assert!(r.commit >= i);
    assert!(r.take_committed().iter().any(|(_, e)| e.data == b"solo"));
}
