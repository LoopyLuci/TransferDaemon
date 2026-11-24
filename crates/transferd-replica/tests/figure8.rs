//! The situation in Figure 8 of the Raft paper, built step by step: a leader must not count replicas of an entry
//! from an earlier term as committed, because a later leader may still overwrite it.

use std::collections::{BTreeMap, VecDeque};
use transferd_replica::raft::{Entry, HardState, Msg, NodeId, Raft, Role};

fn e(term: u64, data: &str) -> Entry {
    Entry { term, data: data.as_bytes().to_vec() }
}

struct Net {
    nodes: BTreeMap<NodeId, Raft>,
    q: VecDeque<(NodeId, NodeId, Msg)>,
    applied: BTreeMap<NodeId, BTreeMap<u64, Vec<u8>>>,
}

impl Net {
    fn collect(&mut self, id: NodeId) {
        let r = self.nodes.get_mut(&id).expect("node");
        for (to, m) in r.take_outbox() {
            self.q.push_back((id, to, m));
        }
        for (i, en) in r.take_committed() {
            self.applied.entry(id).or_default().insert(i, en.data);
        }
    }

    /// Deliver queued messages that `allow` lets through (others are dropped), until none are left.
    fn deliver(&mut self, allow: impl Fn(NodeId, NodeId, &Msg) -> bool) {
        self.deliver_map(|f, t, m| allow(f, t, &m).then_some(m));
    }

    /// Deliver what `map` returns for each queued message (None: dropped).
    fn deliver_map(&mut self, map: impl Fn(NodeId, NodeId, Msg) -> Option<Msg>) {
        let mut guard = 0;
        while let Some((from, to, m)) = self.q.pop_front() {
            guard += 1;
            if guard > 2_000 {
                // a leader retrying what the test keeps cutting off: end this round (real time would pass here)
                self.q.clear();
                break;
            }
            let Some(m) = map(from, to, m) else { continue };
            if !self.nodes.contains_key(&to) {
                continue;
            }
            self.nodes.get_mut(&to).expect("node").step(from, m);
            self.collect(to);
        }
    }

    fn campaign(&mut self, id: NodeId) {
        let r = self.nodes.get_mut(&id).expect("node");
        for _ in 0..100 {
            r.tick();
            if r.role != Role::Follower {
                break;
            }
        }
        self.collect(id);
    }
}

#[test]
fn an_old_term_entry_is_not_committed_by_counting_replicas() {
    let ids: Vec<NodeId> = (1..=5).collect();
    let mk = |id: NodeId, term: u64, log: Vec<Entry>| {
        let mut r = Raft::new(id, ids.clone(), HardState { term, voted_for: None }, log, id);
        r.max_batch = 1;
        r
    };
    let mut net = Net { nodes: BTreeMap::new(), q: VecDeque::new(), applied: BTreeMap::new() };
    // S1 wrote "A" at index 2 when it led term 2; S5 wrote "B" there when it led term 3; nobody else has either
    net.nodes.insert(1, mk(1, 3, vec![e(1, "init"), e(2, "A")]));
    for id in 2..=4 {
        net.nodes.insert(id, mk(id, 3, vec![e(1, "init")]));
    }
    // S5 led term 3; it has since seen term 4 come and go
    net.nodes.insert(5, mk(5, 4, vec![e(1, "init"), e(3, "B")]));

    // S1 wins term 4 (S5 does not hear of it)
    // S1 copies "A" (term 2) to S2 and S3, but its own term-4 entry (index 3) never gets out before it crashes:
    // only S1, S2 and S3 talk, and no append carrying index 3 or beyond is delivered
    // (entries past index 2 are cut off in transit: what arrives is what a leader could have sent, a shorter append)
    let s1_phase = |f: NodeId, t: NodeId, m: Msg| -> Option<Msg> {
        if [f, t].iter().any(|x| *x == 4 || *x == 5) {
            return None;
        }
        match m {
            Msg::Append { term, prev_index, prev_term, mut entries, commit, read_seq } => {
                let keep = 2u64.saturating_sub(prev_index) as usize;
                entries.truncate(keep);
                Some(Msg::Append { term, prev_index, prev_term, entries, commit, read_seq })
            }
            other => Some(other),
        }
    };
    net.campaign(1);
    net.deliver_map(s1_phase);
    assert_eq!(net.nodes[&1].role, Role::Leader);
    for _ in 0..8 {
        net.nodes.get_mut(&1).expect("s1").tick();
        net.collect(1);
        net.deliver_map(s1_phase);
    }
    assert!(net.nodes[&2].entries_from(2).first().is_some_and(|x| x.data == b"A"), "S2 holds A");
    assert!(net.nodes[&3].entries_from(2).first().is_some_and(|x| x.data == b"A"), "S3 holds A");
    assert!(net.nodes[&2].last_index() == 2 && net.nodes[&3].last_index() == 2, "and nothing from term 4");
    let s1_commit = net.nodes[&1].commit;
    // S1 crashes
    net.nodes.remove(&1);
    net.q.clear();
    // S5 wins term 5 with S2, S3, S4 (its last term, 3, is newer than their 2) and overwrites index 2 everywhere
    for _ in 0..50 {
        // only S5's clock runs until it leads (no rival campaigns), then everyone's
        net.campaign(5);
        net.deliver(|_, _, _| true);
        if net.nodes[&5].role == Role::Leader {
            break;
        }
    }

    for _ in 0..20 {
        for id in [2, 3, 4, 5] {
            net.nodes.get_mut(&id).expect("node").tick();
            net.collect(id);
        }
        net.deliver(|_, _, _| true);
    }
    assert_eq!(net.nodes[&5].role, Role::Leader, "S5 leads term 5");
    let others_at_2: Vec<_> = [2, 3, 4, 5].iter().filter_map(|id| net.applied.get(id).and_then(|a| a.get(&2))).collect();
    assert!(others_at_2.iter().all(|d| d.as_slice() == b"B"), "the term-5 leader's entry is what everyone applied at 2");
    // the point: S1 must not have treated "A" as committed (else it would disagree with everyone forever)
    assert!(s1_commit < 2, "S1 committed index 2 (an entry from term 2) by counting replicas: commit = {s1_commit}");
    if let Some(a) = net.applied.get(&1).and_then(|a| a.get(&2)) {
        panic!("S1 applied {:?} at index 2 while the cluster applied B", String::from_utf8_lossy(a));
    }
}
