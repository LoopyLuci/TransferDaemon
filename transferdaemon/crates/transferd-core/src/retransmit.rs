use crate::transport::Chunk;
use crate::types::Gsn;
use std::collections::HashMap;

pub struct RetransmitBuffer {
    map: HashMap<Gsn, Chunk>,
    cumulative_gsn: Gsn,
}

impl RetransmitBuffer {
    pub fn new() -> Self {
        Self { map: HashMap::new(), cumulative_gsn: Gsn::ZERO }
    }

    pub fn insert(&mut self, chunk: Chunk) {
        self.map.insert(chunk.gsn, chunk);
    }

    pub fn get(&self, gsn: Gsn) -> Option<&Chunk> {
        self.map.get(&gsn)
    }

    pub fn prune(&mut self, new_cumulative: Gsn) {
        self.map.retain(|gsn, _| *gsn >= new_cumulative);
        self.cumulative_gsn = new_cumulative;
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Clone all buffered chunks (for retransmit scanning).
    pub fn snapshot(&self) -> Vec<Chunk> {
        self.map.values().cloned().collect()
    }
}

impl Default for RetransmitBuffer {
    fn default() -> Self { Self::new() }
}
