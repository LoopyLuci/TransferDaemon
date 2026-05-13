use std::collections::HashMap;

#[derive(Clone, Default)]
pub struct EpochKeys {
    keys: HashMap<u8, [u8; 32]>,
}

impl EpochKeys {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_epoch(&mut self, epoch: u8, key: [u8; 32]) {
        self.keys.insert(epoch, key);
    }

    pub fn get(&self, epoch: u8) -> Option<&[u8; 32]> {
        self.keys.get(&epoch)
    }

    pub fn rotate(&mut self, old_epoch: u8, new_epoch: u8, key: [u8; 32]) {
        self.keys.remove(&old_epoch);
        self.keys.insert(new_epoch, key);
    }
}
