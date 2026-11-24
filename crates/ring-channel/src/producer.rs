use crate::doorbell::Doorbell;
use crate::grant::WriteGrant;
use crate::mmap::MappedRegion;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Producer {
    region: Arc<MappedRegion>,
    doorbell: Arc<Doorbell>,
    prod_idx: Arc<AtomicU64>,
    cons_idx: Arc<AtomicU64>,
    descriptor_count: u64,
    ring_mask: u64,
}

impl Producer {
    pub fn new(
        region: Arc<MappedRegion>,
        doorbell: Arc<Doorbell>,
        prod_idx: Arc<AtomicU64>,
        cons_idx: Arc<AtomicU64>,
        descriptor_count: usize,
    ) -> Self {
        Self {
            ring_mask: descriptor_count as u64 - 1,
            descriptor_count: descriptor_count as u64,
            region,
            doorbell,
            prod_idx,
            cons_idx,
        }
    }

    pub async fn reserve_grant(&mut self, len: usize) -> Result<WriteGrant, String> {
        loop {
            let p = self.prod_idx.load(Ordering::Acquire);
            let c = self.cons_idx.load(Ordering::Acquire);
            if p - c < self.descriptor_count {
                let slot = (p & self.ring_mask) as usize;
                let max_chunk = self.region.data_area_size / self.descriptor_count as usize;
                let data_offset = (slot * max_chunk).min(
                    self.region.data_area_size.saturating_sub(len),
                );
                let ptr = unsafe { self.region.data_ptr().add(data_offset) };
                return Ok(WriteGrant { ptr, len, slot_idx: slot });
            }
            self.doorbell.wait().await;
        }
    }

    /// Commits a grant, writing the full crypto metadata into the descriptor.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_grant(
        &mut self,
        grant: WriteGrant,
        gsn_start: u64,
        gsn_end: u64,
        nonce: &[u8; 12],
        gcm_tag: &[u8; 16],
        blake3_hash: &[u8; 32],
        key_epoch: u8,
    ) {
        let slot = grant.slot_idx;
        let desc = unsafe { &mut *self.region.descriptor_mut_ptr().add(slot) };
        desc.gsn_start = gsn_start;
        desc.gsn_end = gsn_end;
        desc.length = grant.len as u32;
        desc.flags = 0;
        desc.chunk_id = gsn_start;
        desc.stream_offset = 0;
        desc.key_epoch = key_epoch;
        desc.write_crypto_result(nonce, gcm_tag, blake3_hash);
        std::sync::atomic::fence(Ordering::SeqCst);
        self.prod_idx.fetch_add(1, Ordering::Release);
        self.doorbell.ring();
    }

    /// Convenience: commit without real crypto (used in tests and non-crypto lanes).
    pub fn commit_grant_plain(
        &mut self,
        grant: WriteGrant,
        gsn_start: u64,
        gsn_end: u64,
        blake3_prefix: &[u8; 8],
        key_epoch: u8,
    ) {
        let mut full_hash = [0u8; 32];
        full_hash[..8].copy_from_slice(blake3_prefix);
        let nonce = {
            let mut n = [0u8; 12];
            n[..8].copy_from_slice(&gsn_start.to_le_bytes());
            n[8] = key_epoch;
            n
        };
        self.commit_grant(grant, gsn_start, gsn_end, &nonce, &[0u8; 16], &full_hash, key_epoch);
    }

    pub fn available_slots(&self) -> usize {
        let p = self.prod_idx.load(Ordering::Relaxed);
        let c = self.cons_idx.load(Ordering::Relaxed);
        (self.descriptor_count - (p - c)) as usize
    }
}
