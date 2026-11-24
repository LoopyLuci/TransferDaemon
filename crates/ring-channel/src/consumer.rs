use crate::doorbell::Doorbell;
use crate::grant::ReadGrant;
use crate::mmap::MappedRegion;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Consumer {
    region: Arc<MappedRegion>,
    doorbell: Arc<Doorbell>,
    prod_idx: Arc<AtomicU64>,
    cons_idx: Arc<AtomicU64>,
    ring_mask: u64,
}

impl Consumer {
    pub fn new(
        region: Arc<MappedRegion>,
        doorbell: Arc<Doorbell>,
        prod_idx: Arc<AtomicU64>,
        cons_idx: Arc<AtomicU64>,
        descriptor_count: usize,
    ) -> Self {
        Self {
            ring_mask: descriptor_count as u64 - 1,
            region,
            doorbell,
            prod_idx,
            cons_idx,
        }
    }

    pub async fn read_grant(&mut self) -> Result<ReadGrant<'_>, std::io::Error> {
        loop {
            let p = self.prod_idx.load(Ordering::Acquire);
            let c = self.cons_idx.load(Ordering::Acquire);
            if p > c {
                let slot = (c & self.ring_mask) as usize;
                let desc = unsafe { &*self.region.descriptor_ptr().add(slot) };
                let len = desc.length as usize;
                let buf = unsafe {
                    std::slice::from_raw_parts(
                        self.region.data_ptr(),
                        len.min(self.region.data_area_size),
                    )
                };
                return Ok(ReadGrant { buf, slot_idx: slot, desc });
            }
            self.doorbell.wait().await;
            self.doorbell.consume();
        }
    }

    pub fn release_grant(&mut self) {
        self.cons_idx.fetch_add(1, Ordering::Release);
    }
}
