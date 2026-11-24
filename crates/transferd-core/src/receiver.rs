use crate::transport::Chunk;
use crate::types::{Gsn, SessionId};
use bytes::Bytes;
use std::time::Instant;

#[derive(Debug)]
pub struct Nack {
    pub session_id: SessionId,
    pub missing_gsn: Gsn,
    pub highest_received: Gsn,
    pub timestamp: Instant,
}

#[derive(Debug)]
pub struct WindowUpdate {
    pub session_id: SessionId,
    pub cumulative_gsn: Gsn,
    pub window_right_edge: Gsn,
}

#[derive(Debug, PartialEq)]
pub enum InsertResult {
    Delivered(Gsn),
    Gap(Gsn),
    Retransmit(Gsn),
    OutOfBounds,
}

pub struct ReassemblyWindow {
    window_size: u64,
    delivered_up_to: Gsn,
    highest_received: Gsn,
    buffer: Vec<Option<Bytes>>,
    occupied_slots: u64,
    session_id: SessionId,
}

impl ReassemblyWindow {
    pub fn new(session_id: SessionId, window_size: u64) -> Self {
        Self {
            window_size,
            delivered_up_to: Gsn::ZERO,
            highest_received: Gsn::ZERO,
            buffer: vec![None; window_size as usize],
            occupied_slots: 0,
            session_id,
        }
    }

    pub fn insert(&mut self, chunk: Chunk) -> InsertResult {
        if chunk.gsn < self.delivered_up_to {
            return InsertResult::Retransmit(chunk.gsn);
        }
        if chunk.gsn.distance(self.delivered_up_to) >= self.window_size {
            return InsertResult::OutOfBounds;
        }
        let idx = (chunk.gsn.0 % self.window_size) as usize;
        if self.buffer[idx].is_some() {
            return InsertResult::Retransmit(chunk.gsn);
        }
        self.buffer[idx] = Some(chunk.payload);
        self.occupied_slots += 1;
        if chunk.gsn > self.highest_received {
            self.highest_received = chunk.gsn;
        }

        let mut advanced = false;
        loop {
            let head_idx = (self.delivered_up_to.0 % self.window_size) as usize;
            if self.buffer[head_idx].take().is_some() {
                self.delivered_up_to = self.delivered_up_to.next();
                self.occupied_slots -= 1;
                advanced = true;
            } else {
                break;
            }
        }

        if advanced {
            InsertResult::Delivered(self.delivered_up_to)
        } else {
            InsertResult::Gap(self.delivered_up_to)
        }
    }

    pub fn is_critical_gap(&self) -> bool {
        let max_gap = self.window_size / 4;
        let high_occupancy = self.occupied_slots > self.window_size * 8 / 10;
        let wide_gap = self.highest_received.distance(self.delivered_up_to) > max_gap;
        (high_occupancy || wide_gap) && self.highest_received > self.delivered_up_to
    }

    pub fn generate_nack(&self) -> Nack {
        Nack {
            session_id: self.session_id,
            missing_gsn: self.delivered_up_to,
            highest_received: self.highest_received,
            timestamp: Instant::now(),
        }
    }

    pub fn delivered_up_to(&self) -> Gsn { self.delivered_up_to }

    pub fn should_update_window(&self) -> bool {
        self.occupied_slots < self.window_size * 3 / 4
    }

    pub fn generate_window_update(&self) -> WindowUpdate {
        WindowUpdate {
            session_id: self.session_id,
            cumulative_gsn: self.delivered_up_to,
            window_right_edge: self.delivered_up_to.offset(self.window_size),
        }
    }
}
