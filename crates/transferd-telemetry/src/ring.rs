use std::collections::VecDeque;

use crate::events::TelemetryEvent;

pub struct RingBuffer {
    inner: VecDeque<TelemetryEvent>,
    cap: usize,
}

impl RingBuffer {
    pub fn new(cap: usize) -> Self {
        Self { inner: VecDeque::with_capacity(cap), cap }
    }

    pub fn push(&mut self, event: TelemetryEvent) {
        if self.inner.len() == self.cap {
            self.inner.pop_front();
        }
        self.inner.push_back(event);
    }

    pub fn snapshot(&self) -> Vec<TelemetryEvent> {
        self.inner.iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
