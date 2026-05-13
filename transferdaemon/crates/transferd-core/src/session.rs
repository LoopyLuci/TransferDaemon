use crate::ate::Ate;
use crate::control_channel::ControlMessage;
use crate::retransmit::RetransmitBuffer;
use crate::transport::{Chunk, TransportLane};
use crate::types::{Gsn, SessionId};
use bytes::Bytes;
use std::collections::VecDeque;

pub struct Session {
    pub id: SessionId,
    ate: Ate,
    send_base: Gsn,
    next_gsn: Gsn,
    window_size: u64,
    pending: VecDeque<Chunk>,
    retransmit: RetransmitBuffer,
}

impl Session {
    pub fn new(id: SessionId, ate: Ate, window_size: u64) -> Self {
        Self {
            id,
            ate,
            send_base: Gsn::ZERO,
            next_gsn: Gsn::ZERO,
            window_size,
            pending: VecDeque::new(),
            retransmit: RetransmitBuffer::new(),
        }
    }

    pub fn enqueue(&mut self, payload: Bytes, key_epoch: u8) {
        self.enqueue_qos(payload, key_epoch, false);
    }

    pub fn enqueue_qos(&mut self, payload: Bytes, key_epoch: u8, qos_critical: bool) {
        self.pending.push_back(Chunk {
            gsn: self.next_gsn,
            session_id: self.id,
            payload,
            key_epoch,
            qos_critical,
        });
        self.next_gsn = self.next_gsn.next();
    }

    /// Drives the send loop: picks lanes via ATE and dispatches pending chunks.
    pub async fn process_tick(
        &mut self,
        lanes: &mut [Box<dyn TransportLane>],
    ) -> Vec<(usize, Gsn)> {
        let mut sent = vec![];

        // Collect metrics and capacities without holding mutable refs.
        let metrics_arc: Vec<_> = lanes.iter().map(|l| l.metrics()).collect();
        let metrics_refs: Vec<_> = metrics_arc.iter().map(|a| a.as_ref()).collect();
        let capacities: Vec<_> = lanes.iter().map(|l| l.capacity()).collect();

        while let Some(chunk) = self.pending.pop_front() {
            if chunk.gsn.distance(self.send_base) >= self.window_size {
                self.pending.push_front(chunk);
                break;
            }

            let lane_idx = self.ate.select_lane(
                chunk.gsn, self.send_base, &metrics_refs, &capacities,
            );

            if let Some(idx) = lane_idx {
                self.retransmit.insert(chunk.clone());
                match lanes[idx].send(chunk.clone()).await {
                    Ok(()) => {
                        lanes[idx].metrics().inc_active();
                        sent.push((idx, chunk.gsn));

                        // QoS-critical: mirror on a second lane (first arrival wins at receiver).
                        if chunk.qos_critical {
                            let mirror = self.ate.select_two_lanes(
                                chunk.gsn, self.send_base, &metrics_refs, &capacities,
                            );
                            if let Some((_, mirror_idx)) = mirror {
                                if mirror_idx != idx {
                                    let _ = lanes[mirror_idx].send(chunk.clone()).await;
                                    sent.push((mirror_idx, chunk.gsn));
                                }
                            }
                        }
                    }
                    Err(_) => {
                        self.pending.push_front(chunk);
                        break;
                    }
                }
            } else {
                self.pending.push_front(chunk);
                break;
            }
        }
        sent
    }

    pub fn handle_control(&mut self, msg: ControlMessage) -> Option<Chunk> {
        match msg {
            ControlMessage::Ack { cumulative_gsn, .. } => {
                let new_base = Gsn(cumulative_gsn);
                if new_base > self.send_base { self.send_base = new_base; }
                self.retransmit.prune(self.send_base);
                None
            }
            ControlMessage::Nack { missing_gsn, .. } => {
                self.retransmit.get(Gsn(missing_gsn)).cloned()
            }
            ControlMessage::WindowUpdate { right_edge, .. } => {
                self.window_size = right_edge;
                None
            }
            _ => None,
        }
    }

    pub fn pending_len(&self) -> usize { self.pending.len() }
}
