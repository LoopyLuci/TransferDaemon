use crate::ate::Ate;
use crate::control_channel::ControlMessage;
use crate::retransmit::RetransmitBuffer;
use crate::telemetry::{emit_ate, AteLaneHookData};
use crate::transport::{Chunk, LaneMetrics, TransportLane};
use crate::types::{Gsn, SessionId};
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Retransmit timeout: a sent-but-unacked chunk is re-sent after this long.
const RTO: Duration = Duration::from_millis(500);

pub struct Session {
    pub id: SessionId,
    ate: Ate,
    send_base: Gsn,
    next_gsn: Gsn,
    window_size: u64,
    pending: VecDeque<Chunk>,
    retransmit: RetransmitBuffer,
    /// When each dispatched gsn was sent (for the retransmit timer).
    sent_ts: HashMap<Gsn, Instant>,
    /// Where each sent-but-unacknowledged chunk is booked: one entry per copy on the wire (a QoS-critical chunk has
    /// two). The lane's in-flight bytes count these until the chunk is acknowledged or given up on for a resend.
    sent_on: HashMap<Gsn, Vec<(Arc<LaneMetrics>, u64)>>,
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
            sent_ts: HashMap::new(),
            sent_on: HashMap::new(),
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

    /// Number of sent-but-unacked chunks (in-flight budget used).
    pub fn outstanding(&self) -> usize {
        self.retransmit.len()
    }

    /// Re-dispatch chunks that have been outstanding past the RTO.
    pub async fn maybe_retransmit(
        &mut self,
        lanes: &mut [Box<dyn TransportLane>],
    ) -> Vec<(usize, Gsn)> {
        let now = Instant::now();
        let stale: Vec<Chunk> = self
            .retransmit
            .snapshot()
            .into_iter()
            .filter(|c| {
                self.sent_ts
                    .get(&c.gsn)
                    .map(|t| now.duration_since(*t) >= RTO)
                    .unwrap_or(false)
            })
            .collect();
        for chunk in stale {
            self.release(chunk.gsn);
            self.sent_ts.remove(&chunk.gsn);
            self.pending.push_front(chunk);
        }
        if !self.pending.is_empty() {
            self.process_tick(lanes).await
        } else {
            Vec::new()
        }
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

            let bytes = chunk.payload.len() as u64;
            let lane_idx = self.ate.select_lane(
                chunk.gsn, self.send_base, &metrics_refs, &capacities, bytes,
            );

            if let Some(idx) = lane_idx {
                // Snapshot metrics before the send for the telemetry record.
                let lane_m = lanes[idx].metrics();
                let rtt_ms = lane_m.rtt_ms.load(Ordering::Relaxed) as f64 / 1_000.0;
                let bandwidth_bps = lane_m.bandwidth_bps.load(Ordering::Relaxed);
                let active_chunks = lane_m.active_chunks.load(Ordering::Relaxed);
                emit_ate(AteLaneHookData {
                    session_id: self.id.0,
                    gsn: chunk.gsn.0,
                    selected_lane: idx as u32,
                    rtt_ms,
                    bandwidth_bps,
                    active_chunks,
                    total_lanes: lanes.len() as u32,
                });

                self.retransmit.insert(chunk.clone());
                self.sent_ts.insert(chunk.gsn, Instant::now());
                match lanes[idx].send(chunk.clone()).await {
                    Ok(()) => {
                        self.book(lanes[idx].metrics(), chunk.gsn, bytes);
                        sent.push((idx, chunk.gsn));

                        // QoS-critical: mirror on a second lane (first arrival wins at receiver).
                        if chunk.qos_critical {
                            let mirror = self.ate.select_two_lanes(
                                chunk.gsn, self.send_base, &metrics_refs, &capacities, bytes,
                            );
                            if let Some((_, mirror_idx)) = mirror {
                                if mirror_idx != idx {
                                    if lanes[mirror_idx].send(chunk.clone()).await.is_ok() {
                                        self.book(lanes[mirror_idx].metrics(), chunk.gsn, bytes);
                                    }
                                    sent.push((mirror_idx, chunk.gsn));
                                }
                            }
                        }
                    }
                    Err(_) => {
                        self.sent_ts.remove(&chunk.gsn);
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

    /// Books one copy of chunk `gsn`, `bytes` long, onto `lane`, until the chunk is acknowledged or given up on.
    fn book(&mut self, lane: Arc<LaneMetrics>, gsn: Gsn, bytes: u64) {
        lane.on_sent(bytes);
        self.sent_on.entry(gsn).or_default().push((lane, bytes));
    }

    /// Takes every copy of chunk `gsn` off the lanes it was booked on.
    fn release(&mut self, gsn: Gsn) {
        if let Some(copies) = self.sent_on.remove(&gsn) {
            for (lane, bytes) in copies {
                lane.on_released(bytes);
            }
        }
    }

    pub fn handle_control(&mut self, msg: ControlMessage) {
        match msg {
            ControlMessage::Ack { cumulative_gsn, .. } => {
                let new_base = Gsn(cumulative_gsn);
                if new_base > self.send_base {
                    self.send_base = new_base;
                }
                self.retransmit.prune(self.send_base);
                // Drop send timestamps for acked gsns below the new base.
                self.sent_ts.retain(|gsn, _| *gsn >= self.send_base);
                // Acknowledged chunks leave the lanes they were booked on.
                let acked: Vec<Gsn> = self
                    .sent_on
                    .keys()
                    .copied()
                    .filter(|gsn| *gsn < self.send_base)
                    .collect();
                for gsn in acked {
                    self.release(gsn);
                }
            }
            ControlMessage::Nack { missing_gsn, .. } => {
                // The receiver is missing this chunk. Queue it again, so the next `process_tick` sends it through the
                // same booked path as any other chunk.
                let gsn = Gsn(missing_gsn);
                if let Some(chunk) = self.retransmit.get(gsn).cloned() {
                    self.release(gsn);
                    self.sent_ts.remove(&gsn);
                    if !self.pending.iter().any(|c| c.gsn == gsn) {
                        self.pending.push_front(chunk);
                    }
                }
            }
            ControlMessage::WindowUpdate { right_edge, .. } => {
                self.window_size = right_edge;
            }
            _ => {}
        }
    }

    pub fn pending_len(&self) -> usize { self.pending.len() }

    /// The GSN the next enqueued chunk will be assigned. Used by upper layers to
    /// correlate sent chunks with their message IDs for delivery status.
    pub fn next_gsn(&self) -> Gsn { self.next_gsn }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lanes::simulated_wifi::SimulatedWiFiLane;

    fn lanes_for_test() -> Vec<Box<dyn TransportLane>> {
        vec![
            Box::new(SimulatedWiFiLane::new(1, Duration::from_millis(1), 1_000_000_000.0)),
            Box::new(SimulatedWiFiLane::new(2, Duration::from_millis(1), 1_000_000_000.0)),
        ]
    }

    fn session() -> Session {
        Session::new(SessionId([3; 16]), Ate::new(2, 1 << 20), 64)
    }

    fn booked(lanes: &[Box<dyn TransportLane>]) -> u64 {
        lanes.iter().map(|l| l.metrics().inflight_bytes()).sum()
    }

    /// A sent chunk is booked on its lane, and its bytes come off again once the peer acknowledges it.
    #[tokio::test]
    async fn in_flight_bytes_follow_the_chunks_from_send_to_ack() {
        let mut session = session();
        let mut lanes = lanes_for_test();
        for _ in 0..8 {
            session.enqueue(Bytes::from(vec![7u8; 4096]), 0);
        }
        let sent = session.process_tick(&mut lanes).await;
        assert_eq!(sent.len(), 8);
        assert_eq!(booked(&lanes), 8 * 4096, "every sent chunk is booked on a lane");

        session.handle_control(ControlMessage::Ack {
            session_id: SessionId([3; 16]),
            cumulative_gsn: 8,
        });
        assert_eq!(booked(&lanes), 0, "acknowledged chunks leave their lanes");
    }

    /// A lost chunk is sent again on the next tick, and the resend replaces the lost copy's booking rather than adding
    /// to it. Before this, the resend was returned to a caller that dropped it, so the receiver never got it.
    #[tokio::test]
    async fn a_nacked_chunk_is_sent_again_and_booked_once() {
        let mut session = session();
        let mut lanes = lanes_for_test();
        for _ in 0..4 {
            session.enqueue(Bytes::from(vec![1u8; 1000]), 0);
        }
        session.process_tick(&mut lanes).await;
        session.handle_control(ControlMessage::Nack {
            session_id: SessionId([3; 16]),
            missing_gsn: 2,
            highest_received: 3,
        });
        let resent = session.process_tick(&mut lanes).await;
        let gsns: Vec<Gsn> = resent.iter().map(|(_, gsn)| *gsn).collect();
        assert_eq!(gsns, vec![Gsn(2)], "only the missing chunk goes out again");
        assert_eq!(booked(&lanes), 4 * 1000, "the resend is booked once, in place of the lost copy");
    }
}
