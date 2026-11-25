use crate::transport::LaneMetrics;
use crate::types::Gsn;
use std::sync::atomic::Ordering;

/// The time, in seconds, for one lane to deliver a chunk of `chunk_bytes` queued behind the bytes that lane already
/// carries: one round trip, plus the time to push the backlog and the chunk through at the lane's bandwidth.
///
/// The units follow the stores. `rtt_ms` holds microseconds (`LaneMetrics::update_rtt`), so it is divided by 10^6 to
/// get seconds. `bandwidth_bps` holds bits per second (the daemon derives it from byte deltas × 8), so the backlog is
/// converted to bits before it is divided by the bandwidth. A lane with no bandwidth estimate yet divides by one bit
/// per second, so it ranks behind every lane that has one.
pub fn completion_time(metrics: &LaneMetrics, chunk_bytes: u64) -> f64 {
    let rtt_s = metrics.rtt_ms.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let bps = (metrics.bandwidth_bps.load(Ordering::Relaxed) as f64).max(1.0);
    let backlog_bits = (metrics.inflight_bytes() + chunk_bytes) as f64 * 8.0;
    rtt_s + backlog_bits / bps
}

/// Adaptive Transfer Engine — Earliest Completion First with Reorder Guard (ECF-RG).
///
/// Picks the lane that delivers the next GSN soonest while ensuring the reorder gap
/// never exceeds `reorder_guard_limit`, preventing receiver-buffer deadlock.
pub struct Ate {
    pub lane_count: usize,
    reorder_guard_limit: u64,
}

impl Ate {
    pub fn new(lane_count: usize, gap_limit: u64) -> Self {
        Self {
            lane_count,
            reorder_guard_limit: gap_limit,
        }
    }

    /// Returns the index of the preferred lane for `gsn`, or None if no lane is ready.
    ///
    /// `chunk_bytes` is the size of the chunk being placed. Each lane with capacity is scored by
    /// [`completion_time`], so the chunk goes to the lane that would finish it first, given what each lane already
    /// carries. Lanes therefore share the load in proportion to their speed, and a lane with a backlog is passed over.
    pub fn select_lane(
        &self,
        gsn: Gsn,
        current_base: Gsn,
        lane_metrics: &[&LaneMetrics],
        lane_capacities: &[usize],
        chunk_bytes: u64,
    ) -> Option<usize> {
        if gsn.distance(current_base) >= self.reorder_guard_limit {
            return None;
        }

        let mut best = None;
        let mut min_ct = f64::MAX;

        for (idx, (metrics, &cap)) in lane_metrics.iter().zip(lane_capacities.iter()).enumerate() {
            if cap == 0 {
                continue;
            }
            let ct = completion_time(metrics, chunk_bytes);
            if ct < min_ct {
                min_ct = ct;
                best = Some(idx);
            }
        }
        best
    }

    /// Returns the two best lanes (primary, mirror) for redundant QoS sends.
    ///
    /// Returns `None` if fewer than two viable lanes exist.
    pub fn select_two_lanes(
        &self,
        gsn: Gsn,
        current_base: Gsn,
        lane_metrics: &[&LaneMetrics],
        lane_capacities: &[usize],
        chunk_bytes: u64,
    ) -> Option<(usize, usize)> {
        if gsn.distance(current_base) >= self.reorder_guard_limit {
            return None;
        }
        let mut ranked: Vec<(usize, f64)> = lane_metrics
            .iter()
            .zip(lane_capacities.iter())
            .enumerate()
            .filter(|(_, (_, &cap))| cap > 0)
            .map(|(idx, (metrics, _))| (idx, completion_time(metrics, chunk_bytes)))
            .collect();
        ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        if ranked.len() >= 2 {
            Some((ranked[0].0, ranked[1].0))
        } else {
            None
        }
    }

    /// Returns the index of the lowest-RTT lane (used for retransmit scheduling).
    pub fn fastest_lane(&self, lane_metrics: &[&LaneMetrics]) -> Option<usize> {
        lane_metrics
            .iter()
            .enumerate()
            .min_by_key(|(_, m)| m.rtt_ms.load(Ordering::Relaxed))
            .map(|(i, _)| i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lane with `rtt_ms` round trip and `bps` bits per second, already carrying `inflight` bytes.
    fn lane(rtt_ms: u64, bps: u64, inflight: u64) -> LaneMetrics {
        let metrics = LaneMetrics::default();
        metrics.rtt_ms.store(rtt_ms * 1_000, Ordering::Relaxed);
        metrics.bandwidth_bps.store(bps, Ordering::Relaxed);
        if inflight > 0 {
            metrics.on_sent(inflight);
        }
        metrics
    }

    #[test]
    fn completion_time_counts_the_backlog_in_bits_at_the_lane_speed() {
        // 10 ms round trip; 1 MB of backlog at 100 Mbit/s is 8 Mbit, which takes 80 ms.
        let busy = lane(10, 100_000_000, 1_000_000);
        assert!((completion_time(&busy, 0) - 0.09).abs() < 1e-9);
    }

    #[test]
    fn an_idle_lane_beats_a_busy_lane_of_the_same_speed() {
        let busy = lane(10, 100_000_000, 1_000_000);
        let idle = lane(10, 100_000_000, 0);
        let picked = Ate::new(2, 1 << 20).select_lane(Gsn(0), Gsn(0), &[&busy, &idle], &[16, 16], 65_536);
        assert_eq!(picked, Some(1));
    }

    #[test]
    fn a_fast_lane_with_a_small_backlog_beats_a_slow_idle_lane() {
        let fast = lane(10, 100_000_000, 65_536);
        let slow = lane(10, 10_000_000, 0);
        let picked = Ate::new(2, 1 << 20).select_lane(Gsn(0), Gsn(0), &[&fast, &slow], &[16, 16], 65_536);
        assert_eq!(picked, Some(0));
    }

    #[test]
    fn a_lane_without_capacity_is_never_picked() {
        let idle = lane(10, 100_000_000, 0);
        let full = lane(1, 1_000_000_000, 0);
        let picked = Ate::new(2, 1 << 20).select_lane(Gsn(0), Gsn(0), &[&full, &idle], &[0, 16], 1024);
        assert_eq!(picked, Some(1));
    }

    #[test]
    fn two_lanes_are_ranked_by_completion_time() {
        let busy = lane(10, 100_000_000, 1_000_000);
        let idle = lane(10, 100_000_000, 0);
        let slow = lane(50, 100_000_000, 0);
        let pair = Ate::new(3, 1 << 20).select_two_lanes(
            Gsn(0),
            Gsn(0),
            &[&busy, &idle, &slow],
            &[16, 16, 16],
            1024,
        );
        assert_eq!(pair, Some((1, 2)), "the idle lane first, then the next best");
    }
}
