use crate::types::Gsn;
use std::sync::atomic::Ordering;

/// Adaptive Transfer Engine — Earliest Completion First with Reorder Guard (ECF-RG).
///
/// Picks the lane that delivers the next GSN soonest while ensuring the reorder gap
/// never exceeds `reorder_guard_limit`, preventing receiver-buffer deadlock.
pub struct Ate {
    pub lane_count: usize,
    /// Estimated completion times per lane — populated by the tick loop (Phase 4).
    #[allow(dead_code)]
    completion_times: Vec<f64>,
    reorder_guard_limit: u64,
}

impl Ate {
    pub fn new(lane_count: usize, gap_limit: u64) -> Self {
        Self {
            lane_count,
            completion_times: vec![f64::MAX; lane_count],
            reorder_guard_limit: gap_limit,
        }
    }

    /// Returns the index of the preferred lane for `gsn`, or None if no lane is ready.
    pub fn select_lane(
        &self,
        gsn: Gsn,
        current_base: Gsn,
        lane_metrics: &[&crate::transport::LaneMetrics],
        lane_capacities: &[usize],
    ) -> Option<usize> {
        if gsn.distance(current_base) >= self.reorder_guard_limit {
            return None;
        }

        let mut best = None;
        let mut min_ct = f64::MAX;

        for (idx, (metrics, &cap)) in lane_metrics.iter().zip(lane_capacities.iter()).enumerate() {
            if cap == 0 { continue; }
            let rtt = metrics.rtt_ms.load(Ordering::Relaxed) as f64 / 1_000_000.0; // ms→s
            let bw = metrics.bandwidth_bps.load(Ordering::Relaxed) as f64;
            let in_flight = metrics.active_chunks.load(Ordering::Relaxed) as f64;
            let ct = rtt + in_flight / bw.max(1.0);
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
        lane_metrics: &[&crate::transport::LaneMetrics],
        lane_capacities: &[usize],
    ) -> Option<(usize, usize)> {
        if gsn.distance(current_base) >= self.reorder_guard_limit {
            return None;
        }
        let mut ranked: Vec<(usize, f64)> = lane_metrics
            .iter()
            .zip(lane_capacities.iter())
            .enumerate()
            .filter(|(_, (_, &cap))| cap > 0)
            .map(|(idx, (metrics, _))| {
                let rtt = metrics.rtt_ms.load(Ordering::Relaxed) as f64 / 1_000_000.0;
                let bw  = metrics.bandwidth_bps.load(Ordering::Relaxed) as f64;
                let inf = metrics.active_chunks.load(Ordering::Relaxed) as f64;
                (idx, rtt + inf / bw.max(1.0))
            })
            .collect();
        ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        if ranked.len() >= 2 {
            Some((ranked[0].0, ranked[1].0))
        } else {
            None
        }
    }

    /// Returns the index of the lowest-RTT lane (used for retransmit scheduling).
    pub fn fastest_lane(&self, lane_metrics: &[&crate::transport::LaneMetrics]) -> Option<usize> {
        lane_metrics
            .iter()
            .enumerate()
            .min_by_key(|(_, m)| m.rtt_ms.load(Ordering::Relaxed))
            .map(|(i, _)| i)
    }
}
