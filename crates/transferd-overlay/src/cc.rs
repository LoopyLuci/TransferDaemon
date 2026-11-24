//! Per-route congestion control and retransmission timing.
//!
//! One [`RouteCc`] per route of a session. It is pure state (no sockets, no timers, the caller
//! passes the clock), so the arithmetic is directly testable.
//!
//! * **RTT and RTO** as in RFC 6298: a smoothed RTT and its variance from ACK timing (and from
//!   probe round trips), `rto = srtt + max(4 * rttvar, 100 ms)` between [`MIN_RTO`] and [`MAX_RTO`], doubled
//!   on each timeout until a fresh measurement arrives.
//! * **Window** in bytes in flight, NewReno style: slow start from [`INITIAL_FRAMES`] frames,
//!   additive increase of one frame per round trip after that, cut to 0.7 on loss (CUBIC's factor). NewReno (AIMD,
//!   counted in bytes) was picked over CUBIC because the overlay's paths are short and its
//!   frames are large, where CUBIC's advantage on long fat pipes does not show, and AIMD with
//!   pacing is small enough to reason about and test exactly.
//! * **Pacing**: a window is spread over a round trip instead of leaving as one burst; the
//!   burst is what overflowed a 64 KiB socket buffer in the first place.

use std::time::{Duration, Instant};

use crate::mux::MAX_FRAME;

/// What a data frame costs on the wire beyond its payload: the data header, the seal, the relay's
/// framing and its padding (a full frame is one 16 KiB relay datagram).
pub const FRAME_OVERHEAD: u64 = 192;

/// The size one full frame counts for in the window.
pub const MSS: u64 = MAX_FRAME as u64 + FRAME_OVERHEAD;

/// The window a route starts with, in frames.
pub const INITIAL_FRAMES: u64 = 10;

/// The window never shrinks below this, in frames, so a lossy route still moves.
pub const MIN_FRAMES: u64 = 2;

/// The window never grows beyond this: far past anything a stream window can fill.
const MAX_CWND: u64 = 64 * 1024 * 1024;

/// The retransmission timeout before any round trip has been measured: the old fixed value.
pub const INITIAL_RTO: Duration = Duration::from_millis(400);

/// The retransmission timeout never goes below this.
pub const MIN_RTO: Duration = Duration::from_millis(200);

/// The least the timeout allows beyond the smoothed round trip (RFC 6298's clock granularity,
/// widened): a window growing past the path's capacity builds a queue and the round trip rises
/// faster than the estimate follows, and a timeout then would be a false alarm.
const RTO_SLACK: Duration = Duration::from_millis(100);

/// The retransmission timeout never goes above this, backoff included.
pub const MAX_RTO: Duration = Duration::from_secs(5);

/// How far ahead of the pacing clock a send is still allowed: a couple of frames' burst at
/// low rates, effectively no pacing at loopback speed.
const PACE_SLACK: Duration = Duration::from_millis(2);

/// How far the pacing clock may fall behind real time before the lost time stops being made up.
const PACE_CREDIT: Duration = Duration::from_millis(20);

/// The wire cost of a data frame with `payload` bytes.
pub fn cost(payload: usize) -> u64 {
    payload as u64 + FRAME_OVERHEAD
}

/// Congestion and timing state for one route.
#[derive(Debug, Clone)]
pub struct RouteCc {
    srtt: Option<Duration>,
    rttvar: Duration,
    backoff: u32,
    cwnd: u64,
    ssthresh: u64,
    inflight: u64,
    /// Bytes acknowledged in congestion avoidance towards the next frame of growth.
    credit: u64,
    next_send: Option<Instant>,
    /// When the window was last cut; losses of frames sent before that do not cut it again.
    last_cut: Option<Instant>,
    /// Payload bytes sent on this route, and how many of those were resends.
    sent_bytes: u64,
    retx_bytes: u64,
}

impl Default for RouteCc {
    fn default() -> Self {
        Self {
            srtt: None,
            rttvar: Duration::ZERO,
            backoff: 0,
            cwnd: INITIAL_FRAMES * MSS,
            ssthresh: u64::MAX,
            inflight: 0,
            credit: 0,
            next_send: None,
            last_cut: None,
            sent_bytes: 0,
            retx_bytes: 0,
        }
    }
}

impl RouteCc {
    /// Fold in a round-trip measurement (RFC 6298).
    pub fn on_rtt(&mut self, sample: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(sample);
                self.rttvar = sample / 2;
            }
            Some(srtt) => {
                let err = srtt.abs_diff(sample);
                self.rttvar = self.rttvar * 3 / 4 + err / 4;
                self.srtt = Some(srtt * 7 / 8 + sample / 8);
            }
        }
        self.backoff = 0;
    }

    /// The smoothed round-trip time, once one has been measured.
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// How long a frame may stay unacknowledged on this route before it counts as lost.
    pub fn rto(&self) -> Duration {
        let base = match self.srtt {
            None => INITIAL_RTO,
            Some(srtt) => srtt + (self.rttvar * 4).max(RTO_SLACK),
        };
        let base = base.clamp(MIN_RTO, MAX_RTO);
        (base * 2u32.saturating_pow(self.backoff.min(8))).min(MAX_RTO)
    }

    /// A timeout fired: wait twice as long next time, until a measurement arrives.
    pub fn back_off(&mut self) {
        self.backoff = (self.backoff + 1).min(8);
    }

    /// The window, in bytes.
    pub fn cwnd(&self) -> u64 {
        self.cwnd
    }

    /// Bytes sent on this route and not yet acknowledged or given up on.
    pub fn in_flight(&self) -> u64 {
        self.inflight
    }

    /// Payload bytes sent on this route, resends included.
    pub fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    /// Payload bytes that were resends.
    pub fn retx_bytes(&self) -> u64 {
        self.retx_bytes
    }

    /// Whether a frame costing `cost` may go out now as far as the window is concerned. A route
    /// with nothing in flight always takes one, so a window can never deadlock the route.
    pub fn has_room(&self, cost: u64) -> bool {
        self.inflight == 0 || self.inflight + cost <= self.cwnd
    }

    /// How long until pacing allows the next send, or `None` when it may go now.
    pub fn pace_wait(&self, now: Instant) -> Option<Instant> {
        let at = self.next_send?;
        (at > now + PACE_SLACK).then_some(at - PACE_SLACK)
    }

    /// A frame went out.
    pub fn on_sent(&mut self, cost: u64, payload: usize, retx: bool, now: Instant) {
        self.inflight += cost;
        self.sent_bytes += payload as u64;
        if retx {
            self.retx_bytes += payload as u64;
        }
        if let Some(srtt) = self.srtt {
            // A window per round trip, twice as fast in slow start so the pacing does not cap
            // the probing for bandwidth.
            let gain = if self.cwnd < self.ssthresh { 2.0 } else { 1.0 };
            let rate = self.cwnd as f64 * gain / srtt.as_secs_f64().max(0.000_05);
            let gap = Duration::from_secs_f64(cost as f64 / rate);
            // A timer that fires late (coarse clocks do) leaves the pacing behind by up to
            // PACE_CREDIT, which is made up at once so the average rate holds.
            let floor = now.checked_sub(PACE_CREDIT).unwrap_or(now);
            let base = self.next_send.map_or(now, |t| t.max(floor));
            self.next_send = Some(base + gap);
        }
    }

    /// `bytes` were acknowledged. `window_limited` says the sender was held back by this window
    /// when the acknowledgement came, so an idle route does not grow a window it never uses.
    pub fn on_acked(&mut self, bytes: u64, window_limited: bool) {
        self.inflight = self.inflight.saturating_sub(bytes);
        if !window_limited {
            return;
        }
        if self.cwnd < self.ssthresh {
            self.cwnd = (self.cwnd + bytes).min(MAX_CWND);
        } else {
            self.credit += bytes;
            if self.credit >= self.cwnd {
                self.credit -= self.cwnd;
                self.cwnd = (self.cwnd + MSS).min(MAX_CWND);
            }
        }
    }

    /// Frames were given up on (a timeout, or a gap the receiver reported). Cuts the window to 0.7,
    /// at most once per window's worth of losses.
    pub fn on_lost(&mut self, bytes: u64, sent_at: Instant, now: Instant) {
        self.inflight = self.inflight.saturating_sub(bytes);
        if self.last_cut.is_some_and(|cut| sent_at <= cut) {
            return;
        }
        self.ssthresh = (self.cwnd * 7 / 10).max(MIN_FRAMES * MSS);
        self.cwnd = self.ssthresh;
        self.credit = 0;
        self.last_cut = Some(now);
    }

    /// Bytes leave the books without being acknowledged or lost (the stream was closed).
    pub fn release(&mut self, bytes: u64) {
        self.inflight = self.inflight.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn the_timeout_starts_at_the_old_fixed_value_and_follows_the_measured_round_trip() {
        let mut cc = RouteCc::default();
        assert_eq!(cc.rto(), INITIAL_RTO);
        for _ in 0..40 {
            cc.on_rtt(ms(80));
        }
        let fast = cc.rto();
        assert!(
            fast < ms(250),
            "an 80 ms path times out well under 400 ms: {fast:?}"
        );
        for _ in 0..40 {
            cc.on_rtt(ms(600));
        }
        assert!(
            cc.rto() > ms(600),
            "a 600 ms path waits longer than its round trip"
        );
    }

    #[test]
    fn each_timeout_doubles_the_wait_until_a_measurement_resets_it() {
        let mut cc = RouteCc::default();
        cc.on_rtt(ms(100));
        let base = cc.rto();
        cc.back_off();
        assert_eq!(cc.rto(), base * 2);
        for _ in 0..20 {
            cc.back_off();
        }
        assert_eq!(cc.rto(), MAX_RTO, "the backoff is capped");
        cc.on_rtt(ms(100));
        assert!(cc.rto() < base * 2, "a measurement ends the backoff");
    }

    #[test]
    fn slow_start_doubles_per_round_trip_then_avoidance_adds_one_frame() {
        let mut cc = RouteCc::default();
        let start = cc.cwnd();
        assert_eq!(start, INITIAL_FRAMES * MSS);
        cc.inflight = start;
        cc.on_acked(start, true);
        assert_eq!(
            cc.cwnd(),
            start * 2,
            "a window acknowledged doubles the window"
        );

        let now = Instant::now();
        cc.inflight = cc.cwnd();
        cc.on_lost(MSS, now, now);
        let after_cut = cc.cwnd();
        assert_eq!(after_cut, start * 2 * 7 / 10, "cut to 0.7 of the window");
        cc.inflight = after_cut;
        cc.on_acked(after_cut, true);
        assert_eq!(
            cc.cwnd(),
            after_cut + MSS,
            "one frame per window acknowledged"
        );
    }

    #[test]
    fn losses_from_one_window_cut_it_once() {
        let mut cc = RouteCc::default();
        let t0 = Instant::now();
        let now = t0 + ms(500);
        cc.inflight = 5 * MSS;
        cc.on_lost(MSS, t0, now);
        let cut = cc.cwnd();
        cc.on_lost(MSS, t0, now + ms(10));
        assert_eq!(cc.cwnd(), cut, "the second loss was sent before the cut");
        cc.on_lost(MSS, now + ms(20), now + ms(600));
        assert!(
            cc.cwnd() < cut,
            "a loss of a frame sent after the cut cuts again"
        );
        for _ in 0..30 {
            cc.on_lost(MSS, now + ms(700), now + ms(800));
            cc.last_cut = None;
        }
        assert!(cc.cwnd() >= MIN_FRAMES * MSS, "never below the floor");
    }

    #[test]
    fn an_idle_route_does_not_grow_its_window() {
        let mut cc = RouteCc::default();
        let start = cc.cwnd();
        cc.inflight = MSS;
        cc.on_acked(MSS, false);
        assert_eq!(cc.cwnd(), start);
    }

    #[test]
    fn a_route_with_nothing_in_flight_always_takes_a_frame() {
        let mut cc = RouteCc {
            cwnd: MSS / 2,
            ..RouteCc::default()
        };
        assert!(cc.has_room(MSS));
        cc.inflight = 1;
        assert!(!cc.has_room(MSS));
    }

    #[test]
    fn pacing_spreads_a_window_over_the_round_trip() {
        let mut cc = RouteCc::default();
        cc.on_rtt(ms(100));
        let now = Instant::now();
        let mut waited = None;
        for i in 0..INITIAL_FRAMES {
            if let Some(at) = cc.pace_wait(now) {
                waited = Some((i, at));
                break;
            }
            cc.on_sent(MSS, MAX_FRAME, false, now);
        }
        let (i, at) = waited.expect("a window is not sent as one burst");
        assert!(i >= 1, "a first frame goes at once");
        assert!(
            at - now < ms(100),
            "and the wait is a fraction of a round trip"
        );
    }
}
