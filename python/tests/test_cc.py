"""Congestion control and retransmission timing, ported from the reference's unit tests in `cc.rs`."""

from transferd import cc
from transferd.cc import INITIAL_FRAMES, INITIAL_RTO, MAX_RTO, MIN_FRAMES, MSS, RouteCc
from transferd.mux import MAX_FRAME


def ms(n: float) -> float:
    return n / 1000.0


def test_the_timeout_starts_at_the_old_fixed_value_and_follows_the_measured_round_trip():
    c = RouteCc()
    assert c.rto() == INITIAL_RTO
    for _ in range(40):
        c.on_rtt(ms(80))
    fast = c.rto()
    assert fast < ms(250), f"an 80 ms path times out well under 400 ms: {fast}"
    for _ in range(40):
        c.on_rtt(ms(600))
    assert c.rto() > ms(600), "a 600 ms path waits longer than its round trip"


def test_each_timeout_doubles_the_wait_until_a_measurement_resets_it():
    c = RouteCc()
    c.on_rtt(ms(100))
    base = c.rto()
    c.back_off()
    assert abs(c.rto() - base * 2) < 1e-12
    for _ in range(20):
        c.back_off()
    assert c.rto() == MAX_RTO, "the backoff is capped"
    c.on_rtt(ms(100))
    assert c.rto() < base * 2, "a measurement ends the backoff"


def test_slow_start_doubles_per_round_trip_then_avoidance_adds_one_frame():
    c = RouteCc()
    start = c.cwnd
    assert start == INITIAL_FRAMES * MSS
    c._inflight = start
    c.on_acked(start, True)
    assert c.cwnd == start * 2, "a window acknowledged doubles the window"

    now = 10.0
    c._inflight = c.cwnd
    c.on_lost(MSS, now, now)
    after_cut = c.cwnd
    assert after_cut == start * 2 * 7 // 10, "cut to 0.7 of the window"
    c._inflight = after_cut
    c.on_acked(after_cut, True)
    assert c.cwnd == after_cut + MSS, "one frame per window acknowledged"


def test_losses_from_one_window_cut_it_once():
    c = RouteCc()
    t0 = 10.0
    now = t0 + 0.5
    c._inflight = 5 * MSS
    c.on_lost(MSS, t0, now)
    cut = c.cwnd
    c.on_lost(MSS, t0, now + 0.010)
    assert c.cwnd == cut, "the second loss was sent before the cut"
    c.on_lost(MSS, now + 0.020, now + 0.6)
    assert c.cwnd < cut, "a loss of a frame sent after the cut cuts again"
    for _ in range(30):
        c.on_lost(MSS, now + 0.7, now + 0.8)
        c._last_cut = None
    assert c.cwnd >= MIN_FRAMES * MSS, "never below the floor"


def test_an_idle_route_does_not_grow_its_window():
    c = RouteCc()
    start = c.cwnd
    c._inflight = MSS
    c.on_acked(MSS, False)
    assert c.cwnd == start


def test_a_route_with_nothing_in_flight_always_takes_a_frame():
    c = RouteCc()
    c._cwnd = MSS // 2
    assert c.has_room(MSS)
    c._inflight = 1
    assert not c.has_room(MSS)


def test_pacing_spreads_a_window_over_the_round_trip():
    c = RouteCc()
    c.on_rtt(ms(100))
    now = 5.0
    waited = None
    for i in range(INITIAL_FRAMES):
        at = c.pace_wait(now)
        if at is not None:
            waited = (i, at)
            break
        c.on_sent(MSS, MAX_FRAME, False, now)
    assert waited is not None, "a window is not sent as one burst"
    i, at = waited
    assert i >= 1, "a first frame goes at once"
    assert at - now < ms(100), "and the wait is a fraction of a round trip"


def test_the_wire_cost_adds_the_overhead_to_the_payload():
    assert cc.cost(100) == 100 + cc.FRAME_OVERHEAD
    assert MSS == MAX_FRAME + cc.FRAME_OVERHEAD
