"""Per-route congestion control and retransmission timing.

Mirrors `crates/transferd-overlay/src/cc.rs`. One `RouteCc` per route of a session. It is pure state:
no sockets and no timers. The caller passes the clock, in seconds from any fixed origin.

* RTT and RTO as in RFC 6298: a smoothed RTT and its variance from ACK timing, with
  `rto = srtt + max(4 * rttvar, 100 ms)`, clamped to [`MIN_RTO`, `MAX_RTO`] and doubled on each timeout
  until a fresh measurement arrives.
* Window in bytes in flight, NewReno style: slow start from `INITIAL_FRAMES` frames, then one frame per
  round trip, and cut to 0.7 on loss.
* Pacing: a window is spread over a round trip instead of leaving as one burst.
"""

from __future__ import annotations

import math
from typing import Optional

from .mux import MAX_FRAME

#: What a data frame costs on the wire beyond its payload: the data header, the seal, the relay framing and
#: its padding (a full frame is one 16 KiB relay datagram).
FRAME_OVERHEAD = 192

#: The size one full frame counts for in the window.
MSS = MAX_FRAME + FRAME_OVERHEAD

#: The window a route starts with, in frames.
INITIAL_FRAMES = 10

#: The window never shrinks below this, in frames, so a lossy route still moves.
MIN_FRAMES = 2

#: The window never grows beyond this.
MAX_CWND = 64 * 1024 * 1024

#: The retransmission timeout before any round trip has been measured (seconds).
INITIAL_RTO = 0.400

#: The retransmission timeout never goes below this (seconds).
MIN_RTO = 0.200

#: The least the timeout allows beyond the smoothed round trip (seconds).
RTO_SLACK = 0.100

#: The retransmission timeout never goes above this, backoff included (seconds).
MAX_RTO = 5.0

#: How far ahead of the pacing clock a send is still allowed (seconds).
PACE_SLACK = 0.002

#: How far the pacing clock may fall behind real time before the lost time stops being made up (seconds).
PACE_CREDIT = 0.020


def cost(payload: int) -> int:
    """The wire cost of a data frame with `payload` bytes."""
    return payload + FRAME_OVERHEAD


class RouteCc:
    """Congestion and timing state for one route."""

    def __init__(self) -> None:
        self._srtt: Optional[float] = None
        self._rttvar = 0.0
        self._backoff = 0
        self._cwnd = INITIAL_FRAMES * MSS
        self._ssthresh = math.inf
        self._inflight = 0
        self._credit = 0
        self._next_send: Optional[float] = None
        self._last_cut: Optional[float] = None
        self._sent_bytes = 0
        self._retx_bytes = 0

    # ----- measurements -------------------------------------------------------------------------

    def on_rtt(self, sample: float) -> None:
        """Fold in a round-trip measurement (RFC 6298)."""
        if self._srtt is None:
            self._srtt = sample
            self._rttvar = sample / 2
        else:
            err = abs(self._srtt - sample)
            self._rttvar = self._rttvar * 3 / 4 + err / 4
            self._srtt = self._srtt * 7 / 8 + sample / 8
        self._backoff = 0

    @property
    def srtt(self) -> Optional[float]:
        """The smoothed round-trip time in seconds, once one has been measured."""
        return self._srtt

    def rto(self) -> float:
        """How long a frame may stay unacknowledged on this route before it counts as lost (seconds)."""
        if self._srtt is None:
            base = INITIAL_RTO
        else:
            base = self._srtt + max(self._rttvar * 4, RTO_SLACK)
        base = min(max(base, MIN_RTO), MAX_RTO)
        return min(base * (2 ** min(self._backoff, 8)), MAX_RTO)

    def back_off(self) -> None:
        """A timeout fired: wait twice as long next time, until a measurement arrives."""
        self._backoff = min(self._backoff + 1, 8)

    # ----- window -------------------------------------------------------------------------------

    @property
    def cwnd(self) -> int:
        """The window, in bytes."""
        return self._cwnd

    @property
    def in_flight(self) -> int:
        """Bytes sent on this route and not yet acknowledged or given up on."""
        return self._inflight

    @property
    def sent_bytes(self) -> int:
        """Payload bytes sent on this route, resends included."""
        return self._sent_bytes

    @property
    def retx_bytes(self) -> int:
        """Payload bytes that were resends."""
        return self._retx_bytes

    def has_room(self, frame_cost: int) -> bool:
        """Whether a frame costing `frame_cost` may go out now as far as the window is concerned. A route
        with nothing in flight always takes one, so a window can never deadlock the route."""
        return self._inflight == 0 or self._inflight + frame_cost <= self._cwnd

    def pace_wait(self, now: float) -> Optional[float]:
        """When pacing allows the next send, or None when it may go now."""
        at = self._next_send
        if at is None or at <= now + PACE_SLACK:
            return None
        return at - PACE_SLACK

    def on_sent(self, frame_cost: int, payload: int, retx: bool, now: float) -> None:
        """A frame went out."""
        self._inflight += frame_cost
        self._sent_bytes += payload
        if retx:
            self._retx_bytes += payload
        if self._srtt is not None:
            # A window per round trip, twice as fast in slow start so the pacing does not cap the probing.
            gain = 2.0 if self._cwnd < self._ssthresh else 1.0
            rate = self._cwnd * gain / max(self._srtt, 0.00005)
            gap = frame_cost / rate
            # A timer that fires late leaves the pacing behind by up to PACE_CREDIT, made up at once.
            floor = now - PACE_CREDIT
            base = now if self._next_send is None else max(self._next_send, floor)
            self._next_send = base + gap

    def on_acked(self, nbytes: int, window_limited: bool) -> None:
        """`nbytes` were acknowledged. `window_limited` says the sender was held back by this window when the
        acknowledgement came, so an idle route does not grow a window it never uses."""
        self._inflight = max(0, self._inflight - nbytes)
        if not window_limited:
            return
        if self._cwnd < self._ssthresh:
            self._cwnd = min(self._cwnd + nbytes, MAX_CWND)
        else:
            self._credit += nbytes
            if self._credit >= self._cwnd:
                self._credit -= self._cwnd
                self._cwnd = min(self._cwnd + MSS, MAX_CWND)

    def on_lost(self, nbytes: int, sent_at: float, now: float) -> None:
        """Frames were given up on (a timeout, or a gap the receiver reported). Cuts the window to 0.7, at most
        once per window's worth of losses."""
        self._inflight = max(0, self._inflight - nbytes)
        if self._last_cut is not None and sent_at <= self._last_cut:
            return
        self._ssthresh = max(self._cwnd * 7 // 10, MIN_FRAMES * MSS)
        self._cwnd = int(self._ssthresh)
        self._credit = 0
        self._last_cut = now

    def release(self, nbytes: int) -> None:
        """Bytes leave the books without being acknowledged or lost (the stream was closed)."""
        self._inflight = max(0, self._inflight - nbytes)
