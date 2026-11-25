"""The stream engine: OPEN, DATA, ACK, WINDOW and CLOSE over one session, as pure state.

This follows the stream rules of `docs/PROTOCOL.md` §5 and the reference `crates/transferd-overlay/src/session.rs`:

- an OPEN for a stream id from our own half, or for an id already pending, is refused with `protocol`;
- DATA is delivered in order, acknowledged cumulatively with SACK ranges, and a duplicate is acknowledged again;
  DATA for a stream we do not have is not acknowledged;
- an ACK trims the retransmit buffer; a gap reported by SACK, or three duplicate acknowledgements, counts as a loss;
- a frame unacknowledged for one retransmission timeout (RTO) is resent;
- a sender with no window credit holds its bytes until WINDOW arrives, and never drops them.

The engine does no I/O and reads no clock. The caller passes `now` in milliseconds and sends the frames it returns, so
the rules can be tested without sockets. `stream_session` is the asyncio driver that does the I/O.

Each method returns `(kind, body)` pairs. The caller gives each one a session frame sequence number and seals it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import frames as F
from .mux import Mux, OutFrame

#: The initial retransmission timeout, before any round trip has been measured (ms).
INITIAL_RTO_MS = 400.0
#: The retransmission timeout is never below this (ms).
MIN_RTO_MS = 200.0
#: The retransmission timeout is never above this, backoff included (ms).
MAX_RTO_MS = 5000.0
#: The least the timeout allows beyond the smoothed round trip (ms).
RTO_SLACK_MS = 100.0

#: The most SACK ranges one acknowledgement reports.
SACK_RANGES = 4
#: The most frames one reported range is believed to span.
MAX_SACK_SPAN = 1024
#: Duplicate acknowledgements in a row that show a frame was lost without waiting for its timeout.
DUP_ACKS = 3

Out = List[Tuple[int, object]]


class RtoEstimator:
    """The retransmission timeout, from measured round trips (RFC 6298, with the reference's clamps)."""

    def __init__(self) -> None:
        self.srtt: Optional[float] = None
        self.rttvar: float = 0.0
        self.backoff: int = 0

    def on_rtt(self, sample_ms: float) -> None:
        """Fold in one round-trip measurement, in milliseconds."""
        if self.srtt is None:
            self.srtt = sample_ms
            self.rttvar = sample_ms / 2
        else:
            err = abs(self.srtt - sample_ms)
            self.rttvar = self.rttvar * 3 / 4 + err / 4
            self.srtt = self.srtt * 7 / 8 + sample_ms / 8
        self.backoff = 0

    def rto(self) -> float:
        """How long a frame may stay unacknowledged before it counts as lost, in milliseconds."""
        if self.srtt is None:
            base = INITIAL_RTO_MS
        else:
            base = self.srtt + max(self.rttvar * 4, RTO_SLACK_MS)
        base = min(max(base, MIN_RTO_MS), MAX_RTO_MS)
        return min(base * (2 ** min(self.backoff, 8)), MAX_RTO_MS)

    def back_off(self) -> None:
        """A timeout fired: wait twice as long next time, until a measurement arrives."""
        self.backoff = min(self.backoff + 1, 8)


@dataclass
class _Flight:
    sent_at: float
    retx: bool = False


@dataclass(frozen=True)
class Event:
    """Something the driver must act on, besides the frames to send.

    kind is one of: `open_request` (the peer wants a stream: accept or refuse it), `open_ok` and `open_err`
    (our open was answered), `readable` (bytes are ready to read), `closed` (the peer closed the stream).
    """

    kind: str
    stream: int
    service: str = ""
    code: str = ""
    reason: str = ""


class StreamEngine:
    """The stream tables and rules for one session.

    `odd` is which half of the id space this end allocates from (the two ends of a session must differ).
    `node_id` is our node id, which an OPEN carries.
    """

    def __init__(self, *, odd: bool = True, node_id: str = "") -> None:
        self.node_id = node_id
        self.mux = Mux(odd=odd)
        self.rto = RtoEstimator()
        self._awaiting: Dict[int, str] = {}
        self._pending_opens: Dict[int, str] = {}
        self._backlog: Dict[int, bytearray] = {}
        self._fin_wanted: Dict[int, bool] = {}
        self._fin_sent: Dict[int, bool] = {}
        self._inflight: Dict[Tuple[int, int], _Flight] = {}
        self._last_ack: Dict[int, float] = {}
        self._dup_acks: Dict[int, Tuple[int, int]] = {}
        self._high_sack: Dict[int, int] = {}
        self._recover: Dict[int, int] = {}

    # ----- our side: opening, accepting, writing, reading, closing -----

    def open(self, service: str, now: float) -> Tuple[int, Out]:
        """Open a stream to one of the peer's services. Returns the id and the OPEN to send."""
        sid = self.mux.open(service)
        self._awaiting[sid] = service
        return sid, [(F.OPEN, F.Open(stream=sid, service=service, node_id=self.node_id))]

    def accept(self, sid: int, now: float) -> Out:
        """Accept a stream the peer asked for, after an `open_request` event."""
        service = self._pending_opens.pop(sid)
        self.mux.accept(sid, service)
        return [(F.OPEN_OK, F.OpenOk(stream=sid, route=""))]

    def refuse(self, sid: int, code: str, reason: str) -> Out:
        """Refuse a stream the peer asked for. `code` is one of the OPEN_ERR codes."""
        self._pending_opens.pop(sid, None)
        return [(F.OPEN_ERR, F.OpenErr(stream=sid, code=code, reason=reason))]

    def write(self, sid: int, data: bytes, fin: bool, now: float) -> Out:
        """Queue bytes on a stream and send what the window allows. The rest waits for WINDOW."""
        if self.mux.send_side(sid) is None:
            raise KeyError(f"no stream {sid}")
        self._backlog.setdefault(sid, bytearray()).extend(data)
        if fin:
            self._fin_wanted[sid] = True
        return self._pump(sid, now)

    def read(self, sid: int, now: float) -> Tuple[Optional[bytes], Out]:
        """Take the bytes ready on a stream.

        Returns `(data, out)`: `data` is the bytes, `b""` at the end of the stream, or `None` when nothing is ready
        yet. `out` holds the WINDOW that returns the credit the reader has used.
        """
        recv = self.mux.recv_side(sid)
        if recv is None:
            return b"", []
        taken = recv.take()
        if taken is None:
            return (b"" if recv.finished() else None), []
        granted = recv.window_update()
        out: Out = [(F.WINDOW, F.Window(stream=sid, credit=granted))] if granted > 0 else []
        return taken, out

    def pending(self, sid: int) -> int:
        """Bytes queued on a stream that the window has not let out yet."""
        return len(self._backlog.get(sid, b""))

    def fin_sent(self, sid: int) -> bool:
        """Whether the end of our side of the stream has gone out (after everything queued before it)."""
        return self._fin_sent.get(sid, False)

    def close(self, sid: int, code: str = "closed", reason: str = "") -> Out:
        """Close a stream from our side. The stream's state is dropped at once."""
        self.mux.remove_send(sid)
        self.mux.remove_recv(sid)
        self._forget(sid)
        return [(F.CLOSE, F.Close(stream=sid, code=code, reason=reason))]

    # ----- inbound frames -----

    def on_frame(self, kind: int, body: object, now: float) -> Tuple[Out, List[Event]]:
        """Apply one decoded stream frame. Returns the frames to send and the events to act on."""
        if kind == F.OPEN:
            return self._on_open(body)
        if kind == F.OPEN_OK:
            return self._on_open_ok(body)
        if kind == F.OPEN_ERR:
            return self._on_open_err(body)
        if kind == F.DATA:
            return self._on_data(body)
        if kind == F.ACK:
            return self._on_ack(body, now), []
        if kind == F.WINDOW:
            return self._on_window(body, now), []
        if kind == F.CLOSE:
            return self._on_close(body)
        return [], []

    def _on_open(self, body: F.Open) -> Tuple[Out, List[Event]]:
        if not self.mux.is_peer_stream(body.stream) or body.stream in self._pending_opens:
            return (
                [(F.OPEN_ERR, F.OpenErr(stream=body.stream, code="protocol", reason="that stream id is not yours to open"))],
                [],
            )
        self._pending_opens[body.stream] = body.service
        return [], [Event("open_request", body.stream, service=body.service)]

    def _on_open_ok(self, body: F.OpenOk) -> Tuple[Out, List[Event]]:
        if body.stream in self._awaiting:
            del self._awaiting[body.stream]
            return [], [Event("open_ok", body.stream)]
        return [], []

    def _on_open_err(self, body: F.OpenErr) -> Tuple[Out, List[Event]]:
        events: List[Event] = []
        if body.stream in self._awaiting:
            del self._awaiting[body.stream]
            events.append(Event("open_err", body.stream, code=body.code, reason=body.reason))
        self.mux.remove_send(body.stream)
        self.mux.remove_recv(body.stream)
        self._forget(body.stream)
        return [], events

    def _on_data(self, body: F.Data) -> Tuple[Out, List[Event]]:
        recv = self.mux.recv_side(body.stream)
        if recv is None:
            # Not a stream we have: no acknowledgement, so the sender resends rather than believing it arrived.
            return [], []
        delivered = bool(recv.accept(OutFrame(stream=body.stream, seq=body.seq, payload=body.payload, fin=body.fin)))
        # Cumulative, and sent for a duplicate too: a lost acknowledgement is repaired by the resend it causes.
        ack = F.Ack(stream=body.stream, seq=recv.next_expected(), sack=recv.sack_ranges(SACK_RANGES))
        # A FIN-only frame delivers no bytes but still ends the stream, so a reader must hear about it too.
        events = [Event("readable", body.stream)] if (delivered or body.fin) else []
        return [(F.ACK, ack)], events

    def _on_ack(self, body: F.Ack, now: float) -> Out:
        stream, nxt = body.stream, body.seq
        send = self.mux.send_side(stream)
        if send is not None:
            send.ack_below(nxt)
        self._last_ack[stream] = now

        keys = sorted(k for k in self._inflight if k[0] == stream and k[1] < nxt)
        cumulative = len(keys)
        high: Optional[int] = None
        for frm, to in body.sack:
            to = min(to, frm + MAX_SACK_SPAN)
            if frm < nxt or frm >= to:
                continue  # a range is the peer's word: bound what it can make us walk
            keys.extend(sorted(k for k in self._inflight if k[0] == stream and frm <= k[1] < to))
            high = to - 1 if high is None else max(high, to - 1)

        # A round trip is measured from the newest frame this acknowledgement covers, and only when none of
        # them was resent (the acknowledgement could be for either copy).
        sample: Optional[float] = None
        resent = False
        for key in keys:
            flight = self._inflight.pop(key, None)
            if flight is None:
                continue
            resent = resent or flight.retx
            sample = now - flight.sent_at
        if sample is not None and not resent:
            self.rto.on_rtt(sample)

        if high is not None:
            self._high_sack[stream] = max(self._high_sack.get(stream, 0), high)
        if stream in self._high_sack and self._high_sack[stream] < nxt:
            del self._high_sack[stream]

        out: Out = []
        if stream in self._recover and nxt >= self._recover[stream]:
            del self._recover[stream]
        elif cumulative > 0 and stream in self._recover:
            # A partial acknowledgement: what it stops at was lost along with the frame just repaired.
            key = (stream, nxt)
            if key in self._inflight and not self._inflight[key].retx:
                out += self._mark_lost(key, now)

        # Frames below the highest one the peer has, older than a round trip and a quarter: they went out first
        # and did not arrive. A frame that was resent waits twice as long, since its resend may still be on its way.
        if stream in self._high_sack:
            top = self._high_sack[stream]
            slowest = self.rto.srtt or 0.0
            wait = slowest + slowest / 4
            behind = [
                k
                for k, f in self._inflight.items()
                if k[0] == stream and k[1] < top and (now - f.sent_at) > (wait * 2 if f.retx else wait)
            ]
            for key in sorted(behind):
                out += self._mark_lost(key, now)

        # The same acknowledgement again and again: a frame after the gap keeps arriving while `nxt` does not.
        prev = self._dup_acks.get(stream, (nxt, 0))
        if prev[0] != nxt or cumulative > 0:
            self._dup_acks[stream] = (nxt, 0)
        else:
            count = prev[1] + 1
            self._dup_acks[stream] = (nxt, count)
            if count == DUP_ACKS:
                key = (stream, nxt)
                flight = self._inflight.get(key)
                if flight is not None and (now - flight.sent_at) > (self.rto.srtt or 0.0):
                    out += self._mark_lost(key, now)
        return out

    def _on_window(self, body: F.Window, now: float) -> Out:
        send = self.mux.send_side(body.stream)
        if send is not None:
            send.grant(body.credit)
        return self._pump(body.stream, now)

    def _on_close(self, body: F.Close) -> Tuple[Out, List[Event]]:
        self._pending_opens.pop(body.stream, None)
        self.mux.remove_send(body.stream)
        self._forget(body.stream)
        recv = self.mux.recv_side(body.stream)
        if recv is not None:
            recv.close()
        return [], [Event("closed", body.stream, code=body.code, reason=body.reason)]

    # ----- timers -----

    def tick(self, now: float) -> Out:
        """Resend every frame that has been unacknowledged for a retransmission timeout."""
        rto = self.rto.rto()
        due: List[Tuple[int, int]] = []
        head: Optional[int] = None
        for key in sorted(self._inflight):
            stream, _ = key
            is_head = head != stream
            head = stream
            flight = self._inflight[key]
            last = self._last_ack.get(stream)
            heard = last is not None and last > flight.sent_at and now - last < rto
            if now - flight.sent_at >= rto and (is_head or not heard):
                due.append(key)
        out: Out = []
        for key in due:
            out += self._mark_lost(key, now)
        if due:
            self.rto.back_off()
        return out

    def next_deadline(self) -> Optional[float]:
        """The earliest time `tick` will have something to resend, or None when nothing is in flight."""
        if not self._inflight:
            return None
        rto = self.rto.rto()
        return min(f.sent_at for f in self._inflight.values()) + rto

    # ----- internals -----

    def _pump(self, sid: int, now: float) -> Out:
        send = self.mux.send_side(sid)
        if send is None:
            return []
        out: Out = []
        data = self._backlog.get(sid)
        if data:
            # The window takes min(credit, bytes) in total, so the stream's end can ride on the last frame only
            # when everything fits.
            fin_now = self._fin_wanted.get(sid, False) and len(data) <= send.credit()
            frames = send.frame(bytes(data), fin_now)
            del data[: sum(len(f.payload) for f in frames)]
        elif self._fin_wanted.get(sid, False) and not self._fin_sent.get(sid, False):
            frames = send.frame(b"", True)
        else:
            return out
        for f in frames:
            self._inflight[(sid, f.seq)] = _Flight(sent_at=now)
            if f.fin:
                self._fin_sent[sid] = True
            out.append((F.DATA, F.Data(stream=sid, seq=f.seq, fin=f.fin, payload=f.payload)))
        return out

    def _mark_lost(self, key: Tuple[int, int], now: float) -> Out:
        """A frame is lost: resend it now, with the window narrowed to the frames still in flight behind it."""
        if self._inflight.pop(key, None) is None:
            return []
        stream, seq = key
        ahead = [s for (st, s) in self._inflight if st == stream]
        newest = max(ahead) if ahead else seq
        self._recover[stream] = max(self._recover.get(stream, 0), newest + 1)
        send = self.mux.send_side(stream)
        frame = send.unacked_frame(seq) if send is not None else None
        if frame is None:
            return []
        self._inflight[key] = _Flight(sent_at=now, retx=True)
        return [(F.DATA, F.Data(stream=stream, seq=frame.seq, fin=frame.fin, payload=frame.payload))]

    def _forget(self, sid: int) -> None:
        for key in [k for k in self._inflight if k[0] == sid]:
            del self._inflight[key]
        self._backlog.pop(sid, None)
        self._fin_wanted.pop(sid, None)
        self._fin_sent.pop(sid, None)
        self._dup_acks.pop(sid, None)
        self._recover.pop(sid, None)
        self._last_ack.pop(sid, None)
        self._high_sack.pop(sid, None)
        self._awaiting.pop(sid, None)
