"""The stream multiplexer: many streams over one session, with flow control and in-order delivery.

A port of `crates/transferd-overlay/src/mux.rs`. Every DATA frame carries `(stream, seq)`, so the
receiver can hold frames that arrive out of order and the sender can resend only what is missing.
This module is pure state: no sockets, no timers. `streams` drives it and owns the timing.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

#: The largest payload one data frame carries. A relay pads every datagram to a power of two, so this
#: leaves room for the data header, the seal and the relay's own framing inside 16 KiB.
MAX_FRAME = 16 * 1024 - 192

#: The window a fresh stream starts with, in bytes, in each direction.
DEFAULT_WINDOW = 256 * 1024

#: How many unacknowledged (or out-of-order) frames a stream keeps before it refuses more.
MAX_UNACKED = 256


@dataclass(frozen=True)
class OutFrame:
    """One frame as it travels: which stream, which position, and the bytes."""

    stream: int
    seq: int
    payload: bytes
    #: Set on the last frame of the stream.
    fin: bool = False


@dataclass
class SendSide:
    """The sending half of one stream."""

    id: int
    service: str = ""
    _next_seq: int = 0
    #: Frames sent but not yet acknowledged cumulatively, by sequence number.
    _unacked: Dict[int, OutFrame] = field(default_factory=dict)
    #: Bytes the peer has allowed us to send beyond what it has already received.
    _credit: int = DEFAULT_WINDOW
    #: The highest sequence number the peer acknowledged cumulatively.
    _acked: Optional[int] = None
    #: Bytes sent so far.
    _sent: int = 0
    #: The caller asked to close, but the tail did not fit the window yet.
    _fin_pending: bool = False

    @classmethod
    def with_window(cls, id: int, service: str, window: int) -> "SendSide":
        side = cls(id=id, service=service)
        side._credit = window
        return side

    def credit(self) -> int:
        """Bytes the peer may still take from us before it grants more."""
        return self._credit

    def unacked_frames(self) -> int:
        return len(self._unacked)

    def is_finished(self) -> bool:
        """Whether the end of the stream was asked for and everything sent is acknowledged."""
        return self._fin_pending and not self._unacked

    def fin_sent(self) -> bool:
        """Whether the end of the stream has been framed (it may not be acknowledged yet)."""
        return self._fin_pending

    def frame(self, data: bytes, fin: bool) -> List[OutFrame]:
        """Split `data` into frames the window allows, marking the last one `fin` when asked.

        Returns an empty list when the window is closed: that is the backpressure signal. The bytes
        the window did not take are the caller's to keep (their total is the sum of the payloads).
        """
        out: List[OutFrame] = []
        if not data:
            # The end of the stream on its own: one empty frame, which needs no credit.
            if fin:
                frame = OutFrame(stream=self.id, seq=self._next_seq, payload=b"", fin=True)
                self._next_seq += 1
                self._unacked[frame.seq] = frame
                out.append(frame)
                self._fin_pending = True
            return out

        rest = data
        while True:
            room = min(self._credit, MAX_FRAME, len(rest))
            if room == 0:
                break
            last = room == len(rest)
            chunk, rest = rest[:room], rest[room:]
            self._credit -= room
            self._sent += room
            frame = OutFrame(stream=self.id, seq=self._next_seq, payload=chunk, fin=fin and last)
            self._next_seq += 1
            self._unacked[frame.seq] = frame
            out.append(frame)
            if last:
                break
        if fin:
            # The whole tail fitted, so the stream ends here; otherwise the caller asks again once
            # the peer has granted more credit.
            self._fin_pending = bool(out) and out[-1].fin
        # Bound the retransmit buffer: drop the oldest frames rather than refuse new data.
        while len(self._unacked) > MAX_UNACKED:
            del self._unacked[min(self._unacked)]
        return out

    def ack_below(self, next_expected: int) -> None:
        """Record a cumulative acknowledgement: every frame below `next_expected` has arrived."""
        self._unacked = {seq: f for seq, f in self._unacked.items() if seq >= next_expected}
        if next_expected > 0:
            self._acked = next_expected - 1

    def ack(self, seq: int) -> None:
        self._unacked = {s: f for s, f in self._unacked.items() if s > seq}
        self._acked = seq

    def acked(self) -> Optional[int]:
        return self._acked

    def grant(self, credit: int) -> None:
        """Grant more credit to the sender."""
        self._credit += credit

    def unacked_frame(self, seq: int) -> Optional[OutFrame]:
        return self._unacked.get(seq)

    def retransmit(self) -> List[OutFrame]:
        """Frames still unacknowledged, oldest first."""
        return [self._unacked[s] for s in sorted(self._unacked)]

    def sent(self) -> int:
        return self._sent


@dataclass
class RecvSide:
    """The receiving half of one stream: in-order delivery with a bounded reorder buffer."""

    id: int
    service: str = ""
    window: int = DEFAULT_WINDOW
    #: The next sequence number to deliver.
    _next_seq: int = 0
    #: Frames that arrived early, by sequence number.
    _pending: Dict[int, OutFrame] = field(default_factory=dict)
    #: Delivered bytes waiting for the application to take them.
    _ready: List[bytes] = field(default_factory=list)
    _ready_bytes: int = 0
    #: Bytes delivered in order so far.
    _delivered: int = 0
    #: Bytes the application has taken, against which credit is returned.
    _consumed: int = 0
    #: Credit already handed back to the peer.
    _granted: int = 0
    #: Set once the peer has said this is the last frame.
    _fin: bool = False
    #: Frames refused because the reorder buffer was full.
    _dropped: int = 0
    #: Why the stream ended with an error rather than the end (see `abort`).
    _aborted: Optional[str] = None

    @classmethod
    def with_window(cls, id: int, service: str, window: int) -> "RecvSide":
        return cls(id=id, service=service, window=window)

    def accept(self, frame: OutFrame) -> List[bytes]:
        """Accept a frame and return the chunks that are now deliverable, in order.

        A frame already delivered is ignored (a duplicate); a frame after the end of the stream is
        ignored; a frame beyond the reorder buffer is refused rather than buffered without bound.
        """
        if frame.seq < self._next_seq or self._fin:
            return []
        if frame.seq not in self._pending and len(self._pending) >= MAX_UNACKED:
            self._dropped += 1
            return []
        self._pending[frame.seq] = frame
        out: List[bytes] = []
        while self._next_seq in self._pending:
            frame = self._pending.pop(self._next_seq)
            self._next_seq += 1
            self._fin = frame.fin
            if not frame.payload:
                continue
            self._delivered += len(frame.payload)
            self._ready_bytes += len(frame.payload)
            out.append(frame.payload)
            self._ready.append(frame.payload)
        return out

    def take(self) -> Optional[bytes]:
        """Everything the application has not read yet, as one buffer, or None when nothing is ready."""
        if not self._ready:
            return None
        merged = b"".join(self._ready)
        self._ready = []
        self._ready_bytes = 0
        self._consumed += len(merged)
        return merged

    def in_use(self) -> int:
        """Bytes delivered to the application that it has not taken credit for yet."""
        return max(0, self._delivered - self._consumed)

    def credit(self) -> int:
        """How much credit the peer may still use."""
        return max(0, self.window - self.in_use())

    def granted(self) -> int:
        return self._granted

    def window_update(self) -> int:
        """How much credit to hand the peer now: everything read since the last call."""
        delta = max(0, self._consumed - self._granted)
        self._granted = self._consumed
        return delta

    def sack_ranges(self, max_ranges: int) -> List[Tuple[int, int]]:
        """Ranges `[from, to)` of frames beyond the first gap that have arrived, lowest first."""
        out: List[Tuple[int, int]] = []
        for seq in sorted(self._pending):
            if out and out[-1][1] == seq:
                out[-1] = (out[-1][0], seq + 1)
            elif len(out) == max_ranges:
                break
            else:
                out.append((seq, seq + 1))
        return out

    def next_expected(self) -> int:
        """The next sequence number expected: everything below it has arrived."""
        return self._next_seq

    def ack_seq(self) -> int:
        return max(0, self._next_seq - 1)

    def delivered_upto(self) -> int:
        return max(0, self._next_seq - 1)

    def dropped(self) -> int:
        return self._dropped

    def finished(self) -> bool:
        """Whether the peer signalled the end of the stream."""
        return self._fin

    def close(self) -> None:
        """Mark the stream closed by this side too."""
        self._fin = True
        self._pending.clear()

    def abort(self, why: str) -> None:
        """End the stream with an error: the peer reset it, or it left frames missing. Bytes already delivered are
        still read first; after them the reader gets `why`, not the end."""
        self._fin = True
        self._pending.clear()
        self._aborted = why

    def aborted(self) -> Optional[str]:
        """Why the stream ended with an error, if it did (see `abort`)."""
        return self._aborted

    def has_gap(self) -> bool:
        """Whether frames have arrived beyond a gap: the stream is not complete yet."""
        return bool(self._pending)

    def buffered(self) -> int:
        """Bytes buffered but not yet read by the application."""
        return self._ready_bytes


class Mux:
    """The stream tables for one session.

    Each stream carries bytes both ways, so it has a send side and a receive side on both ends. The
    two ends allocate ids from disjoint halves (odd and even), so a stream either end opens never
    collides with one the other opened.
    """

    def __init__(self, odd: bool = True) -> None:
        self._send: Dict[int, SendSide] = {}
        self._recv: Dict[int, RecvSide] = {}
        # A random point to count stream ids from, so a restarted peer does not reuse ids the other
        # end still remembers. 31 bits leave room to count up.
        self._next_stream = secrets.randbits(64) >> 33
        self._even = not odd

    def alloc_stream(self) -> int:
        self._next_stream += 1
        return self._next_stream * 2 - (0 if self._even else 1)

    def is_peer_stream(self, id: int) -> bool:
        return id != 0 and (id % 2 == 0) != self._even

    def open(self, service: str) -> int:
        """Register a stream we are opening."""
        id = self.alloc_stream()
        self._send[id] = SendSide.with_window(id, service, DEFAULT_WINDOW)
        self._recv[id] = RecvSide.with_window(id, service, DEFAULT_WINDOW)
        return id

    def accept(self, id: int, service: str) -> RecvSide:
        """Register a stream the peer opened."""
        if id not in self._send:
            self._send[id] = SendSide.with_window(id, service, DEFAULT_WINDOW)
        if id not in self._recv:
            self._recv[id] = RecvSide.with_window(id, service, DEFAULT_WINDOW)
        return self._recv[id]

    def send_side(self, id: int) -> Optional[SendSide]:
        return self._send.get(id)

    def recv_side(self, id: int) -> Optional[RecvSide]:
        return self._recv.get(id)

    def remove_send(self, id: int) -> Optional[SendSide]:
        return self._send.pop(id, None)

    def remove_recv(self, id: int) -> Optional[RecvSide]:
        return self._recv.pop(id, None)

    def counts(self) -> Tuple[int, int]:
        """How many streams are open in each direction."""
        return len(self._send), len(self._recv)

    def pending_retransmits(self) -> List[OutFrame]:
        """Every stream's unacknowledged frames, in (stream, seq) order."""
        out: List[OutFrame] = []
        for id in sorted(self._send):
            out.extend(self._send[id].retransmit())
        return out
