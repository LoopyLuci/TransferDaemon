"""One peer's overlay session: the routes to it, the streams over those routes, and the loop that keeps them moving.

Mirrors `crates/transferd-overlay/src/session.rs`. A session owns a set of routes (`link.Link`) and a `Mux`. Everything
that decides where bytes go happens here:

* **Best route per flow.** Control frames and single data frames take the cheapest live route (`link.best_route`).
* **Failover mid-stream.** When a route dies, unacknowledged frames are re-sent over another route. Every data
  frame carries `(stream, seq)`, so the peer reassembles them into the same byte stream.
* **Striping.** A bulk stream is split across the live routes, weighted by measured throughput.
* **Flow control.** Each stream advertises a window; writes wait for credit rather than being dropped.
* **Congestion control.** Every route has its own window, round-trip estimate and retransmission timeout (`cc.py`).
* **Control receipts.** Reliable control frames (HELLO, OPEN, ...) are resent until the peer's CTRL_ACK comes back.

The engine is single-threaded: it runs in one asyncio task and every method that changes its state is synchronous, so
no lock is held across an `await`. The public methods (`open`, `send`, `recv`, ...) are coroutines for symmetry with
the Rust handle, and they never wait on the loop except where the caller asked to (`open`, `recv`).
"""

from __future__ import annotations

import asyncio
import collections
import math
import secrets
import time
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Sequence, Set, Tuple

from . import frames as F
from .cc import INITIAL_RTO, MSS, RouteCc
from .cc import cost as wire_cost
from .errors import Closed, Denied, NoSuchService, OverlayError, RateLimited, StreamReset, TransferdError, Unreachable
from .frames import Frame, PunchMsg, RouteReport, ServiceInfo
from .identity import HybridIdentity
from .link import Link, RouteKind, best_route, ranked_routes
from .mux import Mux, OutFrame
from .replay import CONTROL_WINDOW, ReplayWindow
from .streams import ENDED_KEPT

#: How often the session ticks (probes, resends, timeouts).
TICK = 0.020
#: How often the prober pings each route.
PROBE_EVERY = 1.0
#: How long an unanswered ping may wait before it counts as missed (a multiple of this).
RESEND_AFTER = 0.400
#: The most frames one reported selective-acknowledgement range is believed to span.
MAX_SACK_SPAN = 1024
#: How many ranges of frames beyond a gap an acknowledgement reports.
SACK_RANGES = 4
#: Duplicate acknowledgements in a row that show a frame was lost without waiting for its timeout.
DUP_ACKS = 3
#: Unanswered pings in a row before a route counts as down.
MISSES_DOWN = 3
#: How long a control frame waits for its receipt before it goes out again.
CTRL_RESEND = 0.300
#: How long a control frame is resent before the peer is taken to be gone.
CTRL_GIVE_UP = 60.0
#: How long `open` waits for the peer to accept or refuse a stream.
OPEN_TIMEOUT = 15.0
#: A frame this big or bigger is treated as bulk: striped across routes rather than pinned.
BULK_THRESHOLD = 4096

_MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class SessionEvent:
    """What the session tells the node. `kind` says which of the other fields mean something.

    kinds: `hello` (the peer's hello arrived), `ready` (the session is up), `refused`, `route_changed`,
    `open_request` (the peer wants a stream: the node answers with `authorize`), `punch`, `down`.
    """

    kind: str
    peer: str
    name: str = ""
    ext: bytes = b""
    version: int = 0
    services: List[ServiceInfo] = field(default_factory=list)
    reason: str = ""
    route: Optional[RouteKind] = None
    up: bool = False
    stream: int = 0
    service: str = ""
    msg: Optional[PunchMsg] = None


@dataclass
class SessionSetup:
    """Who a session is with and what we tell it about ourselves."""

    peer_node_id: str
    peer_name: str
    identity: HybridIdentity
    #: The services we expose, for our hello.
    services: List[ServiceInfo] = field(default_factory=list)
    #: The highest protocol version to offer.
    max_version: int = F.VERSION_CURRENT
    #: Our hello's extension bytes.
    ext: bytes = b""


@dataclass
class _InFlight:
    """A data frame on the wire and not yet acknowledged."""

    route: int
    cost: int
    sent_at: float
    #: A resend: its acknowledgement says nothing about the round trip.
    retx: bool


@dataclass
class _WriteQueue:
    """Bytes the application asked to send that have not gone out yet."""

    chunks: Deque[bytes] = field(default_factory=collections.deque)
    #: The application said this was the last write for the stream.
    fin: bool = False


def routes_usable(routes: Sequence[RouteReport]) -> bool:
    """Whether any of these routes is up. Nothing measured yet counts as usable: the session has only just been made."""
    return not routes or any(r.active for r in routes)


def _decode(frame: Frame):
    """The frame's body, or None when it does not decode (the frame is then ignored)."""
    try:
        return frame.decode()
    except TransferdError:
        return None


def _resolve(fut: Optional[asyncio.Future], value) -> None:
    if fut is not None and not fut.done():
        fut.set_result(value)


def _fail(fut: Optional[asyncio.Future], exc: BaseException) -> None:
    if fut is not None and not fut.done():
        fut.set_exception(exc)


def _round3(v: float) -> float:
    return round(v * 1000.0) / 1000.0 if math.isfinite(v) else 0.0


def _now_micros() -> int:
    return int(time.time() * 1_000_000)


class OverlaySession:
    """A session with one peer: the handle the node calls, and the engine that runs its routes and streams.

    Build one with `spawn`. The events queue receives `SessionEvent`s; the node reads them and answers the
    `open_request`s with `authorize`.
    """

    def __init__(self, setup: SessionSetup, links: Sequence[Link], events: "asyncio.Queue[SessionEvent]") -> None:
        self.peer_node_id = setup.peer_node_id
        #: The peer's display name: the one it was given, then the one its hello announces.
        self.peer_name = setup.peer_name
        #: The services the peer advertised, refreshed on every hello.
        self.services: List[ServiceInfo] = []

        identity = setup.identity
        # The two ends allocate stream ids from different halves, decided by who has the lower node id.
        self._mux = Mux(odd=identity.node_id < setup.peer_node_id)
        self._local = F.Hello(
            min_version=F.VERSION_MIN,
            max_version=setup.max_version,
            node_id=identity.node_id,
            name=identity.name,
            services=list(setup.services),
            ext=setup.ext,
            nonce=secrets.token_bytes(16),
        )
        self._version = setup.max_version
        self._agreed = 0
        # Below 2^40, as the reference: every implementation counts these numbers exactly (see session.rs).
        self._frame_seq = secrets.randbits(40)
        self._ready = False
        self._stopped = False

        self._links: List[Link] = list(links)
        self._events = events
        self._kick_event = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self._published_routes: List[RouteReport] = []

        self._last_probe: Dict[int, float] = {}
        self._cc: Dict[int, RouteCc] = {}
        # Every data frame on the wire and not acknowledged, by stream, then by sequence number.
        self._inflight: Dict[int, Dict[int, _InFlight]] = {}
        # Frames the streams released that no route has room for yet, oldest first.
        self._outbox: Deque[OutFrame] = collections.deque()
        # Frames given up on and waiting to go out again, with the route that lost them.
        self._retx_queue: Deque[Tuple[OutFrame, int]] = collections.deque()
        self._retx_pending: Set[Tuple[int, int]] = set()
        # The last cumulative acknowledgement per stream and how often it repeated.
        self._dup_acks: Dict[int, Tuple[int, int]] = {}
        # Per stream, the sequence number one past the newest frame on the wire when a loss was found.
        self._recover: Dict[int, int] = {}
        # Per stream, the highest sequence number the peer reported having beyond a gap.
        self._high_sack: Dict[int, int] = {}
        # When an acknowledgement last came in for each stream.
        self._last_ack: Dict[int, float] = {}
        # When pacing next lets a waiting frame go.
        self._pace_at: Optional[float] = None
        # Which route each open ping went out on, so the answer is credited to the right one.
        self._pings: Dict[int, Tuple[int, float]] = {}
        self._misses: Dict[int, int] = {}
        # Receives still waiting for data.
        self._pending_reads: Dict[int, asyncio.Future] = {}
        # Streams this side closed cleanly, oldest first (see ENDED_KEPT).
        self._ended: List[int] = []
        # Bytes the application wrote that the window has not let out yet, per stream.
        self._write_queue: Dict[int, _WriteQueue] = {}
        # Streams a peer asked for that the node has not answered yet.
        self._pending_opens: Dict[int, str] = {}
        # Streams we asked for, waiting for the peer's OPEN_OK or OPEN_ERR.
        self._awaiting_open: Dict[int, Tuple[str, asyncio.Future]] = {}
        # Control frames sent and not yet receipted: seq -> (frame, first sent, last sent).
        self._ctrl_unacked: Dict[int, Tuple[Frame, float, float]] = {}
        # Control frames received, by frame sequence number, so a resent one is acted on once.
        self._ctrl_seen = ReplayWindow(CONTROL_WINDOW)
        # The nonce of the last hello the peer sent: a new one means the peer restarted (see `_note_peer_hello`).
        self._peer_hello_nonce: Optional[bytes] = None

    # ----- lifecycle ----------------------------------------------------------------------------

    def _start(self) -> None:
        """Adopt the routes, send our hello, and start the loop. Needs a running event loop."""
        for link in self._links:
            link.set_waker(self._kick)
        self._send_frame(F.HELLO, F.encode_body(F.HELLO, self._local), False)
        self._task = asyncio.get_running_loop().create_task(self._run())

    def _kick(self) -> None:
        self._kick_event.set()

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        next_tick = loop.time() + TICK
        try:
            while not self._stopped:
                now = loop.time()
                wait = next_tick - now
                if self._pace_at is not None:
                    wait = min(wait, self._pace_at - now)
                if wait > 0:
                    try:
                        await asyncio.wait_for(self._kick_event.wait(), wait)
                    except asyncio.TimeoutError:
                        pass
                self._kick_event.clear()
                if self._stopped:
                    break
                now = loop.time()
                if now >= next_tick:
                    next_tick = now + TICK
                    self._tick()
                else:
                    self._drain_inbound()
                if self._pace_at is not None and loop.time() >= self._pace_at:
                    self._flush()
        finally:
            self._finish()

    def _finish(self) -> None:
        for _service, fut in self._awaiting_open.values():
            _fail(fut, Closed(f"the session with {self.peer_node_id} ended"))
        self._awaiting_open.clear()
        for stream, fut in self._pending_reads.items():
            # The session ended before the stream did. Silence is not the end of a stream, so the read fails.
            _fail(fut, Closed(f"the session with {self.peer_node_id} ended before stream {stream} did"))
        self._pending_reads.clear()
        self._events.put_nowait(SessionEvent(kind="down", peer=self.peer_node_id, reason="session ended"))

    async def shutdown(self) -> None:
        """Stop the session. Its loop ends and every waiting call is released."""
        self._stopped = True
        self._kick()
        if self._task is not None and self._task is not asyncio.current_task():
            await asyncio.gather(self._task, return_exceptions=True)

    # ----- the handle the node uses ---------------------------------------------------------------

    def _gone(self) -> OverlayError:
        return Closed(f"the session with {self.peer_node_id} is gone")

    def is_live(self) -> bool:
        """Whether the session's loop still runs."""
        return not self._stopped

    def is_usable(self) -> bool:
        """Whether the session can carry traffic now: its loop runs and a route is up."""
        return self.is_live() and routes_usable(self._published_routes)

    def version(self) -> int:
        """The agreed protocol version, or 0 while the session is still negotiating."""
        return self._agreed

    def routes(self) -> List[RouteReport]:
        """The routes this session measures, for the node's peer listing."""
        return list(self._published_routes)

    def route_quality(self) -> float:
        """How good this session's best route is: estimated milliseconds to completion. Lower is better."""
        return min((r.rtt_ms + r.loss * 500.0 for r in self._published_routes if r.active), default=math.inf)

    async def ready(self, limit: float) -> bool:
        """Wait until the peer has answered our hello, at most `limit` seconds. False when it did not in time."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + limit
        while self._agreed == 0:
            if not self.is_live() or loop.time() >= deadline:
                return False
            await asyncio.sleep(0.010)
        return True

    async def open(self, service: str) -> int:
        """Open a stream to a service the peer exposes. Returns once the peer accepted it, or raises with its reason."""
        if self._stopped:
            raise self._gone()
        stream = self._mux.open(service)
        fut = asyncio.get_running_loop().create_future()
        body = F.encode_body(F.OPEN, F.Open(stream=stream, service=service, node_id=self._local.node_id))
        if not self._send_frame(F.OPEN, body, False):
            self._mux.remove_send(stream)
            self._mux.remove_recv(stream)
            raise Unreachable(self.peer_node_id)
        # Answered by the peer's OPEN_OK or OPEN_ERR.
        self._awaiting_open[stream] = (service, fut)
        try:
            return await asyncio.wait_for(fut, OPEN_TIMEOUT)
        except asyncio.TimeoutError:
            self._awaiting_open.pop(stream, None)
            raise Unreachable(self.peer_node_id) from None

    async def send(self, stream: int, data: bytes, fin: bool = False) -> None:
        """Queue bytes for a stream. The stream's window decides how much moves now; the rest waits for credit."""
        if self._stopped:
            raise self._gone()
        queue = self._write_queue.setdefault(stream, _WriteQueue())
        if data:
            queue.chunks.append(data)
        if fin and not queue.fin:
            # The end of the stream travels as its own empty frame, after every byte before it.
            queue.fin = True
            queue.chunks.append(b"")
        self._pump(stream)

    async def recv(self, stream: int) -> Optional[bytes]:
        """Take what the peer has sent on a stream. Waits for data.

        None is the end of the stream: the peer's FIN or a CLOSE with code `closed`, or our own clean close. Raises
        `StreamReset` if the stream ended with an error (reset, refused, or never open here), after the bytes before
        it, and `Closed` when the session ends before the stream does.
        """
        if self._stopped:
            raise self._gone()
        recv = self._mux.recv_side(stream)
        if recv is None:
            if stream in self._ended:
                return None
            raise StreamReset(stream, "it is not open")
        ready = recv.take()
        ended = recv.finished() and recv.buffered() == 0
        if ready is None and ended:
            if recv.aborted() is not None:
                raise StreamReset(stream, recv.aborted() or "")
            return None
        if ready is not None:
            self._grant_window(stream, recv.window_update())
            return ready
        fut = asyncio.get_running_loop().create_future()
        # A second reader on the same stream replaces the first, which then sees the end.
        self._resolve_read(stream, None)
        self._pending_reads[stream] = fut
        return await fut

    async def close(self, stream: int) -> None:
        """Close a stream. Everything written to it goes out first, then its end; once the peer has acknowledged both, the peer is told
        the stream closed cleanly. If that cannot happen within `FLUSH_SECONDS` the peer is told `reset` instead, so its
        reader gets an error.
        """
        if self._stopped:
            return
        side = self._mux.send_side(stream)
        if side is not None and not side.fin_sent():
            # The end of our side goes out after the bytes already queued, as an empty FIN frame. If it went out already
            # (the caller wrote with fin), it is not sent twice.
            await self.send(stream, b"", fin=True)
        flushed = await self._flushed(stream)
        code, reason = ("closed", "") if flushed else ("reset", "the stream could not be flushed in time")
        body = F.encode_body(F.CLOSE, F.Close(stream=stream, code=code, reason=reason))
        self._send_frame(F.CLOSE, body, False)
        self._mux.remove_send(stream)
        self._mux.remove_recv(stream)
        self._forget_stream(stream)
        if flushed:
            self._note_ended(stream)
            self._resolve_read(stream, None)
        else:
            self._fail_read(stream, StreamReset(stream, "this side reset the stream"))

    #: How long `close` waits for the peer to acknowledge what was written before it resets the stream (seconds).
    FLUSH_SECONDS = 5.0

    async def _flushed(self, stream: int) -> bool:
        """Wait until every byte queued on the stream is framed and acknowledged, or the time runs out."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.FLUSH_SECONDS
        while not self._stopped:
            queue = self._write_queue.get(stream)
            side = self._mux.send_side(stream)
            if (queue is None or not queue.chunks) and (side is None or side.unacked_frames() == 0):
                return True
            if loop.time() >= deadline:
                return False
            await asyncio.sleep(0.01)
        return False

    async def add_link(self, link: Link) -> None:
        """Add a route discovered after the session came up (a hole punch, a LAN address)."""
        if self._stopped:
            return
        if any(l.id == link.id for l in self._links):
            return
        link.set_waker(self._kick)
        up = link.is_up()
        self._links.append(link)
        self._events.put_nowait(SessionEvent(kind="route_changed", peer=self.peer_node_id, route=link.kind, up=up))

    async def authorize(self, stream: int, service: str, ok: bool, reason: str = "") -> None:
        """Allow or refuse a stream the peer asked for. This is where the access decision reaches the wire."""
        if self._stopped:
            raise self._gone()
        if self._pending_opens.pop(stream, None) is None:
            # The peer closed it before we decided: nothing to accept or refuse.
            return
        if ok:
            self._mux.accept(stream, service)
            body = F.encode_body(F.OPEN_OK, F.OpenOk(stream=stream, route=self._best_route_name()))
            self._send_frame(F.OPEN_OK, body, False)
        else:
            # The code tells the opener which refusal this was; the reason says it in words.
            if reason == "no such service":
                code = "no_such_service"
            elif "a minute" in reason:
                code = "rate_limited"
            else:
                code = "denied"
            body = F.encode_body(F.OPEN_ERR, F.OpenErr(stream=stream, code=code, reason=reason))
            self._send_frame(F.OPEN_ERR, body, False)

    async def advertise(self, services: List[ServiceInfo]) -> None:
        """Re-announce what we expose: a fresh hello, which the peer answers and uses to update what it knows of us."""
        if self._stopped:
            return
        self._local.services = list(services)
        self._send_frame(F.HELLO, F.encode_body(F.HELLO, self._local), False)

    async def send_punch(self, msg: PunchMsg) -> None:
        """Send our side of a hole-punch exchange. Refused when the session did not agree on a version that carries it."""
        if self.version() < F.VERSION_PUNCH:
            raise OverlayError("the peer's protocol version has no hole punching")
        if self._stopped:
            raise self._gone()
        self._send_frame(F.CANDIDATE, F.encode_body(F.CANDIDATE, msg), False)

    # ----- framing -------------------------------------------------------------------------------

    def _next_seq(self) -> int:
        self._frame_seq += 1
        return self._frame_seq

    def _send_frame(self, kind: int, body: bytes, bulk: bool) -> bool:
        seq = self._next_seq()
        flags = F.FLAG_BULK if bulk else 0
        if kind in F.RELIABLE_KINDS:
            # A reliable control frame goes out on every usable route: the first copy to arrive counts, the rest are dropped.
            flags |= F.FLAG_MIRROR
        frame = Frame(version=self._version, kind=kind, flags=flags, seq=seq, body=body)
        sent = self._dispatch(frame)
        if kind in F.RELIABLE_KINDS:
            # Kept until the peer's receipt comes back. A frame that could not go out at all is tried again on
            # the next resend, so it still counts as queued.
            now = time.monotonic()
            self._ctrl_unacked[seq] = (frame, now, now)
            return True
        return sent

    def _resend_control(self) -> None:
        now = time.monotonic()
        for seq in sorted(self._ctrl_unacked):
            entry = self._ctrl_unacked.get(seq)
            if entry is None:
                continue
            frame, first, last = entry
            if now - last < CTRL_RESEND:
                continue
            if now - first > CTRL_GIVE_UP:
                self._stopped = True
                return
            self._dispatch(frame)
            self._ctrl_unacked[seq] = (frame, first, now)

    def _note_peer_hello(self, frame: Frame) -> None:
        """A hello with a nonce this session has not seen starts a new numbering.

        A peer that restarted counts its control frames from a fresh random base, which the window would refuse as
        older than what it has already seen, and the restarted peer would never be heard. Resent copies of a hello
        carry the same nonce, so they do not reset the window and stay duplicates.
        """
        hello = _decode(frame)
        if hello is not None and hello.nonce != self._peer_hello_nonce:
            self._peer_hello_nonce = hello.nonce
            self._ctrl_seen = ReplayWindow(CONTROL_WINDOW)

    def _admit_control(self, frame: Frame) -> bool:
        """A control frame arrived: send its receipt, and say whether to act on it. False for a copy already acted on."""
        receipt = F.encode_body(F.CTRL_ACK, F.CtrlAck(seq=frame.seq))
        self._send_frame(F.CTRL_ACK, receipt, False)
        return self._ctrl_seen.accept(frame.seq)

    def _dispatch(self, frame: Frame) -> bool:
        """Put a frame on the first route that takes it, cheapest first, so one congested route never holds a frame back
        while another is free. A mirrored frame goes out on every usable route instead: the peer takes the first copy to
        arrive and ignores the rest."""
        candidates = self._usable_links()
        if frame.is_mirrored:
            any_sent = False
            for link in candidates:
                if link.send(frame):
                    any_sent = True
            return any_sent
        return any(link.send(frame) for link in candidates)

    def _route_for_bulk(self, allowed: Sequence[int]) -> Optional[Link]:
        """The route a bulk frame should go out on: striped, weighted by measured throughput.

        The route with the least (used share - bandwidth share) skew wins, which spreads bulk traffic across every
        healthy path instead of hammering the fastest one.
        """
        live = [l for l in self._links if l.id in allowed]
        if not live:
            return None
        total = sum(max(l.stats.metrics().mbps * 1_000.0, 1.0) for l in live)
        best: Optional[Tuple[Link, float]] = None
        for link in live:
            m = link.stats.metrics()
            share = max(m.mbps * 1_000.0, 1.0) / total
            sent = max(link.stats.frames_sent(), 1)
            used = m.active / sent
            skew = used - share
            if best is None or skew < best[1]:
                best = (link, skew)
        return best[0] if best is not None else None

    def _data_frame(self, f: OutFrame, mirrored: bool) -> Frame:
        body = F.encode_body(F.DATA, F.Data(stream=f.stream, seq=f.seq, fin=f.fin, payload=f.payload))
        flags = 0
        if len(f.payload) >= BULK_THRESHOLD:
            flags |= F.FLAG_BULK
        if mirrored:
            flags |= F.FLAG_MIRROR
        return Frame(version=self._version, kind=F.DATA, flags=flags, seq=self._next_seq(), body=body)

    def _cc_of(self, route: int) -> RouteCc:
        cc = self._cc.get(route)
        if cc is None:
            cc = self._cc[route] = RouteCc()
        return cc

    def _routes_report(self) -> List[RouteReport]:
        out: List[RouteReport] = []
        for link in self._links:
            m = link.stats.metrics()
            cc = self._cc.get(link.id) or RouteCc()
            out.append(
                RouteReport(
                    kind=link.kind.value,
                    rtt_ms=_round3(m.rtt_ms),
                    loss=_round3(m.loss),
                    mbps=_round3(m.mbps),
                    active=m.up,
                    cwnd=cc.cwnd,
                    in_flight=cc.in_flight,
                    srtt_ms=_round3((cc.srtt or 0.0) * 1000.0),
                    rto_ms=_round3(cc.rto() * 1000.0),
                    sent_bytes=cc.sent_bytes,
                    retx_bytes=cc.retx_bytes,
                )
            )
        return out

    def _best_route_name(self) -> str:
        best = best_route(self._links)
        return best.kind.value if best is not None else ""

    def _find_link(self, route: int) -> Optional[Link]:
        return next((l for l in self._links if l.id == route), None)

    def _left_route(self, route: int, cost: int) -> None:
        """A data frame of `cost` wire bytes left the books of `route` (acknowledged, lost or dropped with its stream)."""
        link = self._find_link(route)
        if link is not None:
            link.stats.record_acked(cost)

    def _take_inflight(self, stream: int, seq: int) -> Optional[_InFlight]:
        books = self._inflight.get(stream)
        if books is None:
            return None
        entry = books.pop(seq, None)
        if not books:
            del self._inflight[stream]
        return entry

    def _seqs_in(self, stream: int, lo: int, hi: int) -> List[int]:
        books = self._inflight.get(stream)
        if not books:
            return []
        return sorted(s for s in books if lo <= s < hi)

    # ----- streams -------------------------------------------------------------------------------

    def _grant_window(self, stream: int, credit: int) -> None:
        if credit > 0:
            body = F.encode_body(F.WINDOW, F.Window(stream=stream, credit=credit))
            self._send_frame(F.WINDOW, body, False)

    def _pump(self, stream: int) -> None:
        self._frame_pending(stream)
        self._flush()

    def _frame_pending(self, stream: int) -> None:
        """Move the stream's queued writes into frames, as far as its window allows.

        The rest stays queued at the front: dropping it would lose bytes from the middle of the stream.
        """
        while True:
            queue = self._write_queue.get(stream)
            if queue is None or not queue.chunks:
                return
            chunk = queue.chunks.popleft()
            last = queue.fin and not queue.chunks
            side = self._mux.send_side(stream)
            if side is None:
                return
            frames = side.frame(chunk, last)
            taken = sum(len(f.payload) for f in frames)
            if taken < len(chunk):
                queue.chunks.appendleft(chunk[taken:])
            if not frames:
                return
            self._outbox.extend(frames)
            if taken < len(chunk):
                return  # the rest waits for a WINDOW from the peer
            if not queue.chunks:
                del self._write_queue[stream]
                return

    # ----- routes and sending --------------------------------------------------------------------

    def _usable_links(self) -> List[Link]:
        """The routes a frame may use, cheapest first: the live ones, or with none live the cheapest that is not closed."""
        ranked = ranked_routes(self._links)
        live = [l for l in ranked if l.is_up()]
        return live if live else ranked[:1]

    def _pick_routes(self, bulk: bool, cost: int, avoid: Optional[int], retx: bool, now: float) -> Tuple[List[Link], Optional[float]]:
        """The routes a frame of `cost` bytes may go out on now, best first: the striped choice for bulk, then every other
        open route cheapest first. With none open, `wake` says when pacing allows one (None: it waits for an acknowledgement
        or a route)."""
        usable = self._usable_links()
        open_: List[Link] = []
        wake: Optional[float] = None
        for link in usable:
            # A resend prefers another route than the one that lost the frame, when there is one.
            if avoid is not None and avoid == link.id and len(usable) > 1:
                continue
            cc = self._cc_of(link.id)
            # A resend ignores the window: the frames behind the lost one are delivered but cannot be
            # acknowledged until it arrives, so waiting for room would wait for the very resend that frees it.
            if not retx and not cc.has_room(cost):
                continue
            at = cc.pace_wait(now)
            if at is None:
                open_.append(link)
            else:
                wake = at if wake is None else min(wake, at)
        if not open_:
            return [], wake
        ordered: List[Link] = []
        if bulk:
            striped = self._route_for_bulk([l.id for l in open_])
            if striped is not None:
                ordered.append(striped)
        for link in ranked_routes(open_):
            if all(o.id != link.id for o in ordered):
                ordered.append(link)
        return ordered, None

    def _flush(self) -> None:
        """Send what the routes have room for: resends first, then new data. What does not fit waits."""
        now = time.monotonic()
        self._pace_at = None
        while True:
            if self._retx_queue:
                head, route = self._retx_queue[0]
                if (head.stream, head.seq) not in self._retx_pending:
                    self._retx_queue.popleft()  # acknowledged while it waited
                    continue
                frame, avoid, retx = head, route, True
            elif self._outbox:
                frame, avoid, retx = self._outbox[0], None, False
            else:
                return
            if self._mux.send_side(frame.stream) is None:
                # The stream closed while its frame waited.
                if retx:
                    self._retx_queue.popleft()
                    self._retx_pending.discard((frame.stream, frame.seq))
                else:
                    self._outbox.popleft()
                continue
            cost = wire_cost(len(frame.payload))
            bulk = len(frame.payload) >= BULK_THRESHOLD
            routes, wake = self._pick_routes(bulk, cost, avoid, retx, now)
            if not routes:
                self._pace_at = wake
                return
            # The first route that takes the frame carries it. When every route's queue is full, the next tick tries again.
            wire = self._data_frame(frame, False)
            link = next((candidate for candidate in routes if candidate.send(wire)), None)
            if link is None:
                return
            link.stats.record_data_out(cost)
            if retx:
                self._retx_queue.popleft()
                self._retx_pending.discard((frame.stream, frame.seq))
            else:
                self._outbox.popleft()
            self._cc_of(link.id).on_sent(cost, len(frame.payload), retx, now)
            self._inflight.setdefault(frame.stream, {})[frame.seq] = _InFlight(
                route=link.id, cost=cost, sent_at=now, retx=retx
            )

    def _mark_lost(self, stream: int, seq: int, now: float, why: str) -> bool:
        """A frame is given up on: off the route's books, and queued to go out again."""
        entry = self._take_inflight(stream, seq)
        if entry is None:
            return False
        self._left_route(entry.route, entry.cost)
        remaining = self._inflight.get(stream)
        newest = max(remaining) if remaining else seq
        self._recover[stream] = max(self._recover.get(stream, 0), newest + 1)
        self._cc_of(entry.route).on_lost(entry.cost, entry.sent_at, now)
        side = self._mux.send_side(stream)
        frame = side.unacked_frame(seq) if side is not None else None
        if frame is not None and (stream, seq) not in self._retx_pending:
            self._retx_pending.add((stream, seq))
            self._retx_queue.append((frame, entry.route))
        return True

    def _expire(self) -> None:
        """Frames that outlived their route's timeout are lost: the route's window shrinks, its timeout doubles,
        and the frames go out again, on another route where there is one."""
        now = time.monotonic()
        due: List[Tuple[int, int]] = []
        routes: List[int] = []
        for stream in sorted(self._inflight):
            books = self._inflight[stream]
            for index, seq in enumerate(sorted(books)):
                entry = books[seq]
                cc = self._cc.get(entry.route)
                rto = cc.rto() if cc is not None else INITIAL_RTO
                # Behind the oldest unacknowledged frame, a frame is only waiting for the cumulative acknowledgement
                # to get past the gap in front of it, as long as the peer keeps answering: it is not lost.
                last = self._last_ack.get(stream)
                heard = last is not None and last > entry.sent_at and now - last < rto
                if now - entry.sent_at >= rto and (index == 0 or not heard):
                    due.append((stream, seq))
                    if entry.route not in routes:
                        routes.append(entry.route)
        for stream, seq in due:
            self._mark_lost(stream, seq, now, "timeout")
        for route in routes:
            cc = self._cc.get(route)
            if cc is not None:
                cc.back_off()

    def _forget_stream(self, stream: int) -> None:
        """A stream is gone: nothing of it stays on the books."""
        for seq, entry in sorted(self._inflight.pop(stream, {}).items()):
            cc = self._cc.get(entry.route)
            if cc is not None:
                cc.release(entry.cost)
            self._left_route(entry.route, entry.cost)
        self._outbox = collections.deque(f for f in self._outbox if f.stream != stream)
        self._retx_queue = collections.deque((f, r) for (f, r) in self._retx_queue if f.stream != stream)
        self._retx_pending = {k for k in self._retx_pending if k[0] != stream}
        self._dup_acks.pop(stream, None)
        self._recover.pop(stream, None)
        self._last_ack.pop(stream, None)
        self._high_sack.pop(stream, None)

    def _on_ack(self, stream: int, nxt: int, sack: Sequence[Tuple[int, int]]) -> None:
        """An acknowledgement: everything below `nxt` on the stream has arrived, and so have the frames in `sack`."""
        now = time.monotonic()
        self._last_ack[stream] = now
        keys = self._seqs_in(stream, 0, nxt)
        cumulative = len(keys)
        high: Optional[int] = None
        for frm, to in sack:
            # A range is the peer's word: bound what it can make us walk.
            to = min(to, frm + MAX_SACK_SPAN)
            if frm < nxt or frm >= to:
                continue
            keys.extend(self._seqs_in(stream, frm, to))
            high = (to - 1) if high is None else max(high, to - 1)

        # A round trip is measured from the newest frame this acknowledgement covers, and only when none of them was
        # resent (the acknowledgement could be for either copy).
        sample: Optional[Tuple[int, float]] = None
        resent = False
        for seq in keys:
            entry = self._take_inflight(stream, seq)
            if entry is None:
                continue
            self._left_route(entry.route, entry.cost)
            resent = resent or entry.retx
            sample = (entry.route, now - entry.sent_at)
            cc = self._cc_of(entry.route)
            # Held back by this window? Then the window may grow.
            limited = cc.in_flight + MSS >= cc.cwnd
            cc.on_acked(entry.cost, limited)
        if sample is not None and not resent:
            self._cc_of(sample[0]).on_rtt(sample[1])

        self._retx_pending = {k for k in self._retx_pending if k[0] != stream or k[1] >= nxt}
        if high is not None:
            self._high_sack[stream] = max(self._high_sack.get(stream, 0), high)
        if stream in self._high_sack and self._high_sack[stream] < nxt:
            del self._high_sack[stream]
        recover = self._recover.get(stream)
        if recover is not None and nxt >= recover:
            del self._recover[stream]
        elif cumulative > 0 and recover is not None:
            # A partial acknowledgement: what it stops at was lost along with the frame just repaired.
            books = self._inflight.get(stream, {})
            entry = books.get(nxt)
            if entry is not None and not entry.retx:
                self._mark_lost(stream, nxt, now, "partial")

        # Frames below the highest one the peer has, that are older than a round trip and a quarter by now: they
        # went out first and did not arrive, which on one path means lost. The wait is the slowest route's; a resend,
        # which may still be on its way, waits twice as long.
        top = self._high_sack.get(stream)
        if top is not None:
            srtts = [cc.srtt for cc in self._cc.values() if cc.srtt is not None]
            slowest = max(srtts, default=0.0)
            wait = slowest + slowest / 4
            behind = [
                seq
                for seq in self._seqs_in(stream, 0, top)
                if now - self._inflight[stream][seq].sent_at
                > (wait * 2 if self._inflight[stream][seq].retx else wait)
            ]
            for seq in behind:
                self._mark_lost(stream, seq, now, "sack")

        # The same acknowledgement again and again means a frame after the gap keeps arriving while `nxt` does not:
        # it was lost, and waiting for its timeout would waste a round trip.
        prev_next, count = self._dup_acks.get(stream, (nxt, 0))
        if prev_next != nxt or cumulative > 0:
            self._dup_acks[stream] = (nxt, 0)
        else:
            count += 1
            self._dup_acks[stream] = (nxt, count)
            if count == DUP_ACKS:
                entry = self._inflight.get(stream, {}).get(nxt)
                if entry is not None:
                    cc = self._cc.get(entry.route)
                    srtt = cc.srtt if cc is not None else None
                    if now - entry.sent_at > (srtt or 0.0):
                        self._mark_lost(stream, nxt, now, "dupack")
        self._flush()

    # ----- the loop --------------------------------------------------------------------------------

    def _tick(self) -> None:
        self._drain_inbound()
        self._probe()
        self._resend_control()
        # Republish the measurements so the node and group placement see current numbers.
        self._published_routes = self._routes_report()
        if self._ready:
            self._expire()
        self._flush()

    def _drain_inbound(self) -> None:
        for link in list(self._links):
            # Bounded per pass so one busy route cannot starve the others; a route that had more wakes the session
            # again for another pass.
            for taken in range(65):
                if taken == 64:
                    self._kick()
                    break
                frame = link.try_recv()
                if frame is None:
                    break
                if frame.kind == F.PING:
                    # A ping is answered on the route it came in on, so the answer measures that route.
                    self._answer_ping(frame, link)
                elif frame.kind in F.RELIABLE_KINDS:
                    if frame.kind == F.HELLO:
                        self._note_peer_hello(frame)
                    if self._admit_control(frame):
                        self._on_frame(frame)
                else:
                    self._on_frame(frame)
            if not link.is_up():
                link.mark_down()
        # Hand over anything a pending read was waiting for.
        for stream in list(self._pending_reads):
            recv = self._mux.recv_side(stream)
            if recv is None:
                continue
            data = recv.take()
            if data is None:
                continue
            granted = recv.window_update()
            self._resolve_read(stream, data)
            self._grant_window(stream, granted)

    def _resolve_read(self, stream: int, value: Optional[bytes]) -> None:
        fut = self._pending_reads.pop(stream, None)
        _resolve(fut, value)

    def _fail_read(self, stream: int, exc: BaseException) -> None:
        fut = self._pending_reads.pop(stream, None)
        _fail(fut, exc)

    def _note_ended(self, stream: int) -> None:
        """Remember a stream closed cleanly here, so a read on it later is the end and not an error."""
        if stream in self._ended:
            return
        if len(self._ended) >= ENDED_KEPT:
            self._ended.pop(0)
        self._ended.append(stream)

    def _become_ready(self, version: int, name: str, services: List[ServiceInfo]) -> None:
        self._version = version
        self.services = list(services)
        self.peer_name = name
        self._agreed = version
        self._published_routes = self._routes_report()
        if self._ready:
            return
        self._ready = True
        self._events.put_nowait(
            SessionEvent(kind="ready", peer=self.peer_node_id, version=version, services=list(services))
        )
        # Tell the peer what we can do, so it can place streams too.
        self._send_frame(F.ROUTES, F.encode_body(F.ROUTES, F.Routes(routes=self._routes_report())), False)

    def _on_frame(self, frame: Frame) -> None:
        kind = frame.kind
        if kind == F.HELLO:
            hello = _decode(frame)
            if hello is None:
                return
            if hello.node_id == self.peer_node_id:
                self._events.put_nowait(
                    SessionEvent(kind="hello", peer=self.peer_node_id, name=hello.name, ext=hello.ext)
                )
            # The handshake already proved who is on the other end; a hello claiming to be someone else is refused.
            agreed: Optional[int] = None
            reason = ""
            if hello.node_id != self.peer_node_id:
                reason = f"the hello names {hello.node_id} but the handshake proved {self.peer_node_id}"
            else:
                agreed = F.negotiate(hello.min_version, hello.max_version, self._local.min_version, self._local.max_version)
                if agreed is None:
                    reason = (
                        f"no common protocol version: it speaks {hello.min_version}-{hello.max_version}, "
                        f"we speak {self._local.min_version}-{self._local.max_version}"
                    )
            ack = F.HelloAck(
                version=agreed or 0,
                node_id=self._local.node_id,
                name=self._local.name,
                services=list(self._local.services),
                nonce=hello.nonce,
                reason=reason,
                ext=b"",
            )
            self._send_frame(F.HELLO_ACK, F.encode_body(F.HELLO_ACK, ack), False)
            if agreed is not None:
                self._become_ready(agreed, hello.name, hello.services)
            else:
                self._stopped = True
                self._events.put_nowait(SessionEvent(kind="refused", peer=self.peer_node_id, reason=reason))
        elif kind == F.HELLO_ACK:
            ack = _decode(frame)
            if ack is None or ack.nonce != self._local.nonce:
                return  # an answer for another hello
            if ack.version == 0:
                self._stopped = True
                self._events.put_nowait(SessionEvent(kind="refused", peer=self.peer_node_id, reason=ack.reason))
                return
            self._become_ready(ack.version, ack.name, ack.services)
        elif kind == F.OPEN:
            op = _decode(frame)
            if op is None:
                return
            if not self._mux.is_peer_stream(op.stream) or op.stream in self._pending_opens:
                body = F.encode_body(
                    F.OPEN_ERR,
                    F.OpenErr(stream=op.stream, code="protocol", reason="that stream id is not yours to open"),
                )
                self._send_frame(F.OPEN_ERR, body, False)
                return
            # Ask the node first: the access list lives there, and a refused peer must never reach a local socket.
            self._events.put_nowait(
                SessionEvent(kind="open_request", peer=self.peer_node_id, stream=op.stream, service=op.service)
            )
            self._pending_opens[op.stream] = op.service
        elif kind == F.OPEN_OK:
            ok = _decode(frame)
            if ok is None:
                return
            entry = self._awaiting_open.pop(ok.stream, None)
            if entry is not None:
                _resolve(entry[1], ok.stream)
        elif kind == F.OPEN_ERR:
            err = _decode(frame)
            if err is None:
                return
            entry = self._awaiting_open.pop(err.stream, None)
            if entry is not None:
                service, fut = entry
                if err.code == "no_such_service":
                    refusal: BaseException = NoSuchService(service)
                elif err.code == "rate_limited":
                    refusal = RateLimited(service, err.reason)
                elif err.code == "denied":
                    refusal = Denied(self._local.node_id, service)
                else:
                    refusal = Closed(f"{self.peer_node_id} refused the stream: {err.reason}")
                _fail(fut, refusal)
            self._mux.remove_send(err.stream)
            self._mux.remove_recv(err.stream)
            self._forget_stream(err.stream)
            self._fail_read(err.stream, StreamReset(err.stream, f"the peer refused it: {err.reason}"))
        elif kind == F.DATA:
            data = _decode(frame)
            if data is None:
                return
            out = OutFrame(stream=data.stream, seq=data.seq, payload=data.payload, fin=data.fin)
            recv = self._mux.recv_side(data.stream)
            if recv is None:
                # Not a stream we have (yet): no acknowledgement, so the sender sends it again rather than believing it.
                return
            delivered = bool(recv.accept(out))
            # Cumulative, and sent for a duplicate too: a lost acknowledgement is repaired by the resend it causes.
            nxt = recv.next_expected()
            sack = recv.sack_ranges(SACK_RANGES)
            self._send_frame(F.ACK, F.encode_body(F.ACK, F.Ack(stream=data.stream, seq=nxt, sack=sack)), False)
            if delivered:
                self._wake_reader(data.stream)
            if data.fin:
                self._end_reader(data.stream)
        elif kind == F.ACK:
            ack = _decode(frame)
            if ack is None:
                return
            side = self._mux.send_side(ack.stream)
            if side is not None:
                side.ack_below(ack.seq)
            self._on_ack(ack.stream, ack.seq, ack.sack)
        elif kind == F.WINDOW:
            win = _decode(frame)
            if win is None:
                return
            side = self._mux.send_side(win.stream)
            if side is not None:
                side.grant(win.credit)
            # Credit arrived: whatever was waiting behind the window goes now.
            self._pump(win.stream)
        elif kind == F.CLOSE:
            closed = _decode(frame)
            if closed is None:
                return
            self._pending_opens.pop(closed.stream, None)
            self._mux.remove_send(closed.stream)
            self._forget_stream(closed.stream)
            recv = self._mux.recv_side(closed.stream)
            if recv is None:
                if closed.code == "closed":
                    self._note_ended(closed.stream)
            elif closed.code == "closed" and not recv.has_gap():
                # A clean close with every frame in hand is the end.
                recv.close()
            elif closed.code == "closed":
                recv.abort("the peer closed it with frames still missing")
            else:
                # Anything else is an error for the reader, after the bytes that did arrive.
                recv.abort(f"the peer closed it with code {closed.code}: {closed.reason}")
            if recv is not None and recv.aborted() is not None:
                self._fail_read(closed.stream, StreamReset(closed.stream, recv.aborted() or ""))
            else:
                self._resolve_read(closed.stream, None)
        elif kind == F.PONG:
            pong = _decode(frame)
            if pong is None:
                return
            entry = self._pings.pop(pong.nonce, None)
            if entry is None:
                return
            route, sent = entry
            rtt_ms = (time.monotonic() - sent) * 1000.0
            link = self._find_link(route)
            if link is not None:
                link.stats.probe_ok(rtt_ms)
            self._cc_of(route).on_rtt(rtt_ms / 1000.0)
            self._misses.pop(route, None)
        elif kind == F.ROUTES:
            # The peer's routes are informational: our own measurements decide where our frames go, so a peer
            # cannot talk us onto a worse path.
            _decode(frame)
        elif kind == F.CTRL_ACK:
            receipt = _decode(frame)
            if receipt is not None:
                self._ctrl_unacked.pop(receipt.seq, None)
        elif kind == F.CANDIDATE:
            # A build that agreed on less than the punch version never acts on one.
            if self._version < F.VERSION_PUNCH:
                return
            msg = _decode(frame)
            if msg is not None:
                self._events.put_nowait(SessionEvent(kind="punch", peer=self.peer_node_id, msg=msg))
        elif kind == F.BYE:
            self._stopped = True
        # Any other kind is not one this build knows, and is ignored.

    def _answer_ping(self, frame: Frame, link: Link) -> None:
        ping = _decode(frame)
        if ping is None:
            return
        body = F.encode_body(F.PONG, F.Pong(nonce=ping.nonce, sent_us=ping.sent_us))
        pong = Frame(version=self._version, kind=F.PONG, flags=0, seq=self._next_seq(), body=body)
        if not link.send(pong):
            # The route cannot take even a pong: answer on the best one rather than not at all.
            self._dispatch(pong)

    def _end_reader(self, stream: int) -> None:
        """Tell a waiting reader the stream has ended, once nothing is left to read."""
        recv = self._mux.recv_side(stream)
        ended = recv is None or (recv.finished() and recv.buffered() == 0)
        if ended:
            self._resolve_read(stream, None)

    def _wake_reader(self, stream: int) -> None:
        """Hand buffered bytes to a reader that is waiting for them. With nobody waiting they stay buffered."""
        if stream not in self._pending_reads:
            return
        recv = self._mux.recv_side(stream)
        if recv is None:
            return
        data = recv.take()
        if data is None:
            return
        granted = recv.window_update()
        self._resolve_read(stream, data)
        self._grant_window(stream, granted)

    def _probe(self) -> None:
        """Ping each route once per probe round, and count the pings that were never answered."""
        now = time.monotonic()
        for link in list(self._links):
            last = self._last_probe.get(link.id)
            if last is not None and now - last < PROBE_EVERY:
                continue
            self._last_probe[link.id] = now
            # Once per probe round: the loss and throughput estimates are over the last round.
            link.stats.refresh_loss()
            link.stats.refresh_bandwidth(now)
            # The nonce carries the route, so the answer is credited to the route it came from.
            nonce = (_now_micros() ^ (link.id << 40)) & _MASK64
            self._pings[nonce] = (link.id, now)
            link.stats.probe_sent()
            body = F.encode_body(F.PING, F.Ping(nonce=nonce, sent_us=_now_micros()))
            link.send(Frame(version=self._version, kind=F.PING, flags=0, seq=self._next_seq(), body=body))
        # A ping whose answer never came is a miss; a route that misses several in a row is down until a frame
        # arrives on it again.
        stale = [n for n, (_route, sent) in self._pings.items() if now - sent > RESEND_AFTER * 4]
        for nonce in stale:
            route, _sent = self._pings.pop(nonce)
            misses = self._misses.get(route, 0) + 1
            self._misses[route] = misses
            if misses >= MISSES_DOWN:
                link = self._find_link(route)
                if link is not None:
                    link.stats.mark_down()


def spawn(
    setup: SessionSetup,
    links: Sequence[Link],
    events: "asyncio.Queue[SessionEvent]",
) -> OverlaySession:
    """Start a session over `links`: our hello goes out first, the peer's answer fixes the version."""
    session = OverlaySession(setup, links, events)
    session._start()
    return session
