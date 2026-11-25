"""Routes: the kinds of path a session can use, what is measured about each, and the links that carry frames.

Mirrors `crates/transferd-overlay/src/link.rs` (`RouteKind`, `RouteStats`, `RouteMetrics`, `best_route`) and the
frame-carrying links of `crates/transferd-overlay/src/lanes.rs` (`FramePipe`). A session has one route per live
link to its peer. Every route is probed about once a second, and frames go out on the cheapest live one.
"""

from __future__ import annotations

import asyncio
import collections
import enum
import math
import time
from dataclasses import dataclass
from typing import Callable, Deque, List, Optional, Sequence, Tuple

from .frames import Frame
from .tunnel import LinkKeys, Sealer, TunnelReader
from .wire import read_blob, write_blob

#: How many sealed frames a link may queue for its socket before it reports congestion.
SEND_QUEUE = 256
#: How many sealed control and interactive frames a link may queue. They are sent first, so bulk never holds them up.
CONTROL_QUEUE = 512
#: How many inbound frames a link buffers before it stops taking more.
RECV_QUEUE = 1024


class RouteKind(str, enum.Enum):
    """The kind of path a link is, as reported in the route table."""

    DIRECT = "direct"
    LAN = "lan"
    HOLEPUNCH = "holepunch"
    RELAY = "relay"
    WS_RELAY = "ws_relay"
    TAILSCALE = "tailscale"

    @property
    def rank(self) -> int:
        """Routes worth preferring when both work: cheaper is better. Ties in cost break on this."""
        return _RANK[self]

    @property
    def scheme(self) -> Optional[str]:
        """The `scheme://` prefix this kind is published with, when it has one."""
        return _SCHEME[self]

    @classmethod
    def parse(cls, name: str) -> Optional["RouteKind"]:
        try:
            return cls(name)
        except ValueError:
            return None


_RANK = {
    RouteKind.LAN: 0,
    RouteKind.TAILSCALE: 1,
    RouteKind.HOLEPUNCH: 2,
    RouteKind.DIRECT: 3,
    RouteKind.RELAY: 5,
    RouteKind.WS_RELAY: 6,
}

_SCHEME = {
    RouteKind.DIRECT: "tcp",
    RouteKind.LAN: "tcp",
    RouteKind.TAILSCALE: "tcp",
    RouteKind.HOLEPUNCH: "udp",
    RouteKind.RELAY: "relay",
    RouteKind.WS_RELAY: "wsrelay",
}


@dataclass(frozen=True)
class RouteMetrics:
    """A snapshot of what was measured about one route."""

    rtt_ms: float = 0.0
    loss: float = 0.0
    mbps: float = 0.0
    active: int = 0
    #: Wire bytes handed to this route and not yet acknowledged: the backlog the route must clear first.
    outstanding_bytes: int = 0
    up: bool = False

    def cost(self) -> float:
        """The score the router minimises: time to push the next frame out on this route.

        The backlog is charged in time at the route's measured speed, and loss quadratically, so a dead route never
        wins however good its old numbers were.
        """
        if not self.up:
            return math.inf
        bps = max(self.mbps * 1_000_000.0, 1.0)
        backlog_ms = self.outstanding_bytes * 8.0 / bps * 1000.0
        return self.rtt_ms + backlog_ms + self.loss * self.loss * 1000.0


class RouteStats:
    """Rolling statistics for one route, updated by the prober and by real traffic."""

    def __init__(self, kind: RouteKind, now: Optional[float] = None) -> None:
        self.kind = kind
        self._rtt_ms = 0.0
        self._loss = 0.0
        self._mbps = 0.0
        self._active = 0
        self._outstanding_bytes = 0
        self._up = True
        self._sent = 0
        self._bytes = 0
        self._last_bytes = 0
        self._last_sample = time.monotonic() if now is None else now
        self._probes_sent = 0
        self._probes_ok = 0

    def record_rtt(self, ms: float) -> None:
        """Fold a round-trip measurement in (exponential average, so one spike does not dominate)."""
        self._rtt_ms = ms if self._rtt_ms <= 0.0 else self._rtt_ms * 0.7 + ms * 0.3

    def probe_sent(self) -> None:
        self._probes_sent += 1

    def probe_ok(self, rtt_ms: float) -> None:
        """One probe answered: count it, fold in the round trip, and the route is up."""
        self._probes_ok += 1
        self.record_rtt(rtt_ms)
        self.mark_up()

    def refresh_loss(self) -> None:
        """Recompute the loss estimate. Called once per probe round."""
        estimate = 0.0 if self._probes_sent == 0 else 1.0 - min(self._probes_ok / self._probes_sent, 1.0)
        self._loss = max(self._loss * 0.5, 0.0) + estimate * 0.5
        self._probes_sent = 0
        self._probes_ok = 0

    def record_sent(self, nbytes: int) -> None:
        """A frame of `nbytes` went out on this route, of any kind."""
        self._sent += 1
        self._bytes += nbytes

    def record_data_out(self, wire_bytes: int) -> None:
        """A data frame of `wire_bytes` went out and now awaits its acknowledgement.

        Only data frames are counted: a control frame, a ping or an acknowledgement never gets one back.
        """
        self._active += 1
        self._outstanding_bytes += wire_bytes

    def record_acked(self, wire_bytes: int) -> None:
        """A data frame of `wire_bytes` left this route's books: acknowledged, or given up on."""
        self._active = max(0, self._active - 1)
        self._outstanding_bytes = max(0, self._outstanding_bytes - wire_bytes)

    def refresh_bandwidth(self, now: Optional[float] = None) -> None:
        """Recompute throughput from the byte counter. Called once per probe round."""
        now = time.monotonic() if now is None else now
        total = self._bytes
        prev = self._last_bytes
        self._last_bytes = total
        elapsed = max(now - self._last_sample, 0.001)
        self._last_sample = now
        mbps = (total - prev) * 8.0 / elapsed / 1_000_000.0
        self._mbps = mbps if self._mbps <= 0.0 else self._mbps * 0.7 + mbps * 0.3

    def mark_down(self) -> None:
        self._up = False

    def mark_up(self) -> None:
        self._up = True

    @property
    def up(self) -> bool:
        return self._up

    def metrics(self) -> RouteMetrics:
        return RouteMetrics(
            rtt_ms=self._rtt_ms,
            loss=self._loss,
            mbps=self._mbps,
            active=self._active,
            outstanding_bytes=self._outstanding_bytes,
            up=self._up,
        )

    def frames_sent(self) -> int:
        return self._sent


class Link:
    """One route to a peer. Subclasses move the frames; this base holds the identity and the statistics."""

    _next_id = 1

    def __init__(self, kind: RouteKind, *, describe: str = "", link_id: Optional[int] = None, now: Optional[float] = None) -> None:
        if link_id is None:
            link_id = Link._next_id
            Link._next_id += 1
        self.id = link_id
        self.kind = kind
        self.stats = RouteStats(kind, now)
        self.describe = describe or kind.value
        self._closed = False
        self._waker: Optional[Callable[[], None]] = None

    def set_waker(self, callback: Callable[[], None]) -> None:
        """Called when a frame arrives, so the session reads it at once instead of at its next tick."""
        self._waker = callback

    def _wake(self) -> None:
        if self._waker is not None:
            self._waker()

    def is_up(self) -> bool:
        return self.stats.up and not self._closed

    def is_closed(self) -> bool:
        """Gone for good (its transport closed), as opposed to merely down (not answering probes for now)."""
        return self._closed

    def mark_down(self) -> None:
        self.stats.mark_down()

    def send(self, frame: Frame) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError

    def try_recv(self) -> Optional[Frame]:  # pragma: no cover - overridden
        raise NotImplementedError

    def close(self) -> None:
        self._closed = True
        self.stats.mark_down()


def ranked_routes(links: Sequence[Link]) -> List[Link]:
    """Every route that is not closed, cheapest first. Ties break on the kind's rank; a route that is down costs
    infinity, so it comes last. The session walks this list when the cheapest route refuses a frame."""

    def key(link: Link) -> Tuple[float, int]:
        return (link.stats.metrics().cost(), link.kind.rank)

    return sorted((l for l in links if not l.is_closed()), key=key)


def best_route(links: Sequence[Link]) -> Optional[Link]:
    """The live route with the lowest cost; ties break on the kind's rank.

    With nothing live, the best route that is not closed is returned rather than nothing: with one route,
    refusing it would only stop the session healing.
    """
    ranked = ranked_routes(links)
    for link in ranked:
        if link.is_up():
            return link
    return ranked[0] if ranked else None


class MemoryLink(Link):
    """Two ends of an in-memory route: each end's sends land in the other end's inbox.

    The tests use these to run whole sessions without sockets. Like the reference's `PipeLink`, a link that was
    marked down still delivers; only `best_route` stops choosing it.
    """

    def __init__(self, kind: RouteKind = RouteKind.DIRECT, *, link_id: Optional[int] = None, describe: str = "memory") -> None:
        super().__init__(kind, describe=describe, link_id=link_id)
        self._peer: Optional["MemoryLink"] = None
        self._inbox: Deque[Frame] = collections.deque()

    @classmethod
    def pair(cls, kind: RouteKind = RouteKind.DIRECT, *, first_id: Optional[int] = None, second_id: Optional[int] = None) -> Tuple["MemoryLink", "MemoryLink"]:
        a = cls(kind, link_id=first_id)
        b = cls(kind, link_id=second_id)
        a._peer = b
        b._peer = a
        return a, b

    def send(self, frame: Frame) -> bool:
        peer = self._peer
        if self._closed or peer is None or peer._closed or len(peer._inbox) >= RECV_QUEUE:
            return False
        peer._inbox.append(frame)
        self.stats.record_sent(len(frame.body))
        peer._wake()
        return True

    def try_recv(self) -> Optional[Frame]:
        return self._inbox.popleft() if self._inbox else None


class TcpLink(Link):
    """A route over one TCP connection whose handshake has completed.

    Frames are sealed when they are sent and opened when they arrive. Reading and writing run as tasks, so `send`
    and `try_recv` never wait: a full send queue reports congestion and the session tries again on its next tick.
    Needs a running event loop (`start`).
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        keys: LinkKeys,
        *,
        kind: RouteKind = RouteKind.DIRECT,
        link_id: Optional[int] = None,
        describe: str = "tcp",
        now: Optional[float] = None,
    ) -> None:
        super().__init__(kind, describe=describe, link_id=link_id, now=now)
        self._reader = reader
        self._writer = writer
        self._sealer = Sealer(keys.send)
        self._inbound = TunnelReader(keys)
        # Bulk frames go out after the control queue, so a window update or a stream open never waits behind bulk.
        self._outbox: Deque[bytes] = collections.deque()
        self._control: Deque[bytes] = collections.deque()
        self._inbox: Deque[Frame] = collections.deque()
        self._outwake = asyncio.Event()
        self._room = asyncio.Event()  # set when the reader may take a frame again
        self._tasks: List[asyncio.Task] = []

    def start(self) -> None:
        """Start the read and write tasks."""
        loop = asyncio.get_running_loop()
        self._tasks = [loop.create_task(self._read_loop()), loop.create_task(self._write_loop())]

    def send(self, frame: Frame) -> bool:
        queue, limit = (self._outbox, SEND_QUEUE) if frame.is_bulk else (self._control, CONTROL_QUEUE)
        if self._closed or len(queue) >= limit:
            return False
        queue.append(self._sealer.seal(frame.encode()))
        self.stats.record_sent(len(frame.body))
        self._outwake.set()
        return True

    def try_recv(self) -> Optional[Frame]:
        if not self._inbox:
            return None
        frame = self._inbox.popleft()
        self._room.set()
        return frame

    def close(self) -> None:
        super().close()
        for task in self._tasks:
            task.cancel()
        self._writer.close()

    async def _read_loop(self) -> None:
        try:
            while True:
                # While the inbox is full the socket is not read: the frames wait in TCP, so nothing is dropped.
                while len(self._inbox) >= RECV_QUEUE:
                    self._room.clear()
                    await self._room.wait()
                frame = await self._inbound.next_frame(self._reader)
                self.stats.mark_up()
                self._inbox.append(frame)
                self._wake()
        except asyncio.CancelledError:
            raise
        except Exception:
            self._fail()

    async def _write_loop(self) -> None:
        try:
            while True:
                while not self._control and not self._outbox:
                    self._outwake.clear()
                    await self._outwake.wait()
                sealed = self._control.popleft() if self._control else self._outbox.popleft()
                await write_blob(self._writer, sealed)
        except asyncio.CancelledError:
            raise
        except Exception:
            self._fail()

    def _fail(self) -> None:
        self._closed = True
        self.stats.mark_down()
        self._wake()

