"""The asyncio driver for the stream engine: streams over an opened session.

A `StreamSession` wraps a `session.Session`. It reads frames and applies them to a `streams.StreamEngine`, writes the
frames the engine returns (each with the next session sequence number, sealed), resends reliable control frames until
their receipt comes back, and runs the retransmission timer. Application code calls `open`, `next_request`, `accept`,
`refuse`, `write`, `read` and `close`.

Reliable control frames (OPEN, OPEN_OK, OPEN_ERR, WINDOW, CLOSE) are resent every 300 ms until a CTRL_ACK names their
sequence number, and each one is acted on once. A session with no receipt for 60 s is ended.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from typing import Dict, List, Optional, Tuple

from . import frames as F
from .errors import SessionError, StreamRefused
from .frames import Frame
from .mux import DEFAULT_WINDOW
from .replay import CONTROL_WINDOW, ReplayWindow
from .session import Session
from .streams import Event, StreamEngine
from .tunnel import write_frame

#: How often a reliable control frame is sent again until its receipt comes back (ms).
CTRL_RESEND_MS = 300.0
#: A session with no receipt for a control frame this long is ended (ms).
SESSION_DEAD_AFTER_MS = 60_000.0
#: The width, in sequence numbers, of the window that keeps a resent control frame from being acted on twice.
RECEIPT_WINDOW = CONTROL_WINDOW
#: How long `close` waits for the peer's receipt of the CLOSE (seconds).
CLOSE_RECEIPT_SECONDS = 5.0
#: How long `close` waits for the peer to acknowledge what was written before it sends `closed` (seconds).
FLUSH_SECONDS = 5.0
#: How much a stream may hold queued before `write` waits for the window to drain it.
WRITE_LIMIT = DEFAULT_WINDOW
#: How often the timer runs (seconds).
TICK_SECONDS = 0.02

_STREAM_KINDS = frozenset({F.OPEN, F.OPEN_OK, F.OPEN_ERR, F.DATA, F.ACK, F.WINDOW, F.CLOSE})


def _now_ms() -> float:
    return time.monotonic() * 1000.0


class StreamSession:
    """Streams running over one opened session. Create it with `StreamSession(session, node_id=..., odd=...)`."""

    def __init__(self, session: Session, *, node_id: str, odd: bool) -> None:
        self._session = session
        self._engine = StreamEngine(odd=odd, node_id=node_id)
        self._next_seq = secrets.randbits(40) + 1
        self._write_lock = asyncio.Lock()
        # Reliable control frames waiting for their receipt: seq -> (frame, last sent, first sent), in ms.
        self._unreceipted: Dict[int, Tuple[Frame, float, float]] = {}
        self._seen = ReplayWindow(RECEIPT_WINDOW)
        self._open_waiters: Dict[int, asyncio.Future] = {}
        self._read_waiters: Dict[int, asyncio.Future] = {}
        self._drain_waiters: Dict[int, asyncio.Future] = {}
        self._requests: asyncio.Queue = asyncio.Queue()
        self._tasks: list = []
        self._dead: Optional[BaseException] = None

    def start(self) -> None:
        """Start the read loop and the timer. Call this once, inside the running event loop."""
        loop = asyncio.get_running_loop()
        self._tasks = [loop.create_task(self._read_loop()), loop.create_task(self._timers())]

    async def aclose(self) -> None:
        """Stop the driver. Waiting calls fail with `SessionError`. The transport is left to the caller."""
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._fail(SessionError("the stream session was closed"))

    # ----- application calls -----

    async def open(self, service: str) -> int:
        """Open a stream to one of the peer's services. Returns its id once the peer accepts it."""
        self._check()
        sid, out = self._engine.open(service, _now_ms())
        waiter = asyncio.get_running_loop().create_future()
        self._open_waiters[sid] = waiter
        await self._send(out)
        await waiter
        return sid

    async def next_request(self) -> Tuple[int, str]:
        """Wait for the peer to open a stream. Returns `(stream id, service)`: accept it or refuse it."""
        self._check()
        return await self._requests.get()

    async def accept(self, sid: int) -> None:
        """Accept a stream the peer asked for."""
        await self._send(self._engine.accept(sid, _now_ms()))

    async def refuse(self, sid: int, code: str = "denied", reason: str = "") -> None:
        """Refuse a stream the peer asked for. `code` is one of `no_such_service`, `denied`, `rate_limited`, `protocol`."""
        await self._send(self._engine.refuse(sid, code, reason))

    async def write(self, sid: int, data: bytes, *, fin: bool = False) -> None:
        """Send bytes on a stream. Waits while too much is queued behind the peer's window.

        With `fin`, returns only once every byte has gone out and the end of the stream has been sent, so
        `close` right after it cannot drop bytes that were still queued.
        """
        self._check()
        await self._send(self._engine.write(sid, bytes(data), fin, _now_ms()))
        limit = 0 if fin else WRITE_LIMIT
        while self._engine.pending(sid) > limit or (fin and not self._engine.fin_sent(sid)):
            waiter = asyncio.get_running_loop().create_future()
            self._drain_waiters[sid] = waiter
            await waiter
            self._check()

    async def read(self, sid: int) -> bytes:
        """Read the next bytes of a stream. Returns `b""` once the stream has ended cleanly. Raises `StreamReset` if it
        ended with an error (reset, refused, or never open here), after the bytes that arrived before it."""
        while True:
            self._check()
            data, out = self._engine.read(sid, _now_ms())
            if out:
                await self._send(out)
            if data is not None:
                return data
            waiter = asyncio.get_running_loop().create_future()
            self._read_waiters[sid] = waiter
            await waiter

    async def close(self, sid: int, code: str = "closed", reason: str = "") -> None:
        """Close a stream. With code `closed`, every byte written to it goes out first, then its end, and the peer is told the stream
        closed cleanly once it has acknowledged them. If that does not happen within `FLUSH_SECONDS`, the peer is told
        `reset` instead.

        Then waits, up to 5 s, for the peer's receipt of the CLOSE. Without it a caller that tears the transport down
        straight after could reset the connection before the peer reads its CLOSE.
        """
        if code == "closed":
            await self._send(self._engine.finish(sid, _now_ms()))
            if not await self._flushed(sid):
                code, reason = "reset", "the stream could not be flushed in time"
        receipts = await self._send(self._engine.close(sid, code, reason))
        self._wake(self._read_waiters, sid)
        self._wake(self._drain_waiters, sid)
        deadline = time.monotonic() + CLOSE_RECEIPT_SECONDS
        while any(seq in self._unreceipted for seq in receipts) and self._dead is None:
            if time.monotonic() >= deadline:
                break
            await asyncio.sleep(0.005)

    async def _flushed(self, sid: int) -> bool:
        """Wait until everything written to the stream, its end included, is acknowledged, or `FLUSH_SECONDS` pass."""
        deadline = time.monotonic() + FLUSH_SECONDS
        while self._dead is None:
            if self._engine.flushed(sid):
                return True
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(0.005)
        return False

    # ----- tasks -----

    async def _read_loop(self) -> None:
        try:
            while True:
                frame = await self._session.inbound.next_frame(self._session.reader)
                await self._handle(frame)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # the transport ended, or a frame did not authenticate
            self._fail(exc)

    async def _timers(self) -> None:
        try:
            while True:
                await asyncio.sleep(TICK_SECONDS)
                now = _now_ms()
                await self._send(self._engine.tick(now))
                for seq, (frame, sent, first) in list(self._unreceipted.items()):
                    if now - first > SESSION_DEAD_AFTER_MS:
                        raise SessionError("no receipt for a control frame in 60 s: the session ends")
                    if now - sent >= CTRL_RESEND_MS:
                        self._unreceipted[seq] = (frame, now, first)
                        await self._write(frame)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            self._fail(exc)

    async def _handle(self, frame: Frame) -> None:
        if frame.kind == F.CTRL_ACK:
            self._unreceipted.pop(frame.decode().seq, None)
            return
        if frame.kind in F.RELIABLE_KINDS:
            # Every copy is answered, and each sequence number is acted on once.
            await self._write(Frame.with_body(self._session.version, F.CTRL_ACK, self._seq_next(), F.CtrlAck(seq=frame.seq)))
            if not self._seen.accept(frame.seq):
                return
        if frame.kind == F.PING:
            ping = frame.decode()
            await self._send([(F.PONG, F.Pong(nonce=ping.nonce, sent_us=ping.sent_us))])
            return
        if frame.kind not in _STREAM_KINDS:
            return
        body = frame.decode()
        out, events = self._engine.on_frame(frame.kind, body, _now_ms())
        await self._send(out)
        if frame.kind == F.WINDOW:
            self._wake(self._drain_waiters, body.stream)
        for event in events:
            self._dispatch(event)

    def _dispatch(self, event: Event) -> None:
        if event.kind == "open_request":
            self._requests.put_nowait((event.stream, event.service))
        elif event.kind == "open_ok":
            self._resolve(self._open_waiters, event.stream, None)
        elif event.kind == "open_err":
            self._resolve(self._open_waiters, event.stream, StreamRefused(event.code, event.reason))
        elif event.kind in ("readable", "closed"):
            self._wake(self._read_waiters, event.stream)
            if event.kind == "closed":
                self._wake(self._drain_waiters, event.stream)

    # ----- plumbing -----

    async def _send(self, out) -> List[int]:
        """Write the engine's frames. Returns the sequence numbers of the reliable ones, which await a receipt."""
        reliable: List[int] = []
        for kind, body in out:
            frame = Frame.with_body(self._session.version, kind, self._seq_next(), body)
            if kind in F.RELIABLE_KINDS:
                now = _now_ms()
                self._unreceipted[frame.seq] = (frame, now, now)
                reliable.append(frame.seq)
            await self._write(frame)
        return reliable

    async def _write(self, frame: Frame) -> None:
        async with self._write_lock:
            await write_frame(self._session.writer, self._session.sealer, frame)

    def _seq_next(self) -> int:
        seq = self._next_seq
        self._next_seq += 1
        return seq

    @staticmethod
    def _wake(waiters: Dict[int, asyncio.Future], sid: int) -> None:
        waiter = waiters.pop(sid, None)
        if waiter is not None and not waiter.done():
            waiter.set_result(None)

    @staticmethod
    def _resolve(waiters: Dict[int, asyncio.Future], sid: int, error: Optional[BaseException]) -> None:
        waiter = waiters.pop(sid, None)
        if waiter is None or waiter.done():
            return
        if error is None:
            waiter.set_result(None)
        else:
            waiter.set_exception(error)

    def _fail(self, exc: BaseException) -> None:
        if self._dead is not None:
            return
        self._dead = exc
        for sid in list(self._open_waiters):
            self._resolve(self._open_waiters, sid, SessionError("the session ended before the stream opened"))
        for waiters in (self._read_waiters, self._drain_waiters):
            for sid in list(waiters):
                self._wake(waiters, sid)

    def _check(self) -> None:
        if self._dead is not None:
            raise SessionError("the stream session has ended") from self._dead
