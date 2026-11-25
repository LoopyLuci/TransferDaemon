/**
 * The driver for the stream engine: streams over an opened session.
 *
 * A `StreamSession` wraps a `Session`. It reads frames and applies them to a `StreamEngine`, writes the frames the
 * engine returns (each with the next session sequence number, sealed), resends reliable control frames until their
 * receipt comes back, and runs the retransmission timer. Application code calls `open`, `nextRequest`, `accept`,
 * `refuse`, `write`, `read` and `close`.
 *
 * Reliable control frames (OPEN, OPEN_OK, OPEN_ERR, WINDOW, CLOSE) are resent every 300 ms until a CTRL_ACK names their
 * sequence number, and each one is acted on once. A session with no receipt for 60 s is ended.
 */
import { SessionError, StreamRefused } from "./errors.js";
import {
  ACK,
  CLOSE,
  CTRL_ACK,
  DATA,
  Frame,
  OPEN,
  OPEN_ERR,
  OPEN_OK,
  PING,
  PONG,
  RELIABLE_KINDS,
  WINDOW,
  type CtrlAck,
  type Ping,
  type Pong,
  type Window,
} from "./frames.js";
import { DEFAULT_WINDOW } from "./mux.js";
import { CONTROL_WINDOW, ReplayWindow } from "./replay.js";
import type { Session } from "./session.js";
import { StreamEngine, type Event, type Outbound } from "./streams.js";
import { writeFrame } from "./tunnel.js";

/** How often a reliable control frame is sent again until its receipt comes back (ms). */
export const CTRL_RESEND_MS = 300;
/** A session with no receipt for a control frame this long is ended (ms). */
export const SESSION_DEAD_AFTER_MS = 60_000;
/** The width, in sequence numbers, of the window that keeps a resent control frame from being acted on twice. */
export const RECEIPT_WINDOW = CONTROL_WINDOW;
/** How much a stream may hold queued before `write` waits for the window to drain it. */
export const WRITE_LIMIT = DEFAULT_WINDOW;
/** How long `close` waits for the peer's receipt of the CLOSE (ms). */
export const CLOSE_RECEIPT_MS = 5000;
/** How often the timer runs (ms). */
const TICK_MS = 20;

const STREAM_KINDS: ReadonlySet<number> = new Set([OPEN, OPEN_OK, OPEN_ERR, DATA, ACK, WINDOW, CLOSE]);

type Request = [number, string];

interface Unreceipted {
  readonly frame: Frame;
  sentAt: number;
  readonly firstAt: number;
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function nowMs(): number {
  return performance.now();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function wake(waiters: Map<number, () => void>, sid: number): void {
  const resolve = waiters.get(sid);
  waiters.delete(sid);
  resolve?.();
}

/** Streams running over one opened session. */
export class StreamSession {
  private readonly session: Session;
  private readonly engine: StreamEngine;
  private nextSeq: number;
  private writeChain: Promise<void> = Promise.resolve();
  private readonly unreceipted = new Map<number, Unreceipted>();
  private readonly seen = new ReplayWindow(RECEIPT_WINDOW);
  private readonly openWaiters = new Map<number, Deferred<void>>();
  private readonly readWaiters = new Map<number, () => void>();
  private readonly drainWaiters = new Map<number, () => void>();
  private readonly requests: Request[] = [];
  private readonly requestWaiters: Array<Deferred<Request>> = [];
  private timer: ReturnType<typeof setInterval> | null = null;
  private ticking = false;
  private dead: Error | null = null;

  /** `odd` picks the half of the id space this end allocates from: the two ends of a session must differ. */
  constructor(session: Session, options: { nodeId: string; odd: boolean }) {
    this.session = session;
    this.engine = new StreamEngine({ odd: options.odd, nodeId: options.nodeId });
    this.nextSeq = 1 + Math.floor(Math.random() * 2 ** 40);
  }

  /** Start the read loop and the timer. */
  start(): void {
    this.timer = setInterval(() => void this.onTimer(), TICK_MS);
    this.timer.unref();
    void this.readLoop();
  }

  /** Stop the timer and fail waiting calls. The read loop ends when the caller closes the transport. */
  aclose(): void {
    this.fail(new SessionError("the stream session was closed"));
  }

  // ----- application calls -----

  /** Open a stream to one of the peer's services. Resolves with its id once the peer accepts it. */
  async open(service: string): Promise<number> {
    this.check();
    const [sid, out] = this.engine.open(service);
    const waiter = deferred<void>();
    this.openWaiters.set(sid, waiter);
    await this.send(out);
    await waiter.promise;
    return sid;
  }

  /** Wait for the peer to open a stream. Resolves with `[stream id, service]`: accept it or refuse it. */
  nextRequest(): Promise<Request> {
    this.check();
    const queued = this.requests.shift();
    if (queued !== undefined) {
      return Promise.resolve(queued);
    }
    const waiter = deferred<Request>();
    this.requestWaiters.push(waiter);
    return waiter.promise;
  }

  /** Accept a stream the peer asked for. */
  async accept(sid: number): Promise<void> {
    await this.send(this.engine.accept(sid));
  }

  /** Refuse a stream the peer asked for. `code` is one of `no_such_service`, `denied`, `rate_limited`, `protocol`. */
  async refuse(sid: number, code = "denied", reason = ""): Promise<void> {
    await this.send(this.engine.refuse(sid, code, reason));
  }

  /**
   * Send bytes on a stream. Waits while too much is queued behind the peer's window. With `fin`, resolves only once
   * every byte has gone out and the end of the stream has been sent, so `close` right after it cannot drop bytes.
   */
  async write(sid: number, data: Uint8Array, fin = false): Promise<void> {
    this.check();
    await this.send(this.engine.write(sid, data, fin, nowMs()));
    const limit = fin ? 0 : WRITE_LIMIT;
    while (this.engine.pending(sid) > limit || (fin && !this.engine.finSentOn(sid))) {
      await new Promise<void>((resolve) => this.drainWaiters.set(sid, resolve));
      this.check();
    }
  }

  /** Read the next bytes of a stream. Resolves with an empty array once the stream has ended. */
  async read(sid: number): Promise<Uint8Array> {
    for (;;) {
      this.check();
      const [data, out] = this.engine.read(sid);
      if (out.length > 0) {
        await this.send(out);
      }
      if (data !== null) {
        return data;
      }
      await new Promise<void>((resolve) => this.readWaiters.set(sid, resolve));
    }
  }

  /**
   * Close a stream. Its state is dropped on this side at once, so bytes still queued are dropped too: `write` with
   * `fin` first, and close after it resolves. Waits up to 5 s for the peer's receipt of the CLOSE, so that a caller
   * tearing the transport down straight after does not reset the connection before the peer reads it.
   */
  async close(sid: number, code = "closed", reason = ""): Promise<void> {
    const receipts = await this.send(this.engine.close(sid, code, reason));
    wake(this.readWaiters, sid);
    wake(this.drainWaiters, sid);
    const deadline = nowMs() + CLOSE_RECEIPT_MS;
    while (receipts.some((seq) => this.unreceipted.has(seq)) && this.dead === null && nowMs() < deadline) {
      await sleep(5);
    }
  }

  // ----- tasks -----

  private async readLoop(): Promise<void> {
    try {
      for (;;) {
        const frame = await this.session.inbound.nextFrame(this.session.link.input);
        await this.handle(frame);
      }
    } catch (error) {
      this.fail(error instanceof Error ? error : new SessionError(String(error)));
    }
  }

  private async onTimer(): Promise<void> {
    if (this.dead !== null || this.ticking) {
      return;
    }
    this.ticking = true;
    try {
      await this.send(this.engine.tick(nowMs()));
      const now = nowMs();
      for (const entry of [...this.unreceipted.values()]) {
        if (now - entry.firstAt > SESSION_DEAD_AFTER_MS) {
          throw new SessionError("no receipt for a control frame in 60 s: the session ends");
        }
        if (now - entry.sentAt >= CTRL_RESEND_MS) {
          entry.sentAt = now;
          await this.emit(entry.frame);
        }
      }
    } catch (error) {
      this.fail(error instanceof Error ? error : new SessionError(String(error)));
    } finally {
      this.ticking = false;
    }
  }

  private async handle(frame: Frame): Promise<void> {
    if (frame.kind === CTRL_ACK) {
      this.unreceipted.delete((frame.decode() as CtrlAck).seq);
      return;
    }
    if (RELIABLE_KINDS.has(frame.kind)) {
      // Every copy is answered, and each sequence number is acted on once.
      const receipt: CtrlAck = { seq: frame.seq };
      await this.emit(Frame.withBody(this.session.version, CTRL_ACK, this.seqNext(), receipt));
      if (!this.seen.accept(frame.seq)) {
        return;
      }
    }
    if (frame.kind === PING) {
      const ping = frame.decode() as Ping;
      const pong: Pong = { nonce: ping.nonce, sentUs: ping.sentUs };
      await this.send([{ kind: PONG, body: pong }]);
      return;
    }
    if (!STREAM_KINDS.has(frame.kind)) {
      return;
    }
    const body = frame.decode();
    const [out, events] = this.engine.onFrame(frame.kind, body, nowMs());
    await this.send(out);
    if (frame.kind === WINDOW) {
      wake(this.drainWaiters, (body as Window).stream);
    }
    for (const event of events) {
      this.dispatch(event);
    }
  }

  private dispatch(event: Event): void {
    switch (event.kind) {
      case "open_request": {
        const request: Request = [event.stream, event.service ?? ""];
        const waiter = this.requestWaiters.shift();
        if (waiter !== undefined) {
          waiter.resolve(request);
        } else {
          this.requests.push(request);
        }
        return;
      }
      case "open_ok":
        this.openWaiters.get(event.stream)?.resolve(undefined);
        this.openWaiters.delete(event.stream);
        return;
      case "open_err":
        this.openWaiters.get(event.stream)?.reject(new StreamRefused(event.code ?? "", event.reason ?? ""));
        this.openWaiters.delete(event.stream);
        return;
      case "readable":
        wake(this.readWaiters, event.stream);
        return;
      case "closed":
        wake(this.readWaiters, event.stream);
        wake(this.drainWaiters, event.stream);
        return;
    }
  }

  // ----- plumbing -----

  /** Send the engine's messages. Returns the sequence numbers of the reliable ones, which await a receipt. */
  private async send(out: Outbound[]): Promise<number[]> {
    const reliable: number[] = [];
    for (const message of out) {
      const frame = Frame.withBody(this.session.version, message.kind, this.seqNext(), message.body);
      if (RELIABLE_KINDS.has(message.kind)) {
        const now = nowMs();
        this.unreceipted.set(frame.seq, { frame, sentAt: now, firstAt: now });
        reliable.push(frame.seq);
      }
      await this.emit(frame);
    }
    return reliable;
  }

  /** Seal and write one frame. Writes are serialised, so the sealer's counter is used in order. */
  private emit(frame: Frame): Promise<void> {
    const next = this.writeChain.then(() => writeFrame(this.session.link.output, this.session.sealer, frame));
    this.writeChain = next.catch(() => undefined);
    return next;
  }

  private seqNext(): number {
    const seq = this.nextSeq;
    this.nextSeq += 1;
    return seq;
  }

  private fail(error: Error): void {
    if (this.dead !== null) {
      return;
    }
    this.dead = error;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    for (const [sid, waiter] of this.openWaiters) {
      waiter.reject(new SessionError("the session ended before the stream opened"));
      this.openWaiters.delete(sid);
    }
    for (const waiter of this.requestWaiters.splice(0)) {
      waiter.reject(new SessionError("the session ended before a stream was requested"));
    }
    for (const sid of [...this.readWaiters.keys()]) {
      wake(this.readWaiters, sid);
    }
    for (const sid of [...this.drainWaiters.keys()]) {
      wake(this.drainWaiters, sid);
    }
  }

  private check(): void {
    if (this.dead !== null) {
      throw new SessionError("the stream session has ended");
    }
  }
}
