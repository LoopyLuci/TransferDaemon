/**
 * One peer's overlay session: the routes to it, the streams over those routes, and the timers that keep them moving.
 *
 * Mirrors `crates/transferd-overlay/src/session.rs` and `python/transferd/overlay.py`. A session owns a set of routes
 * (`link.ts`) and a `Mux`. Everything that decides where bytes go happens here:
 *
 * - Best route per flow: control frames and single data frames take the cheapest live route (`bestRoute`).
 * - Failover mid-stream: unacknowledged frames are re-sent over another route; every data frame carries
 *   `(stream, seq)`, so the peer reassembles them into the same byte stream.
 * - Striping: a bulk stream is split across the live routes, weighted by measured throughput.
 * - Flow control: each stream advertises a window; writes wait for credit rather than being dropped.
 * - Congestion control: every route has its own window, round-trip estimate and timeout (`cc.ts`).
 * - Control receipts: reliable control frames are resent until the peer's CTRL_ACK comes back.
 *
 * The engine is single-threaded: every method that changes its state is synchronous, so no state is seen half
 * updated. Timers drive it: a tick every 20 ms, a pacing timer, and a coalesced "kick" when a route has a frame.
 * The public methods are async for symmetry with the reference handle.
 */

import { randomBytes } from "node:crypto";
import { type CtrlAck, type Data, type Hello, type HelloAck, type Ack, type Close, type Open, type OpenErr, type OpenOk, type Pong, type Ping, type PunchMsg, type RouteReport, type ServiceInfo, type Window, Frame, encodeBody, negotiate, HELLO, HELLO_ACK, OPEN, OPEN_OK, OPEN_ERR, DATA, ACK, WINDOW, CLOSE, CTRL_ACK, PING, PONG, ROUTES, CANDIDATE, BYE, FLAG_BULK, FLAG_MIRROR, RELIABLE_KINDS, VERSION_MIN, VERSION_CURRENT, VERSION_PUNCH } from "./frames.js";
import { Mux, type OutFrame, type SendSide, type RecvSide } from "./mux.js";
import { CONTROL_WINDOW, ReplayWindow } from "./replay.js";
import { INITIAL_RTO, MSS, RouteCc, cost as wireCost } from "./cc.js";
import { Route, bestRoute, nowSeconds, rankedRoutes } from "./link.js";
import { EventQueue } from "./queue.js";
import { Closed, Denied, NoSuchService, OverlayError, RateLimited, TransferdError, Unreachable } from "./errors.js";
import type { HybridIdentity } from "./identity.js";

/** How often the session ticks, in milliseconds. */
export const TICK_MS = 20;
/** How often the prober pings each route, in seconds. */
export const PROBE_EVERY = 1.0;
/** How long an unanswered ping may wait before it counts as missed (a multiple of this), in seconds. */
export const RESEND_AFTER = 0.4;
/** The most frames one reported selective-acknowledgement range is believed to span. */
export const MAX_SACK_SPAN = 1024;
/** How many ranges of frames beyond a gap an acknowledgement reports. */
export const SACK_RANGES = 4;
/** Duplicate acknowledgements in a row that show a frame was lost without waiting for its timeout. */
export const DUP_ACKS = 3;
/** Unanswered pings in a row before a route counts as down. */
export const MISSES_DOWN = 3;
/** How long a control frame waits for its receipt before it goes out again, in seconds. */
export const CTRL_RESEND = 0.3;
/** How long a control frame is resent before the peer is taken to be gone, in seconds. */
export const CTRL_GIVE_UP = 60;
/** How long `open` waits for the peer to accept or refuse a stream, in milliseconds. */
export const OPEN_TIMEOUT_MS = 15_000;
/** A frame this big or bigger is treated as bulk: striped across routes rather than pinned. */
export const BULK_THRESHOLD = 4096;

const MASK64 = (1n << 64n) - 1n;

/** What the session tells the node. The optional fields say what each kind carries. */
export interface SessionEvent {
  kind: "hello" | "ready" | "refused" | "route_changed" | "open_request" | "punch" | "down";
  peer: string;
  name?: string;
  ext?: Uint8Array;
  version?: number;
  services?: ServiceInfo[];
  reason?: string;
  route?: Route["kind"];
  up?: boolean;
  stream?: number;
  service?: string;
  msg?: PunchMsg;
}

/** Who a session is with and what we tell it about ourselves. */
export interface SessionSetup {
  peerNodeId: string;
  peerName: string;
  identity: HybridIdentity;
  /** The services we expose, for our hello. */
  services?: ServiceInfo[];
  /** The highest protocol version to offer. */
  maxVersion?: number;
  /** Our hello's extension bytes. */
  ext?: Uint8Array;
}

interface InFlight {
  route: number;
  cost: number;
  sentAt: number;
  /** A resend: its acknowledgement says nothing about the round trip. */
  retx: boolean;
}

interface WriteEntry {
  chunks: Uint8Array[];
  /** The application said this was the last write for the stream. */
  fin: boolean;
}

interface PendingOpen {
  service: string;
  resolve: (stream: number) => void;
  reject: (error: Error) => void;
}

function round3(v: number): number {
  return Number.isFinite(v) ? Math.round(v * 1000) / 1000 : 0;
}

function nowMicros(): bigint {
  return BigInt(Date.now()) * 1000n;
}

function equalBytes(a: Uint8Array, b: Uint8Array | null): boolean {
  if (b === null || a.length !== b.length) {
    return false;
  }
  return a.every((value, i) => value === b[i]);
}

function decodeAs<T>(frame: Frame): T | null {
  try {
    return frame.decode() as T;
  } catch (error) {
    if (error instanceof TransferdError) {
      return null;
    }
    throw error;
  }
}

/** Whether any of these routes is up. Nothing measured yet counts as usable: the session has only just been made. */
export function routesUsable(routes: readonly RouteReport[]): boolean {
  return routes.length === 0 || routes.some((r) => r.active);
}

/**
 * A session with one peer: the handle the node calls, and the engine that runs its routes and streams.
 * Build one with `spawn`. Its events queue receives `SessionEvent`s; the node answers `open_request` with `authorize`.
 */
export class OverlaySession {
  readonly peerNodeId: string;
  /** The peer's display name: the one it was given, then the one its hello announces. */
  peerName: string;
  /** The services the peer advertised, refreshed on every hello. */
  services: ServiceInfo[] = [];

  private readonly mux: Mux;
  private readonly local: Hello;
  private readonly links: Route[];
  private readonly events: EventQueue<SessionEvent>;
  private wireVersion: number;
  private agreed = 0;
  private frameSeq: number;
  private established = false;
  private stopped = false;
  private finished = false;
  private kickPending = false;
  private tickTimer: ReturnType<typeof setInterval> | null = null;
  private paceTimer: ReturnType<typeof setTimeout> | null = null;
  private publishedRoutes: RouteReport[] = [];

  private readonly lastProbe = new Map<number, number>();
  private readonly cc = new Map<number, RouteCc>();
  /** Every data frame on the wire and not acknowledged, by stream, then by sequence number. */
  private readonly inflight = new Map<number, Map<number, InFlight>>();
  private outbox: OutFrame[] = [];
  /** Frames given up on and waiting to go out again, with the route that lost them. */
  private retxQueue: Array<{ frame: OutFrame; route: number }> = [];
  private readonly retxPending = new Set<string>();
  private readonly dupAcks = new Map<number, [number, number]>();
  private readonly recover = new Map<number, number>();
  private readonly highSack = new Map<number, number>();
  private readonly lastAck = new Map<number, number>();
  private readonly pings = new Map<bigint, { route: number; sent: number }>();
  private readonly misses = new Map<number, number>();
  private readonly pendingReads = new Map<
    number,
    { resolve: (data: Uint8Array | null) => void; reject: (error: Error) => void }
  >();
  private readonly writeQueue = new Map<number, WriteEntry>();
  private readonly pendingOpens = new Map<number, string>();
  private readonly awaitingOpen = new Map<number, PendingOpen & { timer: ReturnType<typeof setTimeout> }>();
  private readonly ctrlUnacked = new Map<number, { frame: Frame; first: number; last: number }>();
  private ctrlSeen = new ReplayWindow(CONTROL_WINDOW);
  /** The nonce of the last hello the peer sent: a new one means the peer restarted (see `noteHello`). */
  private peerHelloNonce: Uint8Array | null = null;

  constructor(setup: SessionSetup, links: readonly Route[], events: EventQueue<SessionEvent>) {
    this.peerNodeId = setup.peerNodeId;
    this.peerName = setup.peerName;
    const identity = setup.identity;
    // The two ends allocate stream ids from different halves, decided by who has the lower node id.
    this.mux = new Mux(identity.nodeId < setup.peerNodeId);
    this.wireVersion = setup.maxVersion ?? VERSION_CURRENT;
    this.local = {
      minVersion: VERSION_MIN,
      maxVersion: setup.maxVersion ?? VERSION_CURRENT,
      nodeId: identity.nodeId,
      name: identity.name,
      services: [...(setup.services ?? [])],
      ext: setup.ext ?? new Uint8Array(0),
      nonce: new Uint8Array(randomBytes(16)),
    };
    // Below 2^40, as the reference: every implementation counts these numbers exactly (see session.rs).
    this.frameSeq = Math.floor(Math.random() * 2 ** 40);
    this.links = [...links];
    this.events = events;
  }

  /** Adopt the routes, send our hello, and start the timers. */
  start(): void {
    for (const route of this.links) {
      route.setWaker(() => this.kick());
    }
    this.sendFrame(HELLO, encodeBody(HELLO, this.local), false);
    this.tickTimer = setInterval(() => this.tick(), TICK_MS);
  }

  // ----- the handle the node uses ---------------------------------------------------------------

  private gone(): OverlayError {
    return new Closed(`the session with ${this.peerNodeId} is gone`);
  }

  /** Whether the session's timers still run. */
  isLive(): boolean {
    return !this.stopped;
  }

  /** Whether the session can carry traffic now: its loop runs and a route is up. */
  isUsable(): boolean {
    return this.isLive() && routesUsable(this.publishedRoutes);
  }

  /** The agreed protocol version, or 0 while the session is still negotiating. */
  version(): number {
    return this.agreed;
  }

  /** The routes this session measures, for the node's peer listing. */
  routes(): RouteReport[] {
    return [...this.publishedRoutes];
  }

  /** How good this session's best route is: estimated milliseconds to completion. Lower is better. */
  routeQuality(): number {
    let best = Infinity;
    for (const r of this.publishedRoutes) {
      if (r.active) {
        best = Math.min(best, r.rttMs + r.loss * 500);
      }
    }
    return best;
  }

  /** Wait until the peer has answered our hello, at most `limitMs` milliseconds. False when it did not in time. */
  async ready(limitMs: number): Promise<boolean> {
    const deadline = Date.now() + limitMs;
    while (this.agreed === 0) {
      if (!this.isLive() || Date.now() >= deadline) {
        return false;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    return true;
  }

  /** Open a stream to a service the peer exposes. Resolves once the peer accepted it, rejects with its reason. */
  async open(service: string): Promise<number> {
    if (this.stopped) {
      throw this.gone();
    }
    const stream = this.mux.open(service);
    const body = encodeBody(OPEN, { stream, service, nodeId: this.local.nodeId } as Open);
    if (!this.sendFrame(OPEN, body, false)) {
      this.mux.removeSend(stream);
      this.mux.removeRecv(stream);
      throw new Unreachable(this.peerNodeId);
    }
    // Answered by the peer's OPEN_OK or OPEN_ERR.
    return new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.awaitingOpen.delete(stream);
        reject(new Unreachable(this.peerNodeId));
      }, OPEN_TIMEOUT_MS);
      this.awaitingOpen.set(stream, {
        service,
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
        timer,
      });
    });
  }

  /** Queue bytes for a stream. The stream's window decides how much moves now; the rest waits for credit. */
  async send(stream: number, data: Uint8Array, fin = false): Promise<void> {
    if (this.stopped) {
      throw this.gone();
    }
    let entry = this.writeQueue.get(stream);
    if (entry === undefined) {
      entry = { chunks: [], fin: false };
      this.writeQueue.set(stream, entry);
    }
    if (data.length > 0) {
      entry.chunks.push(data);
    }
    if (fin && !entry.fin) {
      // The end of the stream travels as its own empty frame, after every byte before it.
      entry.fin = true;
      entry.chunks.push(new Uint8Array(0));
    }
    this.pump(stream);
  }

  /**
   * Take what the peer has sent on a stream. Waits for data. `null` is the end of the stream: the peer's FIN or CLOSE,
   * or our own close. Rejects with `Closed` when the session ends before the stream does.
   */
  async recv(stream: number): Promise<Uint8Array | null> {
    if (this.stopped) {
      throw this.gone();
    }
    const recv = this.mux.recvSide(stream);
    if (recv === undefined) {
      // No such stream (closed, refused, never opened): the end, not a wait forever.
      return null;
    }
    const ready = recv.take();
    const ended = recv.finished() && recv.buffered() === 0;
    if (ready === null && ended) {
      return null;
    }
    if (ready !== null) {
      this.grantWindow(stream, recv.windowUpdate());
      return ready;
    }
    return new Promise<Uint8Array | null>((resolve, reject) => {
      // A second reader on the same stream replaces the first, which then sees the end.
      this.resolveRead(stream, null);
      this.pendingReads.set(stream, { resolve, reject });
    });
  }

  /** Close a stream: tell the peer, and forget everything about it. */
  async close(stream: number): Promise<void> {
    if (this.stopped) {
      return;
    }
    this.sendFrame(CLOSE, encodeBody(CLOSE, { stream, code: "closed", reason: "" } as Close), false);
    this.mux.removeSend(stream);
    this.mux.removeRecv(stream);
    this.forgetStream(stream);
    this.resolveRead(stream, null);
  }

  /** Add a route discovered after the session came up (a hole punch, a LAN address). */
  async addRoute(route: Route): Promise<void> {
    if (this.stopped || this.links.some((l) => l.id === route.id)) {
      return;
    }
    route.setWaker(() => this.kick());
    const up = route.isUp();
    this.links.push(route);
    this.emit({ kind: "route_changed", peer: this.peerNodeId, route: route.kind, up });
  }

  /** Allow or refuse a stream the peer asked for. This is where the access decision reaches the wire. */
  async authorize(stream: number, service: string, ok: boolean, reason = ""): Promise<void> {
    if (this.stopped) {
      throw this.gone();
    }
    if (!this.pendingOpens.delete(stream)) {
      // The peer closed it before we decided: nothing to accept or refuse.
      return;
    }
    if (ok) {
      this.mux.accept(stream, service);
      this.sendFrame(OPEN_OK, encodeBody(OPEN_OK, { stream, route: this.bestRouteName() } as OpenOk), false);
      return;
    }
    let code: string;
    if (reason === "no such service") {
      code = "no_such_service";
    } else if (reason.includes("a minute")) {
      code = "rate_limited";
    } else {
      code = "denied";
    }
    this.sendFrame(OPEN_ERR, encodeBody(OPEN_ERR, { stream, code, reason } as OpenErr), false);
  }

  /** Re-announce what we expose: a fresh hello, which the peer answers and uses to update what it knows of us. */
  async advertise(services: ServiceInfo[]): Promise<void> {
    if (this.stopped) {
      return;
    }
    this.local.services = [...services];
    this.sendFrame(HELLO, encodeBody(HELLO, this.local), false);
  }

  /** Send our side of a hole-punch exchange. Refused when the session did not agree on a version that carries it. */
  async sendPunch(msg: PunchMsg): Promise<void> {
    if (this.version() < VERSION_PUNCH) {
      throw new OverlayError("the peer's protocol version has no hole punching");
    }
    if (this.stopped) {
      throw this.gone();
    }
    this.sendFrame(CANDIDATE, encodeBody(CANDIDATE, msg), false);
  }

  /** Stop the session: its timers end and every waiting call is released. */
  async shutdown(): Promise<void> {
    this.stopped = true;
    this.finish();
  }

  // ----- internals -------------------------------------------------------------------------------

  private emit(event: SessionEvent): void {
    this.events.push(event);
  }

  private kick(): void {
    if (this.kickPending || this.stopped) {
      return;
    }
    this.kickPending = true;
    setImmediate(() => {
      this.kickPending = false;
      if (this.finished) {
        return;
      }
      this.drainInbound();
      this.afterWork();
    });
  }

  private afterWork(): void {
    if (this.stopped && !this.finished) {
      this.finish();
    }
  }

  private finish(): void {
    if (this.finished) {
      return;
    }
    this.finished = true;
    if (this.tickTimer !== null) {
      clearInterval(this.tickTimer);
      this.tickTimer = null;
    }
    this.setPace(null);
    for (const pending of this.awaitingOpen.values()) {
      pending.reject(new Closed(`the session with ${this.peerNodeId} ended`));
    }
    this.awaitingOpen.clear();
    for (const [stream, pending] of this.pendingReads) {
      // The session ended before the stream did. Silence is not the end of a stream, so the read fails.
      pending.reject(new Closed(`the session with ${this.peerNodeId} ended before stream ${stream} did`));
    }
    this.pendingReads.clear();
    this.emit({ kind: "down", peer: this.peerNodeId, reason: "session ended" });
  }

  private nextSeq(): number {
    this.frameSeq += 1;
    return this.frameSeq;
  }

  private sendFrame(kind: number, body: Uint8Array, bulk: boolean): boolean {
    const seq = this.nextSeq();
    let flags = bulk ? FLAG_BULK : 0;
    if (RELIABLE_KINDS.has(kind)) {
      // A reliable control frame goes out on every live route: the first copy to arrive counts, the rest are dropped.
      flags |= FLAG_MIRROR;
    }
    const frame = new Frame(this.wireVersion, kind, flags, seq, body);
    const sent = this.dispatch(frame);
    if (RELIABLE_KINDS.has(kind)) {
      // Kept until the peer's receipt comes back. A frame that could not go out at all is tried again on the next
      // resend, so it still counts as queued.
      const now = nowSeconds();
      this.ctrlUnacked.set(seq, { frame, first: now, last: now });
      return true;
    }
    return sent;
  }

  private resendControl(): void {
    const now = nowSeconds();
    for (const seq of [...this.ctrlUnacked.keys()].sort((a, b) => a - b)) {
      const entry = this.ctrlUnacked.get(seq);
      if (entry === undefined || now - entry.last < CTRL_RESEND) {
        continue;
      }
      if (now - entry.first > CTRL_GIVE_UP) {
        this.stopped = true;
        return;
      }
      this.dispatch(entry.frame);
      this.ctrlUnacked.set(seq, { frame: entry.frame, first: entry.first, last: now });
    }
  }

  /**
   * A hello with a nonce this session has not seen starts a new numbering. A peer that restarted counts its control
   * frames from a fresh random base, which the window would refuse as older than what it has already seen. Resent
   * copies of a hello carry the same nonce, so they do not reset the window and stay duplicates.
   */
  private noteHello(frame: Frame): void {
    const hello = decodeAs<Hello>(frame);
    if (hello !== null && !equalBytes(hello.nonce, this.peerHelloNonce)) {
      this.peerHelloNonce = hello.nonce;
      this.ctrlSeen = new ReplayWindow(CONTROL_WINDOW);
    }
  }

  /** A control frame arrived: send its receipt, and say whether to act on it. False for a copy already acted on. */
  private admitControl(frame: Frame): boolean {
    this.sendFrame(CTRL_ACK, encodeBody(CTRL_ACK, { seq: frame.seq } as CtrlAck), false);
    return this.ctrlSeen.accept(frame.seq);
  }

  /**
   * Put a frame on the first route that takes it, cheapest first, so one congested route never holds a frame back
   * while another is free. A mirrored frame goes out on every usable route instead: the peer takes the first copy to
   * arrive and ignores the rest.
   */
  private dispatch(frame: Frame): boolean {
    const candidates = this.usableLinks();
    if (frame.isMirrored) {
      let any = false;
      for (const route of candidates) {
        if (route.send(frame)) {
          any = true;
        }
      }
      return any;
    }
    return candidates.some((route) => route.send(frame));
  }

  /** The route a bulk frame should go out on: striped, weighted by measured throughput. */
  private routeForBulk(allowed: readonly number[]): Route | undefined {
    const live = this.links.filter((l) => allowed.includes(l.id));
    if (live.length === 0) {
      return undefined;
    }
    const total = live.reduce((sum, l) => sum + Math.max(l.stats.metrics().mbps * 1000, 1), 0);
    let best: { route: Route; skew: number } | undefined;
    for (const route of live) {
      const m = route.stats.metrics();
      const share = Math.max(m.mbps * 1000, 1) / total;
      const sent = Math.max(route.stats.framesSent(), 1);
      const used = m.active / sent;
      const skew = used - share;
      if (best === undefined || skew < best.skew) {
        best = { route, skew };
      }
    }
    return best?.route;
  }

  private dataFrame(f: OutFrame, mirrored: boolean): Frame {
    const body = encodeBody(DATA, { stream: f.stream, seq: f.seq, fin: f.fin, payload: f.payload } as Data);
    let flags = 0;
    if (f.payload.length >= BULK_THRESHOLD) {
      flags |= FLAG_BULK;
    }
    if (mirrored) {
      flags |= FLAG_MIRROR;
    }
    return new Frame(this.wireVersion, DATA, flags, this.nextSeq(), body);
  }

  private ccOf(route: number): RouteCc {
    let cc = this.cc.get(route);
    if (cc === undefined) {
      cc = new RouteCc();
      this.cc.set(route, cc);
    }
    return cc;
  }

  private routeReportsInternal(): RouteReport[] {
    return this.links.map((link) => {
      const m = link.stats.metrics();
      const cc = this.cc.get(link.id) ?? new RouteCc();
      return {
        kind: link.kind,
        rttMs: round3(m.rttMs),
        loss: round3(m.loss),
        mbps: round3(m.mbps),
        active: m.up,
        cwnd: cc.cwnd,
        inFlight: cc.inFlight,
        srttMs: round3((cc.srtt ?? 0) * 1000),
        rtoMs: round3(cc.rto() * 1000),
        sentBytes: cc.sentBytes,
        retxBytes: cc.retxBytes,
      };
    });
  }

  private bestRouteName(): string {
    return bestRoute(this.links)?.kind ?? "";
  }

  private findRoute(route: number): Route | undefined {
    return this.links.find((l) => l.id === route);
  }

  /** A data frame of `cost` wire bytes left `route`'s books. */
  private leftRoute(route: number, cost: number): void {
    this.findRoute(route)?.stats.recordAcked(cost);
  }

  private takeInflight(stream: number, seq: number): InFlight | undefined {
    const books = this.inflight.get(stream);
    if (books === undefined) {
      return undefined;
    }
    const entry = books.get(seq);
    books.delete(seq);
    if (books.size === 0) {
      this.inflight.delete(stream);
    }
    return entry;
  }

  private seqsIn(stream: number, lo: number, hi: number): number[] {
    const books = this.inflight.get(stream);
    if (books === undefined) {
      return [];
    }
    return [...books.keys()].filter((s) => s >= lo && s < hi).sort((a, b) => a - b);
  }

  private grantWindow(stream: number, credit: number): void {
    if (credit > 0) {
      this.sendFrame(WINDOW, encodeBody(WINDOW, { stream, credit } as Window), false);
    }
  }

  private pump(stream: number): void {
    this.frameWritesFor(stream);
    this.flush();
  }

  /**
   * Move the stream's queued writes into frames, as far as its window allows. The rest stays queued at the front:
   * dropping it would lose bytes from the middle of the stream.
   */
  private frameWritesFor(stream: number): void {
    for (;;) {
      const entry = this.writeQueue.get(stream);
      if (entry === undefined || entry.chunks.length === 0) {
        return;
      }
      const chunk = entry.chunks.shift() as Uint8Array;
      const last = entry.fin && entry.chunks.length === 0;
      const side: SendSide | undefined = this.mux.sendSide(stream);
      if (side === undefined) {
        return;
      }
      const frames = side.frame(chunk, last);
      const taken = frames.reduce((sum, f) => sum + f.payload.length, 0);
      if (taken < chunk.length) {
        entry.chunks.unshift(chunk.slice(taken));
      }
      if (frames.length === 0) {
        return;
      }
      this.outbox.push(...frames);
      if (taken < chunk.length) {
        return; // the rest waits for a WINDOW from the peer
      }
      if (entry.chunks.length === 0) {
        this.writeQueue.delete(stream);
        return;
      }
    }
  }

  /** The routes a frame may go out on, cheapest first: the live ones, or with none live, the cheapest not closed. */
  private usableLinks(): Route[] {
    const ranked = rankedRoutes(this.links);
    const live = ranked.filter((l) => l.isUp());
    return live.length > 0 ? live : ranked.slice(0, 1);
  }

  /**
   * The routes a frame of `cost` bytes may go out on now, best first: the striped choice for bulk, then every other
   * open route cheapest first. With none open, `wake` says when pacing allows one.
   */
  private pickRoutes(bulk: boolean, cost: number, avoid: number | null, retx: boolean, now: number): { routes: Route[]; wake: number | null } {
    const usable = this.usableLinks();
    const open: Route[] = [];
    let wake: number | null = null;
    for (const link of usable) {
      // A resend prefers another route than the one that lost the frame, when there is one.
      if (avoid !== null && avoid === link.id && usable.length > 1) {
        continue;
      }
      const cc = this.ccOf(link.id);
      // A resend ignores the window: waiting for room would wait for the very resend that frees it.
      if (!retx && !cc.hasRoom(cost)) {
        continue;
      }
      const at = cc.paceWait(now);
      if (at === null) {
        open.push(link);
      } else {
        wake = wake === null ? at : Math.min(wake, at);
      }
    }
    if (open.length === 0) {
      return { routes: [], wake };
    }
    const ordered: Route[] = [];
    if (bulk) {
      const striped = this.routeForBulk(open.map((l) => l.id));
      if (striped !== undefined) {
        ordered.push(striped);
      }
    }
    for (const link of rankedRoutes(open)) {
      if (!ordered.some((o) => o.id === link.id)) {
        ordered.push(link);
      }
    }
    return { routes: ordered, wake: null };
  }

  private setPace(at: number | null): void {
    if (this.paceTimer !== null) {
      clearTimeout(this.paceTimer);
      this.paceTimer = null;
    }
    if (at !== null) {
      const delay = Math.max(0, (at - nowSeconds()) * 1000);
      this.paceTimer = setTimeout(() => {
        this.paceTimer = null;
        this.flush();
      }, delay);
    }
  }

  /** Send what the routes have room for: resends first, then new data. What does not fit waits. */
  private flush(): void {
    const now = nowSeconds();
    this.setPace(null);
    for (;;) {
      let frame: OutFrame;
      let avoid: number | null;
      let retx: boolean;
      const head = this.retxQueue[0];
      if (head !== undefined) {
        if (!this.retxPending.has(`${head.frame.stream}:${head.frame.seq}`)) {
          this.retxQueue.shift(); // acknowledged while it waited
          continue;
        }
        frame = head.frame;
        avoid = head.route;
        retx = true;
      } else if (this.outbox.length > 0) {
        frame = this.outbox[0] as OutFrame;
        avoid = null;
        retx = false;
      } else {
        return;
      }
      if (this.mux.sendSide(frame.stream) === undefined) {
        // The stream closed while its frame waited.
        if (retx) {
          this.retxQueue.shift();
          this.retxPending.delete(`${frame.stream}:${frame.seq}`);
        } else {
          this.outbox.shift();
        }
        continue;
      }
      const cost = wireCost(frame.payload.length);
      const bulk = frame.payload.length >= BULK_THRESHOLD;
      const picked = this.pickRoutes(bulk, cost, avoid, retx, now);
      if (picked.routes.length === 0) {
        this.setPace(picked.wake);
        return;
      }
      // The first route that takes the frame carries it. When every route's queue is full, the next tick tries again.
      const wire = this.dataFrame(frame, false);
      const route = picked.routes.find((candidate) => candidate.send(wire));
      if (route === undefined) {
        return;
      }
      route.stats.recordDataOut(cost);
      if (retx) {
        this.retxQueue.shift();
        this.retxPending.delete(`${frame.stream}:${frame.seq}`);
      } else {
        this.outbox.shift();
      }
      this.ccOf(route.id).onSent(cost, frame.payload.length, retx, now);
      let books = this.inflight.get(frame.stream);
      if (books === undefined) {
        books = new Map();
        this.inflight.set(frame.stream, books);
      }
      books.set(frame.seq, { route: route.id, cost, sentAt: now, retx });
    }
  }

  /** A frame is given up on: off the route's books, and queued to go out again. */
  private markLost(stream: number, seq: number, now: number): boolean {
    const entry = this.takeInflight(stream, seq);
    if (entry === undefined) {
      return false;
    }
    this.leftRoute(entry.route, entry.cost);
    const remaining = this.inflight.get(stream);
    const newest = remaining === undefined || remaining.size === 0 ? seq : Math.max(...remaining.keys());
    this.recover.set(stream, Math.max(this.recover.get(stream) ?? 0, newest + 1));
    this.ccOf(entry.route).onLost(entry.cost, entry.sentAt, now);
    const frame = this.mux.sendSide(stream)?.unackedFrame(seq);
    const key = `${stream}:${seq}`;
    if (frame !== undefined && !this.retxPending.has(key)) {
      this.retxPending.add(key);
      this.retxQueue.push({ frame, route: entry.route });
    }
    return true;
  }

  /** Frames that outlived their route's timeout are lost: the route's window shrinks, its timeout doubles, and the
   * frames go out again, on another route where there is one. */
  private expire(): void {
    const now = nowSeconds();
    const due: Array<[number, number]> = [];
    const routes: number[] = [];
    for (const stream of [...this.inflight.keys()].sort((a, b) => a - b)) {
      const books = this.inflight.get(stream);
      if (books === undefined) {
        continue;
      }
      const seqs = [...books.keys()].sort((a, b) => a - b);
      seqs.forEach((seq, index) => {
        const entry = books.get(seq) as InFlight;
        const rto = this.cc.get(entry.route)?.rto() ?? INITIAL_RTO;
        // Behind the oldest unacknowledged frame, a frame is only waiting for the cumulative acknowledgement, as long
        // as the peer keeps answering: it is not lost.
        const last = this.lastAck.get(stream);
        const heard = last !== undefined && last > entry.sentAt && now - last < rto;
        if (now - entry.sentAt >= rto && (index === 0 || !heard)) {
          due.push([stream, seq]);
          if (!routes.includes(entry.route)) {
            routes.push(entry.route);
          }
        }
      });
    }
    for (const [stream, seq] of due) {
      this.markLost(stream, seq, now);
    }
    for (const route of routes) {
      this.cc.get(route)?.backOff();
    }
  }

  /** A stream is gone: nothing of it stays on the books. */
  private forgetStream(stream: number): void {
    const books = this.inflight.get(stream);
    this.inflight.delete(stream);
    for (const seq of [...(books?.keys() ?? [])].sort((a, b) => a - b)) {
      const entry = books?.get(seq);
      if (entry === undefined) {
        continue;
      }
      this.cc.get(entry.route)?.release(entry.cost);
      this.leftRoute(entry.route, entry.cost);
    }
    this.outbox = this.outbox.filter((f) => f.stream !== stream);
    this.retxQueue = this.retxQueue.filter((r) => r.frame.stream !== stream);
    for (const key of [...this.retxPending]) {
      if (key.startsWith(`${stream}:`)) {
        this.retxPending.delete(key);
      }
    }
    this.dupAcks.delete(stream);
    this.recover.delete(stream);
    this.lastAck.delete(stream);
    this.highSack.delete(stream);
  }

  /** An acknowledgement: everything below `nxt` on the stream has arrived, and so have the frames in `sack`. */
  private onAck(stream: number, nxt: number, sack: ReadonlyArray<[number, number]>): void {
    const now = nowSeconds();
    this.lastAck.set(stream, now);
    const keys = this.seqsIn(stream, 0, nxt);
    const cumulative = keys.length;
    let high: number | null = null;
    for (const [from, rawTo] of sack) {
      // A range is the peer's word: bound what it can make us walk.
      const to = Math.min(rawTo, from + MAX_SACK_SPAN);
      if (from < nxt || from >= to) {
        continue;
      }
      keys.push(...this.seqsIn(stream, from, to));
      high = high === null ? to - 1 : Math.max(high, to - 1);
    }

    // A round trip is measured from the newest frame this acknowledgement covers, and only when none of them was
    // resent (the acknowledgement could be for either copy).
    let sample: { route: number; rtt: number } | null = null;
    let resent = false;
    for (const seq of keys) {
      const entry = this.takeInflight(stream, seq);
      if (entry === undefined) {
        continue;
      }
      this.leftRoute(entry.route, entry.cost);
      resent = resent || entry.retx;
      sample = { route: entry.route, rtt: now - entry.sentAt };
      const cc = this.ccOf(entry.route);
      // Held back by this window? Then the window may grow.
      const limited = cc.inFlight + MSS >= cc.cwnd;
      cc.onAcked(entry.cost, limited);
    }
    if (sample !== null && !resent) {
      this.ccOf(sample.route).onRtt(sample.rtt);
    }

    for (const key of [...this.retxPending]) {
      const [s, q] = key.split(":").map(Number) as [number, number];
      if (s === stream && q < nxt) {
        this.retxPending.delete(key);
      }
    }
    if (high !== null) {
      this.highSack.set(stream, Math.max(this.highSack.get(stream) ?? 0, high));
    }
    const top0 = this.highSack.get(stream);
    if (top0 !== undefined && top0 < nxt) {
      this.highSack.delete(stream);
    }
    const recover = this.recover.get(stream);
    if (recover !== undefined && nxt >= recover) {
      this.recover.delete(stream);
    } else if (cumulative > 0 && recover !== undefined) {
      // A partial acknowledgement: what it stops at was lost along with the frame just repaired.
      const entry = this.inflight.get(stream)?.get(nxt);
      if (entry !== undefined && !entry.retx) {
        this.markLost(stream, nxt, now);
      }
    }

    // Frames below the highest one the peer has, that are older than a round trip and a quarter by now, were lost.
    const top = this.highSack.get(stream);
    if (top !== undefined) {
      const srtts = [...this.cc.values()].map((c) => c.srtt).filter((s): s is number => s !== null);
      const slowest = srtts.length === 0 ? 0 : Math.max(...srtts);
      const wait = slowest + slowest / 4;
      const behind = this.seqsIn(stream, 0, top).filter((seq) => {
        const entry = this.inflight.get(stream)?.get(seq);
        return entry !== undefined && now - entry.sentAt > (entry.retx ? wait * 2 : wait);
      });
      for (const seq of behind) {
        this.markLost(stream, seq, now);
      }
    }

    // The same acknowledgement again and again means a frame after the gap keeps arriving while `nxt` does not.
    const [prevNext, count] = this.dupAcks.get(stream) ?? [nxt, 0];
    if (prevNext !== nxt || cumulative > 0) {
      this.dupAcks.set(stream, [nxt, 0]);
    } else {
      this.dupAcks.set(stream, [nxt, count + 1]);
      if (count + 1 === DUP_ACKS) {
        const entry = this.inflight.get(stream)?.get(nxt);
        if (entry !== undefined) {
          const srtt = this.cc.get(entry.route)?.srtt ?? 0;
          if (now - entry.sentAt > srtt) {
            this.markLost(stream, nxt, now);
          }
        }
      }
    }
    this.flush();
  }

  private tick(): void {
    if (this.stopped) {
      this.finish();
      return;
    }
    this.drainInbound();
    this.probe();
    this.resendControl();
    // Republish the measurements so the node and group placement see current numbers.
    this.publishedRoutes = this.routeReportsInternal();
    if (this.established) {
      this.expire();
    }
    this.flush();
    this.afterWork();
  }

  private drainInbound(): void {
    for (const link of [...this.links]) {
      // Bounded per pass so one busy route cannot starve the others; a route that had more wakes the session again.
      for (let taken = 0; taken <= 64; taken++) {
        if (taken === 64) {
          this.kick();
          break;
        }
        const frame = link.tryRecv();
        if (frame === undefined) {
          break;
        }
        if (frame.kind === PING) {
          // A ping is answered on the route it came in on, so the answer measures that route.
          this.answerPing(frame, link);
        } else if (RELIABLE_KINDS.has(frame.kind)) {
          if (frame.kind === HELLO) {
            this.noteHello(frame);
          }
          if (this.admitControl(frame)) {
            this.onFrame(frame);
          }
        } else {
          this.onFrame(frame);
        }
      }
    }
    // Hand over anything a pending read was waiting for.
    for (const stream of [...this.pendingReads.keys()]) {
      const recv = this.mux.recvSide(stream);
      if (recv === undefined) {
        continue;
      }
      const data = recv.take();
      if (data === null) {
        continue;
      }
      const granted = recv.windowUpdate();
      this.resolveRead(stream, data);
      this.grantWindow(stream, granted);
    }
  }

  private resolveRead(stream: number, value: Uint8Array | null): void {
    const pending = this.pendingReads.get(stream);
    if (pending !== undefined) {
      this.pendingReads.delete(stream);
      pending.resolve(value);
    }
  }

  private becomeReady(version: number, name: string, services: ServiceInfo[]): void {
    this.wireVersion = version;
    this.services = [...services];
    this.peerName = name;
    this.agreed = version;
    this.publishedRoutes = this.routeReportsInternal();
    if (this.established) {
      return;
    }
    this.established = true;
    this.emit({ kind: "ready", peer: this.peerNodeId, version, services: [...services] });
    // Tell the peer what we can do, so it can place streams too.
    this.sendFrame(ROUTES, encodeBody(ROUTES, { routes: this.routeReportsInternal() }), false);
  }

  private onFrame(frame: Frame): void {
    switch (frame.kind) {
      case HELLO: {
        const hello = decodeAs<Hello>(frame);
        if (hello === null) {
          return;
        }
        if (hello.nodeId === this.peerNodeId) {
          this.emit({ kind: "hello", peer: this.peerNodeId, name: hello.name, ext: hello.ext });
        }
        // The handshake already proved who is on the other end; a hello claiming to be someone else is refused.
        let agreed: number | null = null;
        let reason = "";
        if (hello.nodeId !== this.peerNodeId) {
          reason = `the hello names ${hello.nodeId} but the handshake proved ${this.peerNodeId}`;
        } else {
          agreed = negotiate(hello.minVersion, hello.maxVersion, this.local.minVersion, this.local.maxVersion);
          if (agreed === null) {
            reason =
              `no common protocol version: it speaks ${hello.minVersion}-${hello.maxVersion}, ` +
              `we speak ${this.local.minVersion}-${this.local.maxVersion}`;
          }
        }
        const ack: HelloAck = {
          version: agreed ?? 0,
          nodeId: this.local.nodeId,
          name: this.local.name,
          services: this.local.services,
          nonce: hello.nonce,
          reason,
          ext: new Uint8Array(0),
        };
        this.sendFrame(HELLO_ACK, encodeBody(HELLO_ACK, ack), false);
        if (agreed !== null) {
          this.becomeReady(agreed, hello.name, hello.services);
        } else {
          this.stopped = true;
          this.emit({ kind: "refused", peer: this.peerNodeId, reason });
        }
        return;
      }
      case HELLO_ACK: {
        const ack = decodeAs<HelloAck>(frame);
        if (ack === null || !equalBytes(ack.nonce, this.local.nonce)) {
          return; // an answer for another hello
        }
        if (ack.version === 0) {
          this.stopped = true;
          this.emit({ kind: "refused", peer: this.peerNodeId, reason: ack.reason });
          return;
        }
        this.becomeReady(ack.version, ack.name, ack.services);
        return;
      }
      case OPEN: {
        const open = decodeAs<Open>(frame);
        if (open === null) {
          return;
        }
        if (!this.mux.isPeerStream(open.stream) || this.pendingOpens.has(open.stream)) {
          const body = encodeBody(OPEN_ERR, {
            stream: open.stream,
            code: "protocol",
            reason: "that stream id is not yours to open",
          } as OpenErr);
          this.sendFrame(OPEN_ERR, body, false);
          return;
        }
        // Ask the node first: the access list lives there, and a refused peer must never reach a local socket.
        this.emit({ kind: "open_request", peer: this.peerNodeId, stream: open.stream, service: open.service });
        this.pendingOpens.set(open.stream, open.service);
        return;
      }
      case OPEN_OK: {
        const ok = decodeAs<OpenOk>(frame);
        if (ok === null) {
          return;
        }
        const pending = this.awaitingOpen.get(ok.stream);
        if (pending !== undefined) {
          this.awaitingOpen.delete(ok.stream);
          pending.resolve(ok.stream);
        }
        return;
      }
      case OPEN_ERR: {
        const err = decodeAs<OpenErr>(frame);
        if (err === null) {
          return;
        }
        const pending = this.awaitingOpen.get(err.stream);
        if (pending !== undefined) {
          this.awaitingOpen.delete(err.stream);
          const service = pending.service;
          if (err.code === "no_such_service") {
            pending.reject(new NoSuchService(service));
          } else if (err.code === "rate_limited") {
            pending.reject(new RateLimited(service, err.reason));
          } else if (err.code === "denied") {
            pending.reject(new Denied(this.local.nodeId, service));
          } else {
            pending.reject(new Closed(`${this.peerNodeId} refused the stream: ${err.reason}`));
          }
        }
        this.mux.removeSend(err.stream);
        this.mux.removeRecv(err.stream);
        this.forgetStream(err.stream);
        this.resolveRead(err.stream, null);
        return;
      }
      case DATA: {
        const data = decodeAs<Data>(frame);
        if (data === null) {
          return;
        }
        const recv: RecvSide | undefined = this.mux.recvSide(data.stream);
        if (recv === undefined) {
          // Not a stream we have (yet): no acknowledgement, so the sender sends it again rather than believing it.
          return;
        }
        const delivered =
          recv.accept({ stream: data.stream, seq: data.seq, payload: data.payload, fin: data.fin }).length > 0;
        // Cumulative, and sent for a duplicate too: a lost acknowledgement is repaired by the resend it causes.
        const nxt = recv.nextExpected();
        const sack = recv.sackRanges(SACK_RANGES);
        this.sendFrame(ACK, encodeBody(ACK, { stream: data.stream, seq: nxt, sack } as Ack), false);
        if (delivered) {
          this.wakeReader(data.stream);
        }
        if (data.fin) {
          this.endReader(data.stream);
        }
        return;
      }
      case ACK: {
        const ack = decodeAs<Ack>(frame);
        if (ack === null) {
          return;
        }
        this.mux.sendSide(ack.stream)?.ackBelow(ack.seq);
        this.onAck(ack.stream, ack.seq, ack.sack);
        return;
      }
      case WINDOW: {
        const win = decodeAs<Window>(frame);
        if (win === null) {
          return;
        }
        this.mux.sendSide(win.stream)?.grant(win.credit);
        // Credit arrived: whatever was waiting behind the window goes now.
        this.pump(win.stream);
        return;
      }
      case CLOSE: {
        const closed = decodeAs<Close>(frame);
        if (closed === null) {
          return;
        }
        this.pendingOpens.delete(closed.stream);
        this.mux.removeSend(closed.stream);
        this.forgetStream(closed.stream);
        this.mux.recvSide(closed.stream)?.close();
        this.resolveRead(closed.stream, null);
        return;
      }
      case PONG: {
        const pong = decodeAs<Pong>(frame);
        if (pong === null) {
          return;
        }
        const entry = this.pings.get(pong.nonce);
        if (entry === undefined) {
          return;
        }
        this.pings.delete(pong.nonce);
        const rttMs = (nowSeconds() - entry.sent) * 1000;
        this.findRoute(entry.route)?.stats.probeOk(rttMs);
        this.ccOf(entry.route).onRtt(rttMs / 1000);
        this.misses.delete(entry.route);
        return;
      }
      case ROUTES:
        // The peer's routes are informational: our own measurements decide where our frames go.
        return;
      case CTRL_ACK: {
        const receipt = decodeAs<CtrlAck>(frame);
        if (receipt !== null) {
          this.ctrlUnacked.delete(receipt.seq);
        }
        return;
      }
      case CANDIDATE: {
        // A build that agreed on less than the punch version never acts on one.
        if (this.agreed < VERSION_PUNCH) {
          return;
        }
        const msg = decodeAs<PunchMsg>(frame);
        if (msg !== null) {
          this.emit({ kind: "punch", peer: this.peerNodeId, msg });
        }
        return;
      }
      case BYE:
        this.stopped = true;
        return;
      default:
        // Any other kind is not one this build knows, and is ignored.
        return;
    }
  }

  private answerPing(frame: Frame, link: Route): void {
    const ping = decodeAs<Ping>(frame);
    if (ping === null) {
      return;
    }
    const body = encodeBody(PONG, { nonce: ping.nonce, sentUs: ping.sentUs } as Pong);
    const pong = new Frame(this.wireVersion, PONG, 0, this.nextSeq(), body);
    if (!link.send(pong)) {
      // The route cannot take even a pong: answer on the best one rather than not at all.
      this.dispatch(pong);
    }
  }

  private endReader(stream: number): void {
    const recv = this.mux.recvSide(stream);
    if (recv === undefined || (recv.finished() && recv.buffered() === 0)) {
      this.resolveRead(stream, null);
    }
  }

  /** Hand buffered bytes to a reader that is waiting for them. With nobody waiting they stay buffered. */
  private wakeReader(stream: number): void {
    if (!this.pendingReads.has(stream)) {
      return;
    }
    const recv = this.mux.recvSide(stream);
    if (recv === undefined) {
      return;
    }
    const data = recv.take();
    if (data === null) {
      return;
    }
    const granted = recv.windowUpdate();
    this.resolveRead(stream, data);
    this.grantWindow(stream, granted);
  }

  private probe(): void {
    const now = nowSeconds();
    for (const link of [...this.links]) {
      const last = this.lastProbe.get(link.id);
      if (last !== undefined && now - last < PROBE_EVERY) {
        continue;
      }
      this.lastProbe.set(link.id, now);
      // Once per probe round: the loss and throughput estimates are over the last round.
      link.stats.refreshLoss();
      link.stats.refreshBandwidth(now);
      // The nonce carries the route, so the answer is credited to the route it came from.
      const nonce = (nowMicros() ^ (BigInt(link.id) << 40n)) & MASK64;
      this.pings.set(nonce, { route: link.id, sent: now });
      link.stats.probeSent();
      const body = encodeBody(PING, { nonce, sentUs: nowMicros() } as Ping);
      link.send(new Frame(this.wireVersion, PING, 0, this.nextSeq(), body));
    }
    // A ping whose answer never came is a miss; a route that misses several in a row is down until a frame arrives.
    const stale: bigint[] = [];
    for (const [nonce, entry] of this.pings) {
      if (now - entry.sent > RESEND_AFTER * 4) {
        stale.push(nonce);
      }
    }
    for (const nonce of stale) {
      const entry = this.pings.get(nonce);
      this.pings.delete(nonce);
      if (entry === undefined) {
        continue;
      }
      const misses = (this.misses.get(entry.route) ?? 0) + 1;
      this.misses.set(entry.route, misses);
      if (misses >= MISSES_DOWN) {
        this.findRoute(entry.route)?.markDown();
      }
    }
  }
}

/**
 * Start a session over `links`: our hello goes out first, and the peer's answer fixes the version.
 * `events` receives the session's `SessionEvent`s.
 */
export function spawn(setup: SessionSetup, links: readonly Route[], events: EventQueue<SessionEvent>): OverlaySession {
  const session = new OverlaySession(setup, links, events);
  session.start();
  return session;
}

