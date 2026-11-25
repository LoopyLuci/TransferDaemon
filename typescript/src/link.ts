/**
 * Routes: the paths a session can use, what is measured about each, and the routes that carry frames.
 *
 * Mirrors `crates/transferd-overlay/src/link.rs` (`RouteKind`, `RouteStats`, `best_route`) and the frame-carrying
 * links of `crates/transferd-overlay/src/lanes.rs` (`FramePipe`). The reference calls the base trait `Link`; it is
 * `Route` here, because `wire.ts` already names its socket wrapper `Link`.
 */

import { Frame } from "./frames.js";
import { LinkKeys, Sealer, TunnelReader } from "./tunnel.js";
import { Link as WireLink, writeBlob } from "./wire.js";

/** How many sealed frames a route may queue for its socket before it reports congestion. */
export const SEND_QUEUE = 256;

/** How many sealed control and interactive frames may be queued. They are drained first, so bulk never holds them up. */
export const CONTROL_QUEUE = 512;
/** How many inbound frames a route buffers before it stops taking more. */
export const RECV_QUEUE = 1024;

/** The kind of path a route is, as reported in the route table. */
export type RouteKind = "direct" | "lan" | "holepunch" | "relay" | "ws_relay" | "tailscale";

const RANK: Record<RouteKind, number> = {
  lan: 0,
  tailscale: 1,
  holepunch: 2,
  direct: 3,
  relay: 5,
  ws_relay: 6,
};

const SCHEME: Record<RouteKind, string | null> = {
  direct: "tcp",
  lan: "tcp",
  tailscale: "tcp",
  holepunch: "udp",
  relay: "relay",
  ws_relay: "wsrelay",
};

/** The rank of a kind: routes worth preferring when both work. Cheaper is better. */
export function rankOf(kind: RouteKind): number {
  return RANK[kind];
}

/** The `scheme://` prefix a kind is published with, when it has one. */
export function schemeOf(kind: RouteKind): string | null {
  return SCHEME[kind];
}

/** Seconds from a fixed origin, for every clock in this module. */
export function nowSeconds(): number {
  return performance.now() / 1000;
}

/** What was measured about one route. */
export interface RouteMetrics {
  /** Smoothed round-trip time in milliseconds. */
  rttMs: number;
  /** Fraction of probes lost in the last window, 0 to 1. */
  loss: number;
  /** Smoothed throughput in megabits per second. */
  mbps: number;
  /** Data frames handed to this route and not yet acknowledged. */
  active: number;
  /** Wire bytes handed to this route and not yet acknowledged: the backlog the route must clear first. */
  outstandingBytes: number;
  /** Whether the route is usable right now. */
  up: boolean;
}

/**
 * The score the router minimises: time to push the next frame out on this route. Loss is charged quadratically,
 * so a dead route never wins however good its old numbers were.
 */
export function routeCost(m: RouteMetrics): number {
  if (!m.up) {
    return Infinity;
  }
  // The backlog is in bytes; it takes time at the route's measured speed, so count it in bits per second.
  const bps = Math.max(m.mbps * 1_000_000, 1);
  const backlogMs = ((m.outstandingBytes * 8) / bps) * 1000;
  return m.rttMs + backlogMs + m.loss * m.loss * 1000;
}

/** Rolling statistics for one route, updated by the prober and by real traffic. */
export class RouteStats {
  private rtt = 0;
  private lossEstimate = 0;
  private throughput = 0;
  private activeFrames = 0;
  private outstandingBytes = 0;
  private up = true;
  private sent = 0;
  private bytes = 0;
  private lastBytes = 0;
  private lastSample: number;
  private probesSent = 0;
  private probesOk = 0;

  constructor(
    readonly kind: RouteKind,
    now: number = nowSeconds(),
  ) {
    this.lastSample = now;
  }

  /** Fold a round-trip measurement in (exponential average, so one spike does not dominate). */
  recordRtt(ms: number): void {
    this.rtt = this.rtt <= 0 ? ms : this.rtt * 0.7 + ms * 0.3;
  }

  /** Count one probe sent. */
  probeSent(): void {
    this.probesSent += 1;
  }

  /** Count one probe answered, fold in its round trip, and the route is up. */
  probeOk(rttMs: number): void {
    this.probesOk += 1;
    this.recordRtt(rttMs);
    this.markUp();
  }

  /** Recompute the loss estimate. Called once per probe round. */
  refreshLoss(): void {
    const estimate = this.probesSent === 0 ? 0 : 1 - Math.min(this.probesOk / this.probesSent, 1);
    this.lossEstimate = Math.max(this.lossEstimate * 0.5, 0) + estimate * 0.5;
    this.probesSent = 0;
    this.probesOk = 0;
  }

  /** A frame of `nbytes` went out on this route, of any kind. */
  recordSent(nbytes: number): void {
    this.sent += 1;
    this.bytes += nbytes;
  }

  /**
   * A data frame of `wireBytes` went out and now awaits its acknowledgement. Only data frames are counted: a control
   * frame, a ping or an acknowledgement never gets one back.
   */
  recordDataOut(wireBytes: number): void {
    this.activeFrames += 1;
    this.outstandingBytes += wireBytes;
  }

  /** A data frame of `wireBytes` left this route's books: acknowledged, or given up on. */
  recordAcked(wireBytes: number): void {
    this.activeFrames = Math.max(0, this.activeFrames - 1);
    this.outstandingBytes = Math.max(0, this.outstandingBytes - wireBytes);
  }

  /** Recompute throughput from the byte counter. Called once per probe round. */
  refreshBandwidth(now: number = nowSeconds()): void {
    const total = this.bytes;
    const prev = this.lastBytes;
    this.lastBytes = total;
    const elapsed = Math.max(now - this.lastSample, 0.001);
    this.lastSample = now;
    const mbps = ((total - prev) * 8) / elapsed / 1_000_000;
    this.throughput = this.throughput <= 0 ? mbps : this.throughput * 0.7 + mbps * 0.3;
  }

  markDown(): void {
    this.up = false;
  }

  markUp(): void {
    this.up = true;
  }

  get isUp(): boolean {
    return this.up;
  }

  metrics(): RouteMetrics {
    return {
      rttMs: this.rtt,
      loss: this.lossEstimate,
      mbps: this.throughput,
      active: this.activeFrames,
      outstandingBytes: this.outstandingBytes,
      up: this.up,
    };
  }

  /** Frames sent on this route since it was created. */
  framesSent(): number {
    return this.sent;
  }
}

/** One authenticated path to a peer. Subclasses move the frames; the base holds identity and statistics. */
export abstract class Route {
  readonly stats: RouteStats;
  protected closed = false;
  private waker: (() => void) | null = null;

  constructor(
    readonly id: number,
    readonly kind: RouteKind,
    readonly describe: string = kind,
    now?: number,
  ) {
    this.stats = new RouteStats(kind, now);
  }

  /** Called when a frame arrives, so the session reads it at once instead of at its next tick. */
  setWaker(callback: () => void): void {
    this.waker = callback;
  }

  protected wake(): void {
    this.waker?.();
  }

  isUp(): boolean {
    return this.stats.isUp && !this.closed;
  }

  /** Gone for good (its transport closed), as opposed to merely down (not answering probes for now). */
  isClosed(): boolean {
    return this.closed;
  }

  markDown(): void {
    this.stats.markDown();
  }

  /** Send one frame. False when the route is closed or congested; the caller tries another route or later. */
  abstract send(frame: Frame): boolean;

  /** Take one received frame, if one is buffered. Never waits. */
  abstract tryRecv(): Frame | undefined;

  close(): void {
    this.closed = true;
    this.stats.markDown();
  }
}

/**
 * Every route that is not closed, cheapest first. Ties break on the kind's rank, and a route that is down costs
 * infinity, so it comes last. The session walks this list when the cheapest route refuses a frame, so one congested
 * route never holds up the others.
 */
export function rankedRoutes(routes: readonly Route[]): Route[] {
  return routes
    .filter((r) => !r.isClosed())
    .map((route) => ({ route, cost: routeCost(route.stats.metrics()) }))
    .sort((a, b) => {
      if (a.cost !== b.cost) {
        return a.cost < b.cost ? -1 : 1;
      }
      return RANK[a.route.kind] - RANK[b.route.kind];
    })
    .map((entry) => entry.route);
}

/**
 * The live route with the lowest cost; ties break on the kind's rank. With nothing live, the best route that is not
 * closed is returned rather than nothing: with one route, refusing it would only stop the session healing.
 */
export function bestRoute(routes: readonly Route[]): Route | undefined {
  const ranked = rankedRoutes(routes);
  return ranked.find((r) => r.isUp()) ?? ranked[0];
}

/**
 * Two ends of an in-memory route: each end's sends land in the other end's inbox. The tests use these to run whole
 * sessions without sockets. Like the reference's `PipeLink`, a route marked down still delivers; only `bestRoute`
 * stops choosing it.
 */
export class MemoryRoute extends Route {
  private peer: MemoryRoute | null = null;
  private readonly inbox: Frame[] = [];

  static pair(kind: RouteKind, firstId: number, secondId: number): [MemoryRoute, MemoryRoute] {
    const a = new MemoryRoute(firstId, kind, "memory");
    const b = new MemoryRoute(secondId, kind, "memory");
    MemoryRoute.join(a, b);
    return [a, b];
  }

  /** Joins two routes, so each end's sends land in the other end's inbox. */
  static join(a: MemoryRoute, b: MemoryRoute): void {
    a.peer = b;
    b.peer = a;
  }

  send(frame: Frame): boolean {
    const peer = this.peer;
    if (this.closed || peer === null || peer.closed || peer.inbox.length >= RECV_QUEUE) {
      return false;
    }
    peer.inbox.push(frame);
    this.stats.recordSent(frame.body.length);
    peer.wake();
    return true;
  }

  tryRecv(): Frame | undefined {
    return this.inbox.shift();
  }
}

/**
 * A route over one TCP connection whose handshake has completed. Frames are sealed when sent and opened when they
 * arrive. Reading and writing run as loops, so `send` and `tryRecv` never wait.
 */
export class TcpRoute extends Route {
  private readonly sealer: Sealer;
  private readonly reader: TunnelReader;
  /** Bulk frames, sent after the control queue. */
  private readonly outbox: Uint8Array[] = [];
  /** Control and interactive frames, sent first. */
  private readonly control: Uint8Array[] = [];
  private readonly inbox: Frame[] = [];
  private outWaiter: (() => void) | null = null;
  private roomWaiter: (() => void) | null = null;
  private started = false;

  constructor(
    id: number,
    private readonly link: WireLink,
    keys: LinkKeys,
    kind: RouteKind = "direct",
    describe = "tcp",
  ) {
    super(id, kind, describe);
    this.sealer = new Sealer(keys.send);
    this.reader = new TunnelReader(keys);
  }

  /** Start the read and write loops. Call once the handshake has finished on `link`. */
  start(): void {
    if (this.started) {
      return;
    }
    this.started = true;
    void this.readLoop();
    void this.writeLoop();
  }

  send(frame: Frame): boolean {
    const queue = frame.isBulk ? this.outbox : this.control;
    const limit = frame.isBulk ? SEND_QUEUE : CONTROL_QUEUE;
    if (this.closed || queue.length >= limit) {
      return false;
    }
    queue.push(this.sealer.seal(frame.encode()));
    this.stats.recordSent(frame.body.length);
    this.wakeWriter();
    return true;
  }

  tryRecv(): Frame | undefined {
    const frame = this.inbox.shift();
    if (frame !== undefined) {
      this.wakeReader();
    }
    return frame;
  }

  override close(): void {
    super.close();
    this.wakeWriter();
    this.wakeReader();
    this.link.output.destroy();
  }

  private wakeWriter(): void {
    const waiter = this.outWaiter;
    this.outWaiter = null;
    waiter?.();
  }

  private async readLoop(): Promise<void> {
    try {
      for (;;) {
        // While the inbox is full the socket is not read: the frames wait in TCP, so nothing is dropped.
        await this.waitForRoom();
        const frame = await this.reader.nextFrame(this.link.input);
        this.stats.markUp();
        this.inbox.push(frame);
        this.wake();
      }
    } catch {
      this.fail();
    }
  }

  private waitForRoom(): Promise<void> {
    if (this.inbox.length < RECV_QUEUE || this.closed) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.roomWaiter = resolve;
    });
  }

  private wakeReader(): void {
    const waiter = this.roomWaiter;
    this.roomWaiter = null;
    waiter?.();
  }

  private async writeLoop(): Promise<void> {
    try {
      for (;;) {
        while (this.control.length === 0 && this.outbox.length === 0) {
          if (this.closed) {
            return;
          }
          await new Promise<void>((resolve) => {
            this.outWaiter = resolve;
          });
        }
        const sealed = this.control.shift() ?? this.outbox.shift();
        if (sealed !== undefined) {
          await writeBlob(this.link.output, sealed);
        }
      }
    } catch {
      this.fail();
    }
  }

  private fail(): void {
    this.closed = true;
    this.stats.markDown();
    this.wake();
  }
}
