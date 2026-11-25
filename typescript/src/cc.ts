/**
 * Per-route congestion control and retransmission timing.
 *
 * Mirrors `crates/transferd-overlay/src/cc.rs`. One `RouteCc` per route of a session. It is pure state: no
 * sockets and no timers. The caller passes the clock, in seconds from any fixed origin.
 *
 * - RTT and RTO as in RFC 6298: a smoothed RTT and its variance from ACK timing, with
 *   `rto = srtt + max(4 * rttvar, 100 ms)`, clamped to [MIN_RTO, MAX_RTO] and doubled on each timeout until a
 *   fresh measurement arrives.
 * - Window in bytes in flight, NewReno style: slow start from INITIAL_FRAMES frames, then one frame per round trip,
 *   and cut to 0.7 on loss.
 * - Pacing: a window is spread over a round trip instead of leaving as one burst.
 */
import { MAX_FRAME } from "./mux.js";

/** What a data frame costs on the wire beyond its payload: the data header, the seal, the relay framing and its padding. */
export const FRAME_OVERHEAD = 192;

/** The size one full frame counts for in the window. */
export const MSS = MAX_FRAME + FRAME_OVERHEAD;

/** The window a route starts with, in frames. */
export const INITIAL_FRAMES = 10;

/** The window never shrinks below this, in frames, so a lossy route still moves. */
export const MIN_FRAMES = 2;

/** The window never grows beyond this. */
export const MAX_CWND = 64 * 1024 * 1024;

/** The retransmission timeout before any round trip has been measured (seconds). */
export const INITIAL_RTO = 0.4;

/** The retransmission timeout never goes below this (seconds). */
export const MIN_RTO = 0.2;

/** The least the timeout allows beyond the smoothed round trip (seconds). */
export const RTO_SLACK = 0.1;

/** The retransmission timeout never goes above this, backoff included (seconds). */
export const MAX_RTO = 5.0;

/** How far ahead of the pacing clock a send is still allowed (seconds). */
export const PACE_SLACK = 0.002;

/** How far the pacing clock may fall behind real time before the lost time stops being made up (seconds). */
export const PACE_CREDIT = 0.02;

/** The wire cost of a data frame with `payload` bytes. */
export function cost(payload: number): number {
  return payload + FRAME_OVERHEAD;
}

/** Congestion and timing state for one route. */
export class RouteCc {
  private smoothed: number | null = null;
  private rttvar = 0;
  private backoff = 0;
  private window = INITIAL_FRAMES * MSS;
  private ssthresh = Number.POSITIVE_INFINITY;
  private inflight = 0;
  private credit = 0;
  private nextSend: number | null = null;
  private lastCut: number | null = null;
  private sent = 0;
  private retx = 0;

  /** Fold in a round-trip measurement (RFC 6298). */
  onRtt(sample: number): void {
    if (this.smoothed === null) {
      this.smoothed = sample;
      this.rttvar = sample / 2;
    } else {
      const err = Math.abs(this.smoothed - sample);
      this.rttvar = (this.rttvar * 3) / 4 + err / 4;
      this.smoothed = (this.smoothed * 7) / 8 + sample / 8;
    }
    this.backoff = 0;
  }

  /** The smoothed round-trip time in seconds, once one has been measured. */
  get srtt(): number | null {
    return this.smoothed;
  }

  /** How long a frame may stay unacknowledged on this route before it counts as lost (seconds). */
  rto(): number {
    const base0 = this.smoothed === null ? INITIAL_RTO : this.smoothed + Math.max(this.rttvar * 4, RTO_SLACK);
    const base = Math.min(Math.max(base0, MIN_RTO), MAX_RTO);
    return Math.min(base * 2 ** Math.min(this.backoff, 8), MAX_RTO);
  }

  /** A timeout fired: wait twice as long next time, until a measurement arrives. */
  backOff(): void {
    this.backoff = Math.min(this.backoff + 1, 8);
  }

  /** The window, in bytes. */
  get cwnd(): number {
    return this.window;
  }

  /** Bytes sent on this route and not yet acknowledged or given up on. */
  get inFlight(): number {
    return this.inflight;
  }

  /** Payload bytes sent on this route, resends included. */
  get sentBytes(): number {
    return this.sent;
  }

  /** Payload bytes that were resends. */
  get retxBytes(): number {
    return this.retx;
  }

  /** Whether a frame costing `frameCost` may go out now as far as the window is concerned. */
  hasRoom(frameCost: number): boolean {
    return this.inflight === 0 || this.inflight + frameCost <= this.window;
  }

  /** When pacing allows the next send, or null when it may go now. */
  paceWait(now: number): number | null {
    const at = this.nextSend;
    if (at === null || at <= now + PACE_SLACK) {
      return null;
    }
    return at - PACE_SLACK;
  }

  /** A frame went out. */
  onSent(frameCost: number, payload: number, retransmit: boolean, now: number): void {
    this.inflight += frameCost;
    this.sent += payload;
    if (retransmit) {
      this.retx += payload;
    }
    if (this.smoothed !== null) {
      // A window per round trip, twice as fast in slow start so the pacing does not cap the probing.
      const gain = this.window < this.ssthresh ? 2 : 1;
      const rate = (this.window * gain) / Math.max(this.smoothed, 0.00005);
      const gap = frameCost / rate;
      // A timer that fires late leaves the pacing behind by up to PACE_CREDIT, made up at once.
      const floor = now - PACE_CREDIT;
      const base = this.nextSend === null ? now : Math.max(this.nextSend, floor);
      this.nextSend = base + gap;
    }
  }

  /** `nbytes` were acknowledged. `windowLimited` says the sender was held back by this window when the ack came. */
  onAcked(nbytes: number, windowLimited: boolean): void {
    this.inflight = Math.max(0, this.inflight - nbytes);
    if (!windowLimited) {
      return;
    }
    if (this.window < this.ssthresh) {
      this.window = Math.min(this.window + nbytes, MAX_CWND);
    } else {
      this.credit += nbytes;
      if (this.credit >= this.window) {
        this.credit -= this.window;
        this.window = Math.min(this.window + MSS, MAX_CWND);
      }
    }
  }

  /** Frames were given up on. Cuts the window to 0.7, at most once per window's worth of losses. */
  onLost(nbytes: number, sentAt: number, now: number): void {
    this.inflight = Math.max(0, this.inflight - nbytes);
    if (this.lastCut !== null && sentAt <= this.lastCut) {
      return;
    }
    this.ssthresh = Math.max(Math.floor((this.window * 7) / 10), MIN_FRAMES * MSS);
    this.window = this.ssthresh;
    this.credit = 0;
    this.lastCut = now;
  }

  /** Bytes leave the books without being acknowledged or lost (the stream was closed). */
  release(nbytes: number): void {
    this.inflight = Math.max(0, this.inflight - nbytes);
  }

  /** Test access to the internals, as the Rust unit tests use. */
  setForTest(fields: { inflight?: number; window?: number; lastCut?: number | null }): void {
    if (fields.inflight !== undefined) this.inflight = fields.inflight;
    if (fields.window !== undefined) this.window = fields.window;
    if (fields.lastCut !== undefined) this.lastCut = fields.lastCut;
  }
}
