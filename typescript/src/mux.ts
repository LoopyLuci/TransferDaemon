/**
 * The stream multiplexer: many streams over one session, with flow control and in-order delivery.
 *
 * A port of `crates/transferd-overlay/src/mux.rs`. Every DATA frame carries `(stream, seq)`, so the receiver can hold
 * frames that arrive out of order and the sender can resend only what is missing. This module is pure state: no
 * sockets, no timers. `streams` drives it and owns the timing.
 *
 * Stream ids and sequence numbers are `number`s: they count up from a random 31-bit base and stay far below 2^53.
 */
import { randomBytes } from "./crypto.js";

/** The largest payload one data frame carries (16 KiB less the framing a relay adds). */
export const MAX_FRAME = 16 * 1024 - 192;

/** The window a fresh stream starts with, in bytes, in each direction. */
export const DEFAULT_WINDOW = 256 * 1024;

/** How many unacknowledged (or out-of-order) frames a stream keeps before it refuses more. */
export const MAX_UNACKED = 256;

/** One frame as it travels: which stream, which position, and the bytes. */
export interface OutFrame {
  readonly stream: number;
  readonly seq: number;
  readonly payload: Uint8Array;
  /** Set on the last frame of the stream. */
  readonly fin: boolean;
}

/** The sending half of one stream. */
export class SendSide {
  readonly id: number;
  readonly service: string;
  private nextSeq = 0;
  /** Frames sent but not yet acknowledged cumulatively, by sequence number. */
  private readonly unacked = new Map<number, OutFrame>();
  /** Bytes the peer has allowed us to send beyond what it has already received. */
  private creditBytes: number;
  /** The highest sequence number the peer acknowledged cumulatively. */
  private ackedSeq: number | null = null;
  private sentBytes = 0;
  /** The caller asked to close, but the tail did not fit the window yet. */
  private finPending = false;

  constructor(id: number, service = "", window = DEFAULT_WINDOW) {
    this.id = id;
    this.service = service;
    this.creditBytes = window;
  }

  /** Bytes the peer may still take from us before it grants more. */
  credit(): number {
    return this.creditBytes;
  }

  /** How many frames are waiting for a cumulative acknowledgement. */
  unackedFrames(): number {
    return this.unacked.size;
  }

  /** Whether the end of the stream was asked for and everything sent is acknowledged. */
  isFinished(): boolean {
    return this.finPending && this.unacked.size === 0;
  }

  /**
   * Split `data` into frames the window allows, marking the last one `fin` when asked. Returns an empty list when the
   * window is closed: that is the backpressure signal. The bytes the window did not take are the caller's to keep;
   * their total is the sum of the payloads returned.
   */
  frame(data: Uint8Array, fin: boolean): OutFrame[] {
    const out: OutFrame[] = [];
    if (data.length === 0) {
      // The end of the stream on its own: one empty frame, which needs no credit.
      if (fin) {
        const frame: OutFrame = { stream: this.id, seq: this.nextSeq, payload: new Uint8Array(0), fin: true };
        this.nextSeq += 1;
        this.unacked.set(frame.seq, frame);
        out.push(frame);
        this.finPending = true;
      }
      return out;
    }

    let offset = 0;
    for (;;) {
      const room = Math.min(this.creditBytes, MAX_FRAME, data.length - offset);
      if (room === 0) {
        break;
      }
      const last = offset + room === data.length;
      const chunk = data.slice(offset, offset + room);
      offset += room;
      this.creditBytes -= room;
      this.sentBytes += room;
      const frame: OutFrame = { stream: this.id, seq: this.nextSeq, payload: chunk, fin: fin && last };
      this.nextSeq += 1;
      this.unacked.set(frame.seq, frame);
      out.push(frame);
      if (last) {
        break;
      }
    }
    if (fin) {
      // The whole tail fitted, so the stream ends here; otherwise the caller asks again once credit arrives.
      this.finPending = out.length > 0 && out[out.length - 1]!.fin;
    }
    // Bound the retransmit buffer: drop the oldest frames rather than refuse new data.
    while (this.unacked.size > MAX_UNACKED) {
      this.unacked.delete(Math.min(...this.unacked.keys()));
    }
    return out;
  }

  /** Record a cumulative acknowledgement: every frame below `nextExpected` has arrived. */
  ackBelow(nextExpected: number): void {
    for (const seq of [...this.unacked.keys()]) {
      if (seq < nextExpected) {
        this.unacked.delete(seq);
      }
    }
    if (nextExpected > 0) {
      this.ackedSeq = nextExpected - 1;
    }
  }

  /** Record a cumulative acknowledgement of `seq` itself. */
  ack(seq: number): void {
    for (const s of [...this.unacked.keys()]) {
      if (s <= seq) {
        this.unacked.delete(s);
      }
    }
    this.ackedSeq = seq;
  }

  /** The highest sequence number the peer has acknowledged, if any. */
  acked(): number | null {
    return this.ackedSeq;
  }

  /** Grant more credit to the sender. */
  grant(credit: number): void {
    this.creditBytes += credit;
  }

  /** An unacknowledged frame by sequence number. */
  unackedFrame(seq: number): OutFrame | undefined {
    return this.unacked.get(seq);
  }

  /** Frames still unacknowledged, oldest first. */
  retransmit(): OutFrame[] {
    return [...this.unacked.keys()].sort((a, b) => a - b).map((seq) => this.unacked.get(seq)!);
  }

  /** Bytes sent so far. */
  sent(): number {
    return this.sentBytes;
  }
}

/** The receiving half of one stream: in-order delivery with a bounded reorder buffer. */
export class RecvSide {
  readonly id: number;
  readonly service: string;
  readonly window: number;
  /** The next sequence number to deliver. */
  private nextSeq = 0;
  /** Frames that arrived early, by sequence number. */
  private readonly pending = new Map<number, OutFrame>();
  /** Delivered bytes waiting for the application to take them. */
  private ready: Uint8Array[] = [];
  private readyBytes = 0;
  /** Bytes delivered in order so far. */
  private delivered = 0;
  /** Bytes the application has taken, against which credit is returned. */
  private consumed = 0;
  /** Credit already handed back to the peer. */
  private grantedBytes = 0;
  /** Set once the peer has said this is the last frame. */
  private fin = false;
  /** Frames refused because the reorder buffer was full. */
  private droppedCount = 0;

  constructor(id: number, service = "", window = DEFAULT_WINDOW) {
    this.id = id;
    this.service = service;
    this.window = window;
  }

  /**
   * Accept a frame and return the chunks that are now deliverable, in order. A frame already delivered is ignored
   * (a duplicate); a frame after the end of the stream is ignored; a frame beyond the reorder buffer is refused.
   */
  accept(frame: OutFrame): Uint8Array[] {
    if (frame.seq < this.nextSeq || this.fin) {
      return [];
    }
    if (!this.pending.has(frame.seq) && this.pending.size >= MAX_UNACKED) {
      this.droppedCount += 1;
      return [];
    }
    this.pending.set(frame.seq, frame);
    const out: Uint8Array[] = [];
    for (let next = this.pending.get(this.nextSeq); next !== undefined; next = this.pending.get(this.nextSeq)) {
      this.pending.delete(this.nextSeq);
      this.nextSeq += 1;
      this.fin = next.fin;
      if (next.payload.length === 0) {
        continue;
      }
      this.delivered += next.payload.length;
      this.readyBytes += next.payload.length;
      out.push(next.payload);
      this.ready.push(next.payload);
    }
    return out;
  }

  /** Everything the application has not read yet, as one buffer, or `null` when nothing is ready. */
  take(): Uint8Array | null {
    if (this.ready.length === 0) {
      return null;
    }
    const merged = new Uint8Array(this.readyBytes);
    let at = 0;
    for (const part of this.ready) {
      merged.set(part, at);
      at += part.length;
    }
    this.ready = [];
    this.readyBytes = 0;
    this.consumed += merged.length;
    return merged;
  }

  /** Bytes delivered to the application that it has not taken credit for yet. */
  inUse(): number {
    return Math.max(0, this.delivered - this.consumed);
  }

  /** How much credit the peer may still use. */
  credit(): number {
    return Math.max(0, this.window - this.inUse());
  }

  /** How much credit the peer has been given since the stream opened. */
  granted(): number {
    return this.grantedBytes;
  }

  /** How much credit to hand the peer now: everything read since the last call. */
  windowUpdate(): number {
    const delta = Math.max(0, this.consumed - this.grantedBytes);
    this.grantedBytes = this.consumed;
    return delta;
  }

  /** Ranges `[from, to)` of frames beyond the first gap that have arrived, lowest first, at most `max` of them. */
  sackRanges(max: number): [number, number][] {
    const out: [number, number][] = [];
    for (const seq of [...this.pending.keys()].sort((a, b) => a - b)) {
      const last = out[out.length - 1];
      if (last !== undefined && last[1] === seq) {
        last[1] = seq + 1;
      } else if (out.length === max) {
        break;
      } else {
        out.push([seq, seq + 1]);
      }
    }
    return out;
  }

  /** The next sequence number expected: everything below it has arrived. */
  nextExpected(): number {
    return this.nextSeq;
  }

  /** Frames refused because the reorder buffer was full. */
  dropped(): number {
    return this.droppedCount;
  }

  /** Whether the peer signalled the end of the stream. */
  finished(): boolean {
    return this.fin;
  }

  /** Mark the stream closed by this side too. */
  close(): void {
    this.fin = true;
    this.pending.clear();
  }

  /** Bytes buffered but not yet read by the application. */
  buffered(): number {
    return this.readyBytes;
  }
}

/** A random point to count stream ids from: 31 bits, so a restarted peer does not reuse ids the other end remembers. */
function freshStreamBase(): number {
  const b = randomBytes(4);
  return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 1;
}

/**
 * The stream tables for one session. Each stream carries bytes both ways, so it has a send side and a receive side on
 * both ends. The two ends allocate ids from disjoint halves (odd and even).
 */
export class Mux {
  private readonly send = new Map<number, SendSide>();
  private readonly recv = new Map<number, RecvSide>();
  private nextStream: number;
  /** This end allocates even ids rather than odd ones. */
  private readonly even: boolean;

  constructor(odd = true) {
    this.nextStream = freshStreamBase();
    this.even = !odd;
  }

  allocStream(): number {
    this.nextStream += 1;
    return this.nextStream * 2 - (this.even ? 0 : 1);
  }

  /** Whether `id` belongs to the half the peer allocates from. */
  isPeerStream(id: number): boolean {
    return id !== 0 && (id % 2 === 0) !== this.even;
  }

  /** Register a stream we are opening. */
  open(service: string): number {
    const id = this.allocStream();
    this.send.set(id, new SendSide(id, service));
    this.recv.set(id, new RecvSide(id, service));
    return id;
  }

  /** Register a stream the peer opened. */
  accept(id: number, service: string): RecvSide {
    if (!this.send.has(id)) {
      this.send.set(id, new SendSide(id, service));
    }
    let side = this.recv.get(id);
    if (side === undefined) {
      side = new RecvSide(id, service);
      this.recv.set(id, side);
    }
    return side;
  }

  sendSide(id: number): SendSide | undefined {
    return this.send.get(id);
  }

  recvSide(id: number): RecvSide | undefined {
    return this.recv.get(id);
  }

  removeSend(id: number): SendSide | undefined {
    const side = this.send.get(id);
    this.send.delete(id);
    return side;
  }

  removeRecv(id: number): RecvSide | undefined {
    const side = this.recv.get(id);
    this.recv.delete(id);
    return side;
  }

  /** How many streams are open in each direction. */
  counts(): [number, number] {
    return [this.send.size, this.recv.size];
  }

  /** Every stream's unacknowledged frames, in (stream, seq) order. */
  pendingRetransmits(): OutFrame[] {
    const out: OutFrame[] = [];
    for (const id of [...this.send.keys()].sort((a, b) => a - b)) {
      out.push(...this.send.get(id)!.retransmit());
    }
    return out;
  }
}
