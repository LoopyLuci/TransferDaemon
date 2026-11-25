/**
 * The stream engine: OPEN, DATA, ACK, WINDOW and CLOSE over one session, as pure state.
 *
 * This follows the stream rules of `docs/PROTOCOL.md` §5 and the reference `crates/transferd-overlay/src/session.rs`:
 *
 * - an OPEN for a stream id from our own half, or for an id already pending, is refused with `protocol`;
 * - DATA is delivered in order, acknowledged cumulatively with SACK ranges, and a duplicate is acknowledged again;
 *   DATA for a stream we do not have is not acknowledged;
 * - an ACK trims the retransmit buffer; a gap reported by SACK, or three duplicate acknowledgements, counts as a loss;
 * - a frame unacknowledged for one retransmission timeout (RTO) is resent;
 * - a sender with no window credit holds its bytes until WINDOW arrives, and never drops them.
 *
 * The engine does no I/O and reads no clock. The caller passes `now` in milliseconds and sends the messages it returns,
 * so the rules can be tested without sockets. `stream_session` is the driver that does the I/O.
 */
import {
  ACK,
  CLOSE,
  DATA,
  OPEN,
  OPEN_ERR,
  OPEN_OK,
  WINDOW,
  type Ack,
  type Close,
  type Data,
  type Open,
  type OpenErr,
  type OpenOk,
  type Window,
} from "./frames.js";
import { Mux, type OutFrame } from "./mux.js";

/** The initial retransmission timeout, before any round trip has been measured (ms). */
export const INITIAL_RTO_MS = 400;
/** The retransmission timeout is never below this (ms). */
export const MIN_RTO_MS = 200;
/** The retransmission timeout is never above this, backoff included (ms). */
export const MAX_RTO_MS = 5000;
/** The least the timeout allows beyond the smoothed round trip (ms). */
export const RTO_SLACK_MS = 100;

/** The most SACK ranges one acknowledgement reports. */
export const SACK_RANGES = 4;
/** The most frames one reported range is believed to span. */
export const MAX_SACK_SPAN = 1024;
/** Duplicate acknowledgements in a row that show a frame was lost without waiting for its timeout. */
export const DUP_ACKS = 3;

/** A frame the engine wants sent: its kind and its body, as the frame codec takes them. */
export interface Outbound {
  readonly kind: number;
  readonly body: unknown;
}

/** Something the driver must act on, besides the frames to send. */
export interface Event {
  /**
   * `open_request`: the peer wants a stream, to accept or refuse. `open_ok` and `open_err`: our open was answered.
   * `readable`: bytes are ready to read, or the stream has ended. `closed`: the peer closed the stream.
   */
  readonly kind: "open_request" | "open_ok" | "open_err" | "readable" | "closed";
  readonly stream: number;
  readonly service?: string;
  readonly code?: string;
  readonly reason?: string;
}

/** The retransmission timeout, from measured round trips (RFC 6298, with the reference's clamps). */
export class RtoEstimator {
  srtt: number | null = null;
  private rttvar = 0;
  private backoffSteps = 0;

  /** Fold in one round-trip measurement, in milliseconds. */
  onRtt(sampleMs: number): void {
    if (this.srtt === null) {
      this.srtt = sampleMs;
      this.rttvar = sampleMs / 2;
    } else {
      const err = Math.abs(this.srtt - sampleMs);
      this.rttvar = (this.rttvar * 3) / 4 + err / 4;
      this.srtt = (this.srtt * 7) / 8 + sampleMs / 8;
    }
    this.backoffSteps = 0;
  }

  /** How long a frame may stay unacknowledged before it counts as lost, in milliseconds. */
  rto(): number {
    const base = this.srtt === null ? INITIAL_RTO_MS : this.srtt + Math.max(this.rttvar * 4, RTO_SLACK_MS);
    const clamped = Math.min(Math.max(base, MIN_RTO_MS), MAX_RTO_MS);
    return Math.min(clamped * 2 ** Math.min(this.backoffSteps, 8), MAX_RTO_MS);
  }

  /** A timeout fired: wait twice as long next time, until a measurement arrives. */
  backOff(): void {
    this.backoffSteps = Math.min(this.backoffSteps + 1, 8);
  }
}

interface Flight {
  readonly stream: number;
  readonly seq: number;
  readonly sentAt: number;
  readonly retx: boolean;
}

function flightKey(stream: number, seq: number): string {
  return `${stream}/${seq}`;
}

function dataMessage(frame: OutFrame): Outbound {
  const body: Data = { stream: frame.stream, seq: frame.seq, fin: frame.fin, payload: frame.payload };
  return { kind: DATA, body };
}

/** The stream tables and rules for one session. */
export class StreamEngine {
  readonly nodeId: string;
  readonly mux: Mux;
  readonly rto = new RtoEstimator();
  private readonly awaiting = new Map<number, string>();
  private readonly pendingOpens = new Map<number, string>();
  private readonly backlog = new Map<number, Uint8Array>();
  private readonly finWanted = new Set<number>();
  private readonly finSent = new Set<number>();
  private readonly inflight = new Map<string, Flight>();
  private readonly lastAck = new Map<number, number>();
  private readonly dupAcks = new Map<number, [number, number]>();
  private readonly highSack = new Map<number, number>();
  private readonly recover = new Map<number, number>();

  /** `odd` is which half of the id space this end allocates from; `nodeId` is ours, which an OPEN carries. */
  constructor(options: { odd?: boolean; nodeId?: string } = {}) {
    this.mux = new Mux(options.odd ?? true);
    this.nodeId = options.nodeId ?? "";
  }

  // ----- our side: opening, accepting, writing, reading, closing -----

  /** Open a stream to one of the peer's services. Returns the id and the OPEN to send. */
  open(service: string): [number, Outbound[]] {
    const sid = this.mux.open(service);
    this.awaiting.set(sid, service);
    const body: Open = { stream: sid, service, nodeId: this.nodeId };
    return [sid, [{ kind: OPEN, body }]];
  }

  /** Accept a stream the peer asked for, after an `open_request` event. */
  accept(sid: number): Outbound[] {
    const service = this.pendingOpens.get(sid);
    if (service === undefined) {
      throw new Error(`stream ${sid} is not waiting to be accepted`);
    }
    this.pendingOpens.delete(sid);
    this.mux.accept(sid, service);
    const body: OpenOk = { stream: sid, route: "" };
    return [{ kind: OPEN_OK, body }];
  }

  /** Refuse a stream the peer asked for. `code` is one of the OPEN_ERR codes. */
  refuse(sid: number, code: string, reason: string): Outbound[] {
    this.pendingOpens.delete(sid);
    const body: OpenErr = { stream: sid, code, reason };
    return [{ kind: OPEN_ERR, body }];
  }

  /** Queue bytes on a stream and send what the window allows. The rest waits for WINDOW. */
  write(sid: number, data: Uint8Array, fin: boolean, now: number): Outbound[] {
    if (this.mux.sendSide(sid) === undefined) {
      throw new Error(`no stream ${sid}`);
    }
    const prev = this.backlog.get(sid) ?? new Uint8Array(0);
    const merged = new Uint8Array(prev.length + data.length);
    merged.set(prev, 0);
    merged.set(data, prev.length);
    this.backlog.set(sid, merged);
    if (fin) {
      this.finWanted.add(sid);
    }
    return this.pump(sid, now);
  }

  /**
   * Take the bytes ready on a stream. Returns `[data, out]`: `data` is the bytes, an empty array at the end of the
   * stream, or `null` when nothing is ready yet. `out` holds the WINDOW that returns the credit the reader used.
   */
  read(sid: number): [Uint8Array | null, Outbound[]] {
    const recv = this.mux.recvSide(sid);
    if (recv === undefined) {
      return [new Uint8Array(0), []];
    }
    const taken = recv.take();
    if (taken === null) {
      return [recv.finished() ? new Uint8Array(0) : null, []];
    }
    const granted = recv.windowUpdate();
    const body: Window = { stream: sid, credit: granted };
    return [taken, granted > 0 ? [{ kind: WINDOW, body }] : []];
  }

  /** Bytes queued on a stream that the window has not let out yet. */
  pending(sid: number): number {
    return this.backlog.get(sid)?.length ?? 0;
  }

  /** Whether the end of our side of the stream has gone out (after everything queued before it). */
  finSentOn(sid: number): boolean {
    return this.finSent.has(sid);
  }

  /** Close a stream from our side. The stream's state is dropped at once. */
  close(sid: number, code = "closed", reason = ""): Outbound[] {
    this.mux.removeSend(sid);
    this.mux.removeRecv(sid);
    this.forget(sid);
    const body: Close = { stream: sid, code, reason };
    return [{ kind: CLOSE, body }];
  }

  // ----- inbound frames -----

  /** Apply one decoded stream frame. Returns the messages to send and the events to act on. */
  onFrame(kind: number, body: unknown, now: number): [Outbound[], Event[]] {
    switch (kind) {
      case OPEN:
        return this.onOpen(body as Open);
      case OPEN_OK:
        return this.onOpenOk(body as OpenOk);
      case OPEN_ERR:
        return this.onOpenErr(body as OpenErr);
      case DATA:
        return this.onData(body as Data);
      case ACK:
        return [this.onAck(body as Ack, now), []];
      case WINDOW:
        return [this.onWindow(body as Window, now), []];
      case CLOSE:
        return this.onClose(body as Close);
      default:
        return [[], []];
    }
  }

  private onOpen(body: Open): [Outbound[], Event[]] {
    if (!this.mux.isPeerStream(body.stream) || this.pendingOpens.has(body.stream)) {
      const refusal: OpenErr = { stream: body.stream, code: "protocol", reason: "that stream id is not yours to open" };
      return [[{ kind: OPEN_ERR, body: refusal }], []];
    }
    this.pendingOpens.set(body.stream, body.service);
    return [[], [{ kind: "open_request", stream: body.stream, service: body.service }]];
  }

  private onOpenOk(body: OpenOk): [Outbound[], Event[]] {
    if (!this.awaiting.has(body.stream)) {
      return [[], []];
    }
    this.awaiting.delete(body.stream);
    return [[], [{ kind: "open_ok", stream: body.stream }]];
  }

  private onOpenErr(body: OpenErr): [Outbound[], Event[]] {
    const events: Event[] = [];
    if (this.awaiting.has(body.stream)) {
      this.awaiting.delete(body.stream);
      events.push({ kind: "open_err", stream: body.stream, code: body.code, reason: body.reason });
    }
    this.mux.removeSend(body.stream);
    this.mux.removeRecv(body.stream);
    this.forget(body.stream);
    return [[], events];
  }

  private onData(body: Data): [Outbound[], Event[]] {
    const recv = this.mux.recvSide(body.stream);
    if (recv === undefined) {
      // Not a stream we have: no acknowledgement, so the sender resends rather than believing it arrived.
      return [[], []];
    }
    const delivered = recv.accept({ stream: body.stream, seq: body.seq, payload: body.payload, fin: body.fin }).length > 0;
    // Cumulative, and sent for a duplicate too: a lost acknowledgement is repaired by the resend it causes.
    const ack: Ack = { stream: body.stream, seq: recv.nextExpected(), sack: recv.sackRanges(SACK_RANGES) };
    // A FIN-only frame delivers no bytes but still ends the stream, so a reader must hear about it too.
    const events: Event[] = delivered || body.fin ? [{ kind: "readable", stream: body.stream }] : [];
    return [[{ kind: ACK, body: ack }], events];
  }

  private onAck(body: Ack, now: number): Outbound[] {
    const stream = body.stream;
    const nxt = body.seq;
    this.mux.sendSide(stream)?.ackBelow(nxt);
    this.lastAck.set(stream, now);

    const seqs = this.seqsOf(stream, (s) => s < nxt);
    const cumulative = seqs.length;
    let high: number | null = null;
    for (const [from, rawTo] of body.sack) {
      const to = Math.min(rawTo, from + MAX_SACK_SPAN); // a range is the peer's word: bound what it can make us walk
      if (from < nxt || from >= to) {
        continue;
      }
      seqs.push(...this.seqsOf(stream, (s) => s >= from && s < to));
      high = high === null ? to - 1 : Math.max(high, to - 1);
    }

    // A round trip is measured from the newest frame this acknowledgement covers, and only when none of them was
    // resent (the acknowledgement could be for either copy).
    let sample: number | null = null;
    let resent = false;
    for (const seq of seqs) {
      const key = flightKey(stream, seq);
      const flight = this.inflight.get(key);
      if (flight === undefined) {
        continue;
      }
      this.inflight.delete(key);
      resent = resent || flight.retx;
      sample = now - flight.sentAt;
    }
    if (sample !== null && !resent) {
      this.rto.onRtt(sample);
    }

    if (high !== null) {
      this.highSack.set(stream, Math.max(this.highSack.get(stream) ?? 0, high));
    }
    const top0 = this.highSack.get(stream);
    if (top0 !== undefined && top0 < nxt) {
      this.highSack.delete(stream);
    }

    const out: Outbound[] = [];
    const recovering = this.recover.get(stream);
    if (recovering !== undefined && nxt >= recovering) {
      this.recover.delete(stream);
    } else if (cumulative > 0 && recovering !== undefined) {
      // A partial acknowledgement: what it stops at was lost along with the frame just repaired.
      const flight = this.inflight.get(flightKey(stream, nxt));
      if (flight !== undefined && !flight.retx) {
        out.push(...this.markLost(stream, nxt, now));
      }
    }

    // Frames below the highest one the peer has, older than a round trip and a quarter: they went out first and did
    // not arrive. A frame that was resent waits twice as long, since its resend may still be on its way.
    const top = this.highSack.get(stream);
    if (top !== undefined) {
      const slowest = this.rto.srtt ?? 0;
      const wait = slowest + slowest / 4;
      const behind = this.seqsOf(stream, (s) => s < top).filter((seq) => {
        const flight = this.inflight.get(flightKey(stream, seq));
        return flight !== undefined && now - flight.sentAt > (flight.retx ? wait * 2 : wait);
      });
      for (const seq of behind) {
        out.push(...this.markLost(stream, seq, now));
      }
    }

    // The same acknowledgement again and again: a frame after the gap keeps arriving while `nxt` does not.
    const prev = this.dupAcks.get(stream) ?? [nxt, 0];
    if (prev[0] !== nxt || cumulative > 0) {
      this.dupAcks.set(stream, [nxt, 0]);
    } else {
      const count = prev[1] + 1;
      this.dupAcks.set(stream, [nxt, count]);
      const flight = this.inflight.get(flightKey(stream, nxt));
      if (count === DUP_ACKS && flight !== undefined && now - flight.sentAt > (this.rto.srtt ?? 0)) {
        out.push(...this.markLost(stream, nxt, now));
      }
    }
    return out;
  }

  private onWindow(body: Window, now: number): Outbound[] {
    this.mux.sendSide(body.stream)?.grant(body.credit);
    return this.pump(body.stream, now);
  }

  private onClose(body: Close): [Outbound[], Event[]] {
    this.pendingOpens.delete(body.stream);
    this.mux.removeSend(body.stream);
    this.forget(body.stream);
    this.mux.recvSide(body.stream)?.close();
    return [[], [{ kind: "closed", stream: body.stream, code: body.code, reason: body.reason }]];
  }

  // ----- timers -----

  /** Resend every frame that has been unacknowledged for a retransmission timeout. */
  tick(now: number): Outbound[] {
    const rto = this.rto.rto();
    const due: Array<[number, number]> = [];
    let head: number | null = null;
    for (const flight of this.sortedFlights()) {
      const isHead = head !== flight.stream;
      head = flight.stream;
      const last = this.lastAck.get(flight.stream);
      const heard = last !== undefined && last > flight.sentAt && now - last < rto;
      if (now - flight.sentAt >= rto && (isHead || !heard)) {
        due.push([flight.stream, flight.seq]);
      }
    }
    const out: Outbound[] = [];
    for (const [stream, seq] of due) {
      out.push(...this.markLost(stream, seq, now));
    }
    if (due.length > 0) {
      this.rto.backOff();
    }
    return out;
  }

  /** The earliest time `tick` will have something to resend, or `null` when nothing is in flight. */
  nextDeadline(): number | null {
    let earliest: number | null = null;
    for (const flight of this.inflight.values()) {
      earliest = earliest === null ? flight.sentAt : Math.min(earliest, flight.sentAt);
    }
    return earliest === null ? null : earliest + this.rto.rto();
  }

  // ----- internals -----

  private pump(sid: number, now: number): Outbound[] {
    const send = this.mux.sendSide(sid);
    if (send === undefined) {
      return [];
    }
    const data = this.backlog.get(sid) ?? new Uint8Array(0);
    let frames: OutFrame[];
    if (data.length > 0) {
      // The window takes min(credit, bytes) in total, so the stream's end can ride on the last frame only when
      // everything fits.
      const finNow = this.finWanted.has(sid) && data.length <= send.credit();
      frames = send.frame(data, finNow);
      const taken = frames.reduce((n, f) => n + f.payload.length, 0);
      this.backlog.set(sid, data.slice(taken));
    } else if (this.finWanted.has(sid) && !this.finSent.has(sid)) {
      frames = send.frame(new Uint8Array(0), true);
    } else {
      return [];
    }
    const out: Outbound[] = [];
    for (const frame of frames) {
      this.inflight.set(flightKey(sid, frame.seq), { stream: sid, seq: frame.seq, sentAt: now, retx: false });
      if (frame.fin) {
        this.finSent.add(sid);
      }
      out.push(dataMessage(frame));
    }
    return out;
  }

  /** A frame is lost: resend it now, and narrow the window to the frames still in flight behind it. */
  private markLost(stream: number, seq: number, now: number): Outbound[] {
    const key = flightKey(stream, seq);
    if (!this.inflight.has(key)) {
      return [];
    }
    this.inflight.delete(key);
    const ahead = this.seqsOf(stream, () => true);
    const newest = ahead.length > 0 ? Math.max(...ahead) : seq;
    this.recover.set(stream, Math.max(this.recover.get(stream) ?? 0, newest + 1));
    const frame = this.mux.sendSide(stream)?.unackedFrame(seq);
    if (frame === undefined) {
      return [];
    }
    this.inflight.set(key, { stream, seq, sentAt: now, retx: true });
    return [dataMessage(frame)];
  }

  private seqsOf(stream: number, keep: (seq: number) => boolean): number[] {
    const seqs: number[] = [];
    for (const flight of this.inflight.values()) {
      if (flight.stream === stream && keep(flight.seq)) {
        seqs.push(flight.seq);
      }
    }
    return seqs.sort((a, b) => a - b);
  }

  private sortedFlights(): Flight[] {
    return [...this.inflight.values()].sort((a, b) => a.stream - b.stream || a.seq - b.seq);
  }

  private forget(sid: number): void {
    for (const flight of [...this.inflight.values()]) {
      if (flight.stream === sid) {
        this.inflight.delete(flightKey(flight.stream, flight.seq));
      }
    }
    this.backlog.delete(sid);
    this.finWanted.delete(sid);
    this.finSent.delete(sid);
    this.dupAcks.delete(sid);
    this.recover.delete(sid);
    this.lastAck.delete(sid);
    this.highSack.delete(sid);
    this.awaiting.delete(sid);
  }
}
