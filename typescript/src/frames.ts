import { Reader, Writer } from "./bincode.js";
import { concatBytes } from "./bytes.js";
import { DecodeError, FrameError } from "./errors.js";

/** `"TDOV"`: every overlay frame begins with these four bytes. */
export const MAGIC = Uint8Array.of(0x54, 0x44, 0x4f, 0x56);
/** `magic(4) | version u8 | kind u8 | flags u16 LE | seq u64 LE | len u32 LE`. */
export const HEADER_LEN = 20;
export const MAX_BODY = 60 * 1024;
export const VERSION_MIN = 1;
export const VERSION_CURRENT = 3;
export const VERSION_PUNCH = 3;

export const FLAG_MIRROR = 0x1;
export const FLAG_BULK = 0x2;

export const HELLO = 0x01;
export const HELLO_ACK = 0x02;
export const OPEN = 0x03;
export const OPEN_OK = 0x04;
export const OPEN_ERR = 0x05;
export const DATA = 0x10;
export const ACK = 0x11;
export const WINDOW = 0x12;
export const CLOSE = 0x13;
export const CTRL_ACK = 0x14;
export const PING = 0x20;
export const PONG = 0x21;
export const ROUTES = 0x30;
export const CANDIDATE = 0x40;
export const BYE = 0x7f;

/** Kinds this build knows. Frames of any other kind are skipped by their length. */
export const KNOWN_KINDS: ReadonlySet<number> = new Set([
  HELLO, HELLO_ACK, OPEN, OPEN_OK, OPEN_ERR, DATA, ACK, WINDOW, CLOSE, CTRL_ACK, PING, PONG, ROUTES, CANDIDATE, BYE,
]);

export const RELIABLE_KINDS: ReadonlySet<number> = new Set([
  HELLO, HELLO_ACK, OPEN, OPEN_OK, OPEN_ERR, WINDOW, CLOSE, CANDIDATE,
]);

// --- Bodies ---------------------------------------------------------------------------------------

export interface ServiceInfo {
  name: string;
  description: string;
}

/** The bincode extension a HELLO or HELLO_ACK carries. Optional fields only. */
export interface HelloExt {
  /** A 16-byte invite nonce, when this is a pairing. */
  pairing: Uint8Array | null;
  direct: string[];
}

export interface Hello {
  minVersion: number;
  maxVersion: number;
  nodeId: string;
  name: string;
  services: ServiceInfo[];
  /** A bincode `HelloExt`, carried as opaque bytes. */
  ext: Uint8Array;
  /** 16 bytes. */
  nonce: Uint8Array;
}

export interface HelloAck {
  version: number;
  nodeId: string;
  name: string;
  services: ServiceInfo[];
  nonce: Uint8Array;
  reason: string;
  ext: Uint8Array;
}

export interface Open {
  stream: number;
  service: string;
  nodeId: string;
}

export interface OpenOk {
  stream: number;
  route: string;
}

export interface OpenErr {
  stream: number;
  code: string;
  reason: string;
}

export interface Data {
  stream: number;
  seq: number;
  fin: boolean;
  payload: Uint8Array;
}

export interface Ack {
  stream: number;
  seq: number;
  sack: [number, number][];
}

/** The older ACK form, which has no SACK ranges. */
export interface AckBase {
  stream: number;
  seq: number;
}

export interface Window {
  stream: number;
  credit: number;
}

export interface Close {
  stream: number;
  code: string;
  reason: string;
}

export interface CtrlAck {
  seq: number;
}

export interface Ping {
  nonce: bigint;
  sentUs: bigint;
}

export interface Pong {
  nonce: bigint;
  sentUs: bigint;
}

export interface RouteReport {
  kind: string;
  rttMs: number;
  loss: number;
  mbps: number;
  active: boolean;
  cwnd: number;
  inFlight: number;
  srttMs: number;
  rtoMs: number;
  sentBytes: number;
  retxBytes: number;
}

export interface Routes {
  routes: RouteReport[];
}

export interface Candidate {
  addr: string;
  private: boolean;
}

export interface PunchMsg {
  id: bigint;
  reply: boolean;
  /** 32 bytes. */
  nonce: Uint8Array;
  candidates: Candidate[];
}

// --- Codecs ---------------------------------------------------------------------------------------

function writeService(w: Writer, s: ServiceInfo): void {
  w.string(s.name);
  w.string(s.description);
}

function readService(r: Reader): ServiceInfo {
  return { name: r.string(), description: r.string() };
}

export function encodeHelloExt(ext: HelloExt): Uint8Array {
  const w = new Writer();
  w.option(ext.pairing, (ww, value) => ww.raw(value));
  w.seq(ext.direct, (ww, value) => ww.string(value));
  return w.getValue();
}

/** An unreadable extension is an empty one: an extension is never fatal. */
export function decodeHelloExt(data: Uint8Array): HelloExt {
  if (data.length === 0) {
    return { pairing: null, direct: [] };
  }
  try {
    const r = new Reader(data);
    const pairing = r.option((rr) => rr.raw(16));
    const direct = r.seq((rr) => rr.string());
    return { pairing, direct };
  } catch (error) {
    if (!(error instanceof DecodeError)) {
      throw error;
    }
  }
  try {
    // The extension as it was before `direct` existed.
    return { pairing: new Reader(data).option((rr) => rr.raw(16)), direct: [] };
  } catch (error) {
    if (!(error instanceof DecodeError)) {
      throw error;
    }
    return { pairing: null, direct: [] };
  }
}

function encodeHello(h: Hello): Uint8Array {
  const w = new Writer();
  w.u16(h.minVersion);
  w.u16(h.maxVersion);
  w.string(h.nodeId);
  w.string(h.name);
  w.seq(h.services, writeService);
  w.bytes(h.ext);
  w.raw(h.nonce);
  return w.getValue();
}

function decodeHello(r: Reader): Hello {
  return {
    minVersion: r.u16(),
    maxVersion: r.u16(),
    nodeId: r.string(),
    name: r.string(),
    services: r.seq(readService),
    ext: r.bytes(),
    nonce: r.raw(16),
  };
}

function encodeHelloAck(h: HelloAck): Uint8Array {
  const w = new Writer();
  w.u16(h.version);
  w.string(h.nodeId);
  w.string(h.name);
  w.seq(h.services, writeService);
  w.raw(h.nonce);
  w.string(h.reason);
  w.bytes(h.ext);
  return w.getValue();
}

function decodeHelloAck(r: Reader): HelloAck {
  return {
    version: r.u16(),
    nodeId: r.string(),
    name: r.string(),
    services: r.seq(readService),
    nonce: r.raw(16),
    reason: r.string(),
    ext: r.bytes(),
  };
}

function encodeRoutes(routes: Routes): Uint8Array {
  const w = new Writer();
  w.seq(routes.routes, (ww, x) => {
    ww.string(x.kind);
    ww.f64(x.rttMs);
    ww.f64(x.loss);
    ww.f64(x.mbps);
    ww.boolean(x.active);
    ww.u64(x.cwnd);
    ww.u64(x.inFlight);
    ww.f64(x.srttMs);
    ww.f64(x.rtoMs);
    ww.u64(x.sentBytes);
    ww.u64(x.retxBytes);
  });
  return w.getValue();
}

function decodeRoutes(r: Reader): Routes {
  return {
    routes: r.seq((rr) => ({
      kind: rr.string(),
      rttMs: rr.f64(),
      loss: rr.f64(),
      mbps: rr.f64(),
      active: rr.boolean(),
      cwnd: rr.u64(),
      inFlight: rr.u64(),
      srttMs: rr.f64(),
      rtoMs: rr.f64(),
      sentBytes: rr.u64(),
      retxBytes: rr.u64(),
    })),
  };
}

function encodePunch(p: PunchMsg): Uint8Array {
  const w = new Writer();
  w.u64(p.id);
  w.boolean(p.reply);
  w.raw(p.nonce);
  w.seq(p.candidates, (ww, c) => {
    ww.string(c.addr);
    ww.boolean(c.private);
  });
  return w.getValue();
}

function decodePunch(r: Reader): PunchMsg {
  return {
    id: r.u64Big(),
    reply: r.boolean(),
    nonce: r.raw(32),
    candidates: r.seq((rr) => ({ addr: rr.string(), private: rr.boolean() })),
  };
}

function decodeAckBase(r: Reader): AckBase {
  return { stream: r.u64(), seq: r.u64() };
}

/** An ACK with its trailing SACK list. A body that does not read that way is an `AckBase`. */
function ackFrom(body: Uint8Array): Ack {
  try {
    const r = new Reader(body);
    const stream = r.u64();
    const seq = r.u64();
    const sack = r.seq((rr) => [rr.u64(), rr.u64()] as [number, number]);
    return { stream, seq, sack };
  } catch (error) {
    if (!(error instanceof DecodeError)) {
      throw error;
    }
    const base = decodeAckBase(new Reader(body));
    return { stream: base.stream, seq: base.seq, sack: [] };
  }
}

function encodeAck(a: Ack): Uint8Array {
  const w = new Writer();
  w.u64(a.stream);
  w.u64(a.seq);
  w.seq(a.sack, (ww, pair) => {
    ww.u64(pair[0]);
    ww.u64(pair[1]);
  });
  return w.getValue();
}

function kindName(kind: number): string {
  return `0x${kind.toString(16).padStart(2, "0")}`;
}

/** The bincode body for `kind`. `body` must be the matching interface; BYE takes no body. */
export function encodeBody(kind: number, body: unknown): Uint8Array {
  const w = new Writer();
  switch (kind) {
    case HELLO:
      return encodeHello(body as Hello);
    case HELLO_ACK:
      return encodeHelloAck(body as HelloAck);
    case OPEN: {
      const o = body as Open;
      w.u64(o.stream);
      w.string(o.service);
      w.string(o.nodeId);
      return w.getValue();
    }
    case OPEN_OK: {
      const o = body as OpenOk;
      w.u64(o.stream);
      w.string(o.route);
      return w.getValue();
    }
    case OPEN_ERR: {
      const o = body as OpenErr;
      w.u64(o.stream);
      w.string(o.code);
      w.string(o.reason);
      return w.getValue();
    }
    case DATA: {
      const o = body as Data;
      w.u64(o.stream);
      w.u64(o.seq);
      w.boolean(o.fin);
      w.bytes(o.payload);
      return w.getValue();
    }
    case ACK:
      return encodeAck(body as Ack);
    case WINDOW: {
      const o = body as Window;
      w.u64(o.stream);
      w.u64(o.credit);
      return w.getValue();
    }
    case CLOSE: {
      const o = body as Close;
      w.u64(o.stream);
      w.string(o.code);
      w.string(o.reason);
      return w.getValue();
    }
    case CTRL_ACK:
      w.u64((body as CtrlAck).seq);
      return w.getValue();
    case PING:
    case PONG: {
      const o = body as Ping;
      w.u64(o.nonce);
      w.u64(o.sentUs);
      return w.getValue();
    }
    case ROUTES:
      return encodeRoutes(body as Routes);
    case CANDIDATE:
      return encodePunch(body as PunchMsg);
    case BYE:
      return new Uint8Array(0);
    default:
      throw new FrameError(`no body codec for kind ${kindName(kind)}`);
  }
}

/** The body for `kind`, decoded. BYE decodes to `undefined`. */
export function decodeBody(kind: number, body: Uint8Array): unknown {
  try {
    switch (kind) {
      case HELLO:
        return decodeHello(new Reader(body));
      case HELLO_ACK:
        return decodeHelloAck(new Reader(body));
      case OPEN: {
        const r = new Reader(body);
        return { stream: r.u64(), service: r.string(), nodeId: r.string() } satisfies Open;
      }
      case OPEN_OK: {
        const r = new Reader(body);
        return { stream: r.u64(), route: r.string() } satisfies OpenOk;
      }
      case OPEN_ERR: {
        const r = new Reader(body);
        return { stream: r.u64(), code: r.string(), reason: r.string() } satisfies OpenErr;
      }
      case DATA: {
        const r = new Reader(body);
        return { stream: r.u64(), seq: r.u64(), fin: r.boolean(), payload: r.bytes() } satisfies Data;
      }
      case ACK:
        return ackFrom(body);
      case WINDOW: {
        const r = new Reader(body);
        return { stream: r.u64(), credit: r.u64() } satisfies Window;
      }
      case CLOSE: {
        const r = new Reader(body);
        return { stream: r.u64(), code: r.string(), reason: r.string() } satisfies Close;
      }
      case CTRL_ACK:
        return { seq: new Reader(body).u64() } satisfies CtrlAck;
      case PING: {
        const r = new Reader(body);
        return { nonce: r.u64Big(), sentUs: r.u64Big() } satisfies Ping;
      }
      case PONG: {
        const r = new Reader(body);
        return { nonce: r.u64Big(), sentUs: r.u64Big() } satisfies Pong;
      }
      case ROUTES:
        return decodeRoutes(new Reader(body));
      case CANDIDATE:
        return decodePunch(new Reader(body));
      case BYE:
        return undefined;
      default:
        throw new FrameError(`no body codec for kind ${kindName(kind)}`);
    }
  } catch (error) {
    if (error instanceof DecodeError) {
      throw new FrameError(`body of kind ${kindName(kind)} does not decode: ${error.message}`);
    }
    throw error;
  }
}

// --- Frames ---------------------------------------------------------------------------------------

export class Frame {
  constructor(
    readonly version: number,
    readonly kind: number,
    readonly flags: number,
    readonly seq: number,
    readonly body: Uint8Array,
  ) {}

  static withBody(version: number, kind: number, seq: number, body: unknown, flags = 0): Frame {
    return new Frame(version, kind, flags, seq, encodeBody(kind, body));
  }

  decode(): unknown {
    return decodeBody(this.kind, this.body);
  }

  get isMirrored(): boolean {
    return (this.flags & FLAG_MIRROR) !== 0;
  }

  get isBulk(): boolean {
    return (this.flags & FLAG_BULK) !== 0;
  }

  encode(): Uint8Array {
    const header = new Uint8Array(HEADER_LEN);
    const view = new DataView(header.buffer);
    header.set(MAGIC, 0);
    view.setUint8(4, this.version);
    view.setUint8(5, this.kind);
    view.setUint16(6, this.flags, true);
    view.setBigUint64(8, BigInt(this.seq), true);
    view.setUint32(16, this.body.length, true);
    return concatBytes(header, this.body);
  }
}

/**
 * Reads one frame from the front of `buf`. Returns `null` while the frame is incomplete.
 * Throws `FrameError` when the bytes are not an overlay frame or declare an oversized body.
 */
export function decodeFrame(buf: Uint8Array): { frame: Frame; used: number } | null {
  if (buf.length < HEADER_LEN) {
    return null;
  }
  for (let i = 0; i < MAGIC.length; i++) {
    if (buf[i] !== MAGIC[i]) {
      throw new FrameError("not a TransferDaemon overlay frame");
    }
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const version = view.getUint8(4);
  const kind = view.getUint8(5);
  const flags = view.getUint16(6, true);
  const seq = view.getBigUint64(8, true);
  if (seq > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new FrameError("frame sequence number is too large");
  }
  const length = view.getUint32(16, true);
  if (length > MAX_BODY) {
    throw new FrameError(`frame body of ${length} bytes is over the limit`);
  }
  if (buf.length < HEADER_LEN + length) {
    return null;
  }
  const body = buf.slice(HEADER_LEN, HEADER_LEN + length);
  return { frame: new Frame(version, kind, flags, Number(seq), body), used: HEADER_LEN + length };
}

/** The highest version both ranges contain, or `null` when they do not overlap. */
export function negotiate(
  peerMin: number,
  peerMax: number,
  ourMin: number = VERSION_MIN,
  ourMax: number = VERSION_CURRENT,
): number | null {
  const hi = Math.min(peerMax, ourMax);
  const lo = Math.max(peerMin, ourMin);
  return lo <= hi ? hi : null;
}

/** Reassembles frames from a byte stream, keeping those of kinds this build knows. */
export class FrameReader {
  private buf: Uint8Array = new Uint8Array(0);

  push(data: Uint8Array): Frame[] {
    this.buf = concatBytes(this.buf, data);
    const out: Frame[] = [];
    for (;;) {
      let got: { frame: Frame; used: number } | null;
      try {
        got = decodeFrame(this.buf);
      } catch (error) {
        if (!(error instanceof FrameError)) {
          throw error;
        }
        // Not our framing: drop what we hold, as the reference does.
        this.buf = new Uint8Array(0);
        break;
      }
      if (got === null) {
        break;
      }
      this.buf = this.buf.slice(got.used);
      if (KNOWN_KINDS.has(got.frame.kind)) {
        out.push(got.frame);
      }
    }
    return out;
  }

  buffered(): number {
    return this.buf.length;
  }
}
