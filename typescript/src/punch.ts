import { concatBytes, constantTimeEqual, u32Bytes, u64Bytes, utf8 } from "./bytes.js";
import { blake3DeriveKey, blake3Keyed } from "./crypto.js";
import { ipFromBytes, ipToBytes } from "./addr.js";
import { deferred, valueWithin } from "./async.js";
import { OverlayError, TransferdError, TunnelError } from "./errors.js";
import { type Frame, FrameReader } from "./frames.js";
import { RECV_QUEUE, Route } from "./link.js";
import { type SocketAddr } from "./relay.js";
import { type RelayClient } from "./relay_client.js";
import { type LinkKeys, Opener, Sealer, deriveLinkKeys, swapLinkKeys } from "./tunnel.js";

/**
 * Hole punching (§8): the probe keys, the 33-byte probe datagram, and the TDGW gateway envelope.
 *
 *   probe := "TDPB" | kind u8 | id u64 BE | seq u32 BE | mac[16]   (33 bytes)
 *   kind  := 1 probe from the initiator, 2 probe from the responder,
 *            3 reply from the initiator, 4 reply from the responder
 *   mac   := BLAKE3-keyed(probe_key, every byte before it)[..16]
 */
export const PROBE_MAGIC = utf8("TDPB");
export const PROBE_LEN = 33;
export const GATEWAY_MAGIC = utf8("TDGW");
export const MAX_CANDIDATES = 8;
export const ROUNDS = 10;
export const PROBE_EVERY_S = 0.2;
export const LINGER_S = 2.0;
export const REPLY_GAP_S = 0.04;
export const MAX_REPLIES = 64;
export const MAX_ESTABLISHED = 8;

export const PROBE_CONTEXT = "transferd-overlay-punch-probe-v1";
export const LINK_CONTEXT = "transferd-overlay-punch-link-v1";

export interface PunchKeys {
  probe: Uint8Array;
  link: Uint8Array;
}

/** The two keys an attempt uses, from its id and both nonces. */
export function derivePunchKeys(attemptId: bigint, initiatorNonce: Uint8Array, responderNonce: Uint8Array): PunchKeys {
  const material = concatBytes(u64Bytes(attemptId, false), initiatorNonce, responderNonce);
  return {
    probe: blake3DeriveKey(PROBE_CONTEXT, material),
    link: blake3DeriveKey(LINK_CONTEXT, material),
  };
}

export type ProbeKind = "probe" | "reply";

export interface Probe {
  kind: ProbeKind;
  fromInitiator: boolean;
  id: bigint;
  seq: number;
}

function kindByte(p: Probe): number {
  return 1 + (p.kind === "reply" ? 2 : 0) + (p.fromInitiator ? 0 : 1);
}

export function encodeProbe(keys: PunchKeys, probe: Probe): Uint8Array {
  const head = concatBytes(PROBE_MAGIC, Uint8Array.of(kindByte(probe)), u64Bytes(probe.id, false), u32Bytes(probe.seq, false));
  return concatBytes(head, blake3Keyed(keys.probe, head).subarray(0, 16));
}

export function probeShaped(datagram: Uint8Array): boolean {
  return datagram.length === PROBE_LEN && PROBE_MAGIC.every((b, i) => datagram[i] === b);
}

export function probeId(datagram: Uint8Array): bigint | null {
  if (!probeShaped(datagram)) {
    return null;
  }
  return new DataView(datagram.buffer, datagram.byteOffset, datagram.byteLength).getBigUint64(5, false);
}

/** The probe, if its MAC is valid under `keys`. Anything else is `null`. */
export function decodeProbe(keys: PunchKeys, datagram: Uint8Array): Probe | null {
  if (!probeShaped(datagram)) {
    return null;
  }
  const expected = blake3Keyed(keys.probe, datagram.subarray(0, 17)).subarray(0, 16);
  if (!constantTimeEqual(expected, datagram.subarray(17))) {
    return null;
  }
  const kinds: Record<number, { kind: ProbeKind; fromInitiator: boolean }> = {
    1: { kind: "probe", fromInitiator: true },
    2: { kind: "probe", fromInitiator: false },
    3: { kind: "reply", fromInitiator: true },
    4: { kind: "reply", fromInitiator: false },
  };
  const entry = kinds[datagram[4]];
  if (entry === undefined) {
    return null;
  }
  const view = new DataView(datagram.buffer, datagram.byteOffset, datagram.byteLength);
  return {
    kind: entry.kind,
    fromInitiator: entry.fromInitiator,
    id: view.getBigUint64(5, false),
    seq: view.getUint32(13, false),
  };
}

/** `"TDGW" | family u8 | ip | port u16 BE | datagram`, for a local UDP gateway only. */
export function gatewayWrap(addr: [string, number], datagram: Uint8Array): Uint8Array {
  const { family, bytes } = ipToBytes(addr[0]);
  const port = new Uint8Array(2);
  new DataView(port.buffer).setUint16(0, addr[1], false);
  return concatBytes(GATEWAY_MAGIC, Uint8Array.of(family), bytes, port, datagram);
}

export interface Unwrapped {
  addr: [string, number];
  datagram: Uint8Array;
}

export function gatewayUnwrap(data: Uint8Array): Unwrapped | null {
  if (data.length < 5 || !GATEWAY_MAGIC.every((b, i) => data[i] === b)) {
    return null;
  }
  const family = data[4];
  if (family !== 4 && family !== 6) {
    return null;
  }
  const width = family === 4 ? 4 : 16;
  if (data.length < 5 + width + 2) {
    return null;
  }
  const ip = ipFromBytes(family, data.subarray(5, 5 + width));
  const port = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint16(5 + width, false);
  return { addr: [ip, port], datagram: data.slice(7 + width) };
}

// ---------------------------------------------------------------------------
// The table of attempts and punched routes on one relay socket (punch.rs)
// ---------------------------------------------------------------------------

/** How long the last probe round waits for an answer that is late but still taken. */
export const LATE_REPLY_S = 0.4;

/** `ip:port`, with an IPv6 address in brackets, as Rust's `SocketAddr` writes it (and as a candidate names it). */
export function addrText(addr: SocketAddr): string {
  return addr[0].includes(":") ? `[${addr[0]}]:${addr[1]}` : `${addr[0]}:${addr[1]}`;
}

function isV6Loopback(bytes: Uint8Array): boolean {
  return bytes.subarray(0, 15).every((b) => b === 0) && bytes[15] === 1;
}

/** Whether `host` is a loopback address: 127/8 or `::1`. */
export function isLoopbackHost(host: string): boolean {
  const { family, bytes } = ipToBytes(host);
  return family === 4 ? bytes[0] === 127 : isV6Loopback(bytes);
}

/**
 * Whether a peer's address may be probed: an address that can be a peer, with a port. Never port 0, unspecified,
 * multicast, broadcast or link-local. Loopback only when the relay is on loopback too: a node and its relay on one
 * machine (a test, or a lab). Otherwise a peer could aim our probes at our own services.
 */
export function acceptableCandidate(addr: SocketAddr, relayIsLoopback: boolean): boolean {
  const [host, port] = addr;
  if (port === 0) {
    return false;
  }
  const { family, bytes } = ipToBytes(host);
  if (bytes.every((b) => b === 0)) {
    return false; // unspecified
  }
  if (family === 4) {
    const multicast = bytes[0] >= 224 && bytes[0] <= 239;
    const broadcast = bytes.every((b) => b === 255);
    const linkLocal = bytes[0] === 169 && bytes[1] === 254;
    if (multicast || broadcast || linkLocal) {
      return false;
    }
    return !(bytes[0] === 127 && !relayIsLoopback);
  }
  if (bytes[0] === 0xff || (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80)) {
    return false; // multicast, link-local
  }
  return !(isV6Loopback(bytes) && !relayIsLoopback);
}

/** A route over a hole-punched UDP path: frames are sealed like any route's, and sent as datagrams to one address. */
export class PunchLink extends Route {
  private readonly sealer: Sealer;
  private readonly inbox: Frame[] = [];

  constructor(
    id: number,
    addr: SocketAddr,
    keys: LinkKeys,
    private readonly sink: (sealed: Uint8Array) => void,
  ) {
    super(id, "holepunch", `udp://${addrText(addr)}`);
    this.sealer = new Sealer(keys.send);
  }

  send(frame: Frame): boolean {
    if (this.closed) {
      return false;
    }
    this.sink(this.sealer.seal(frame.encode()));
    this.stats.recordSent(frame.body.length);
    return true;
  }

  tryRecv(): Frame | undefined {
    return this.inbox.shift();
  }

  /** Keeps a frame that a punched datagram carried. Dropped when the inbox is full, as the reference's punch path is. */
  pushFrame(frame: Frame): void {
    if (this.inbox.length < RECV_QUEUE) {
      this.inbox.push(frame);
    }
    this.wake();
  }
}

/** What one attempt needs. `candidates` are the peer's, as it named them (filtered by `PunchTable.begin`). */
export interface PunchParams {
  id: bigint;
  initiator: boolean;
  keys: PunchKeys;
  candidates: readonly SocketAddr[];
  linkId: number;
}

interface Attempt {
  keys: PunchKeys;
  initiator: boolean;
  allowed: Set<string>;
  roundsSent: number;
  /** Settles the first authenticated reply; cleared once it has been used. */
  settle: ((addr: SocketAddr) => void) | null;
  replies: number;
  lastReply: Map<string, number>;
}

interface Established {
  link: PunchLink;
  opener: Opener;
  reader: FrameReader;
}

export interface PunchTableOptions {
  /** Where datagrams to peers go, wrapped (see `gatewayWrap`). Null sends them straight. */
  gateway?: SocketAddr | null;
  relayIsLoopback?: boolean;
}

/**
 * The hole-punching state of one relay socket: the attempts in progress, and the punched routes.
 *
 * The relay client offers every datagram it receives here first (`onDatagram`). A probe is taken, and a datagram of a
 * punched route; the rest is for the relay path.
 */
export class PunchTable {
  private readonly attempts = new Map<bigint, Attempt>();
  private readonly routes = new Map<string, Established>();
  private readonly gateway: SocketAddr | null;
  private readonly relayIsLoopback: boolean;

  constructor(
    private readonly client: RelayClient,
    options: PunchTableOptions = {},
  ) {
    this.gateway = options.gateway ?? null;
    this.relayIsLoopback = options.relayIsLoopback ?? false;
    client.onDatagram = (datagram, from) => this.offered(datagram, from);
  }

  /** The port of the socket every candidate of this node is on. */
  localPort(): number | null {
    return this.client.localAddr?.[1] ?? null;
  }

  /** A datagram that came through the gateway arrives wrapped with its address; one that came straight is looked at as it is. */
  private offered(datagram: Uint8Array, from: SocketAddr): boolean {
    if (this.gateway !== null && addrText(from) === addrText(this.gateway)) {
      const unwrapped = gatewayUnwrap(datagram);
      if (unwrapped !== null) {
        this.onDatagram(unwrapped.addr, unwrapped.datagram);
        return true; // a wrapped datagram is never the relay's
      }
    }
    return this.onDatagram(from, datagram);
  }

  /** Takes a datagram that arrived from `src`. True when it was ours: a probe, or traffic of a punched route. */
  onDatagram(src: SocketAddr, datagram: Uint8Array): boolean {
    if (probeShaped(datagram)) {
      this.onProbe(src, datagram);
      return true;
    }
    const key = addrText(src);
    const est = this.routes.get(key);
    if (est === undefined) {
      return false;
    }
    if (est.link.isClosed()) {
      this.routes.delete(key);
      return true;
    }
    let plain: Uint8Array;
    try {
      plain = est.opener.open(datagram);
    } catch (error) {
      if (error instanceof TunnelError) {
        return true; // not under this route's keys: dropped without a word
      }
      throw error;
    }
    est.link.stats.markUp();
    for (const frame of est.reader.push(plain)) {
      est.link.pushFrame(frame);
    }
    return true;
  }

  private onProbe(src: SocketAddr, datagram: Uint8Array): void {
    const attemptId = probeId(datagram);
    if (attemptId === null) {
      return;
    }
    const attempt = this.attempts.get(attemptId);
    if (attempt === undefined) {
      return;
    }
    const srcKey = addrText(src);
    // Only from an address the peer named, and only with a valid MAC from the other role.
    if (!attempt.allowed.has(srcKey)) {
      return;
    }
    const probe = decodeProbe(attempt.keys, datagram);
    if (probe === null || probe.id !== attemptId || probe.fromInitiator === attempt.initiator) {
      return;
    }
    if (probe.kind === "probe") {
      const now = performance.now() / 1000;
      const last = attempt.lastReply.get(srcKey);
      const recent = last !== undefined && now - last < REPLY_GAP_S;
      if (recent || attempt.replies >= MAX_REPLIES) {
        return;
      }
      attempt.replies += 1;
      attempt.lastReply.set(srcKey, now);
      this.sendTo(
        src,
        encodeProbe(attempt.keys, { kind: "reply", fromInitiator: attempt.initiator, id: attemptId, seq: probe.seq }),
      );
    } else if (probe.seq < attempt.roundsSent && attempt.settle !== null) {
      // A reply must answer a round we sent, and the first one to do so wins.
      const settle = attempt.settle;
      attempt.settle = null;
      settle(src);
    }
  }

  /**
   * Registers an attempt, so the peer's probes are answered from now on. Call it before the answer that tells the peer
   * to start goes out; then `Running.finish` does the probing.
   */
  begin(params: PunchParams): Running {
    const seen = new Set<string>();
    const usable: SocketAddr[] = [];
    for (const addr of params.candidates) {
      const key = addrText(addr);
      if (!seen.has(key) && acceptableCandidate(addr, this.relayIsLoopback)) {
        seen.add(key);
        usable.push(addr);
      }
    }
    usable.splice(MAX_CANDIDATES);
    if (usable.length === 0) {
      throw new OverlayError("the peer named no usable address");
    }
    const { promise, resolve } = deferred<SocketAddr>();
    this.attempts.set(params.id, {
      keys: params.keys,
      initiator: params.initiator,
      allowed: new Set(usable.map(addrText)),
      roundsSent: 0,
      settle: resolve,
      replies: 0,
      lastReply: new Map(),
    });
    return new Running(this, params, usable, promise);
  }

  /** Records how many probe rounds an attempt has sent: a reply must answer one of them. Used by `Running`. */
  setRoundsSent(id: bigint, rounds: number): void {
    const attempt = this.attempts.get(id);
    if (attempt !== undefined) {
      attempt.roundsSent = rounds;
    }
  }

  /** Stops answering an attempt's probes, once it has lingered long enough. Used by `Running`. */
  retire(id: bigint): void {
    this.attempts.delete(id);
  }

  /** Sends one datagram to a peer address from the relay socket, through the gateway when there is one. */
  sendTo(dest: SocketAddr, datagram: Uint8Array): void {
    try {
      if (this.gateway !== null) {
        this.client.sendTo(gatewayWrap(dest, datagram), this.gateway);
      } else {
        this.client.sendTo(datagram, dest);
      }
    } catch (error) {
      if (!(error instanceof TransferdError)) {
        throw error;
      }
      // A datagram that did not go is a lost one; the next round sends again.
    }
  }

  /** The route over a punched address, registered so its datagrams reach it. Used by `Running`. */
  establish(addr: SocketAddr, params: PunchParams): PunchLink {
    let keys = deriveLinkKeys(params.keys.link);
    if (!params.initiator) {
      keys = swapLinkKeys(keys);
    }
    const link = new PunchLink(params.linkId, addr, keys, (sealed) => this.sendTo(addr, sealed));
    link.markDown();
    for (const [key, est] of [...this.routes]) {
      if (est.link.isClosed()) {
        this.routes.delete(key);
      }
    }
    if (this.routes.size >= MAX_ESTABLISHED) {
      let oldest: string | undefined;
      let oldestId = Number.POSITIVE_INFINITY;
      for (const [key, est] of this.routes) {
        if (est.link.id < oldestId) {
          oldestId = est.link.id;
          oldest = key;
        }
      }
      if (oldest !== undefined) {
        this.routes.get(oldest)?.link.close();
        this.routes.delete(oldest);
      }
    }
    const key = addrText(addr);
    const replaced = this.routes.get(key);
    this.routes.set(key, { link, opener: new Opener(keys.recv), reader: new FrameReader() });
    replaced?.link.close();
    return link;
  }
}

/** An attempt that is registered and about to probe (see `PunchTable.begin`). */
export class Running {
  constructor(
    private readonly table: PunchTable,
    private readonly params: PunchParams,
    private readonly allowed: readonly SocketAddr[],
    private readonly won: Promise<SocketAddr>,
  ) {}

  /**
   * Probes every named address for about two seconds, and on the first authenticated reply returns a route over it.
   * The route starts marked down, so the session sends nothing on it before its own first ping has been answered.
   */
  async finish(): Promise<PunchLink> {
    let winner: SocketAddr | undefined;
    for (let seq = 0; seq < ROUNDS; seq++) {
      this.table.setRoundsSent(this.params.id, seq + 1);
      const probe = encodeProbe(this.params.keys, {
        kind: "probe",
        fromInitiator: this.params.initiator,
        id: this.params.id,
        seq,
      });
      for (const addr of this.allowed) {
        this.table.sendTo(addr, probe);
      }
      winner = await valueWithin(this.won, PROBE_EVERY_S * 1000);
      if (winner !== undefined) {
        break;
      }
    }
    if (winner === undefined) {
      winner = await valueWithin(this.won, LATE_REPLY_S * 1000);
    }
    // The attempt keeps answering the peer's probes a little longer: it may not have heard our reply to the last one.
    setTimeout(() => this.table.retire(this.params.id), LINGER_S * 1000).unref();
    if (winner === undefined) {
      throw new OverlayError("no authenticated reply came back from any address the peer named");
    }
    return this.table.establish(winner, this.params);
  }
}
