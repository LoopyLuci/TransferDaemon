/**
 * The relay path for one node: one registered point, many peers, one inbound demultiplexer.
 *
 * Mirrors `python/transferd/relay_hub.py` and the relay route of `crates/transferd-overlay/src/relay.rs`. A relay is the
 * only path that always works: it is reached by an *outbound* datagram, and it delivers to the mapping that datagram
 * created, so nothing here listens and nothing needs a firewall port.
 *
 * Over one relay the overlay runs three kinds of payload, each padded to a power of two (`pad`):
 *
 *     [0x01][sender_token: 32][initiator flight]    the authenticated hybrid handshake, opening
 *     [0x03][sender_token: 32][responder flight]    ... and its answer
 *     [0x02][sender_token: 32][sealed tunnel frame] a session's traffic
 *
 * The node decides what to do with a peer that dials in: `admit` says whether its presented key may come in, and
 * `onAdopt` receives the new link so the node can make it a session. Everything else is the transport itself.
 */

import { deferred, valueWithin } from "./async.js";
import { blake3Hash } from "./crypto.js";
import { HandshakeError, OverlayError, TransferdError, TunnelError } from "./errors.js";
import { type Candidate, type Frame, FrameReader } from "./frames.js";
import {
  Flight,
  INITIATOR_FLIGHT_LEN,
  INITIATOR_HELLO_LEN,
  InitiatorState,
  RESPONDER_FLIGHT_LEN,
  RESPONDER_HELLO_LEN,
  TAG_INITIATOR,
  TAG_RESPONDER,
  buildFlight,
  respond,
} from "./handshake.js";
import { type HybridIdentity, relayTokenFor } from "./identity.js";
import { CONTROL_QUEUE, Route, SEND_QUEUE } from "./link.js";
import {
  type PunchParams,
  PunchTable,
  type Running,
  acceptableCandidate,
  addrText,
  isLoopbackHost,
} from "./punch.js";
import {
  type Located,
  PREFIX_DATA,
  PREFIX_HANDSHAKE,
  PREFIX_HANDSHAKE_REPLY,
  type SocketAddr,
  encapsulate,
  unpad,
} from "./relay.js";
import { type RelayAddress, RelayClient, routeSource } from "./relay_client.js";
import { type LinkKeys, Opener, Sealer, deriveLinkKeys, swapLinkKeys } from "./tunnel.js";

/** How long a relay handshake may take. Four datagrams must all get through, so on a lossy path it takes several tries. */
export const HANDSHAKE_TIMEOUT_MS = 10_000;
/** How often an unanswered handshake flight is sent again (a datagram may be lost). */
export const FLIGHT_RESEND_MS = 900;
/** Answers kept, so a resent flight gets the same answer instead of a second session key. */
export const ANSWERS_KEPT = 64;
/** How long to wait for a relay's answer to a request. */
export const RELAY_TIMEOUT_MS = 5_000;
/** How often the registration is renewed: well inside relayd's TTL. */
export const REREGISTER_EVERY_MS = 30_000;
/**
 * Session payloads held for a peer whose link is not registered yet, for this many per peer and this many peers. The
 * two sides of a handshake finish at slightly different moments, so the first frames can overtake the link they belong to.
 */
export const EARLY_PER_PEER = 64;
export const EARLY_PEERS = 64;
/** Links kept per peer on one relay. The oldest beyond this is closed. */
export const LINKS_PER_PEER = 4;

/** Datagrams a link may have in flight to the relay before its send loop waits for one to be acknowledged. */
export const MAX_FORWARDS_IN_FLIGHT = 128;

export type Admit = (nodeId: string, hybridPublicKey: Uint8Array) => boolean;
export type Adopt = (
  link: RelayLink,
  peerNodeId: string,
  peerHybridPublicKey: Uint8Array,
  sender: Uint8Array,
) => void | Promise<void>;

export interface RelayHubOptions {
  admit?: Admit;
  onAdopt?: Adopt;
  /** How long a request to the relay may wait for its answer. */
  timeoutMs?: number;
  /** How long a handshake may take before the peer is given up on. */
  handshakeTimeoutMs?: number;
  /** The gateway that hole-punch datagrams to peers go through, if any (see `gatewayWrap`). Null sends them straight. */
  gateway?: SocketAddr | null;
}

export interface RelayHandshake {
  keys: LinkKeys;
  peerHybridPublicKey: Uint8Array;
}

export interface AnsweredHandshake {
  keys: LinkKeys;
  peerNodeId: string;
  peerHybridPublicKey: Uint8Array;
  reply: Uint8Array;
}

function hexOf(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

let lastLinkId = 0;

function nextLinkId(): number {
  lastLinkId += 1;
  return lastLinkId;
}

/** A route to one peer through a relay. Frames are sealed like any route's, and wrapped for the relay when sent. */
export class RelayLink extends Route {
  private readonly sealer: Sealer;
  private readonly opener: Opener;
  private readonly frames = new FrameReader();
  private readonly inbox: Frame[] = [];
  /** Bulk frames, forwarded after the control queue. */
  private readonly outbox: Uint8Array[] = [];
  /** Control and interactive frames, forwarded first, so a relay backlog never holds a window update up. */
  private readonly control: Uint8Array[] = [];
  private outWaiter: (() => void) | null = null;
  /** Datagrams sent and not yet acknowledged by the relay (pipelined: the loop does not wait for each one). */
  private readonly inFlight = new Set<Promise<void>>();
  /** A failure that is a bug rather than a lost datagram: the route ends with it, as a thrown error would. */
  private fault: unknown = undefined;
  private started = false;

  constructor(
    private readonly hub: RelayHub,
    private readonly peerToken: Uint8Array,
    keys: LinkKeys,
    id: number,
  ) {
    super(id, "relay", `relay://${hub.relay.host}:${hub.relay.port}#${hexOf(peerToken)}`);
    this.sealer = new Sealer(keys.send);
    this.opener = new Opener(keys.recv);
  }

  /** Start the loop that sends what is queued. Call once the link is registered with its hub. */
  start(): void {
    if (this.started) {
      return;
    }
    this.started = true;
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
    return this.inbox.shift();
  }

  /**
   * Open one sealed payload and keep its frames. False when it is not this link's: another link to the same peer may
   * own it, or it is a replay.
   */
  deliver(sealed: Uint8Array): boolean {
    let plain: Uint8Array;
    try {
      plain = this.opener.open(sealed);
    } catch (error) {
      if (error instanceof TunnelError) {
        return false;
      }
      throw error;
    }
    this.stats.markUp();
    this.inbox.push(...this.frames.push(plain));
    this.wake();
    return true;
  }

  override close(): void {
    super.close();
    this.wakeWriter();
  }

  private wakeWriter(): void {
    const waiter = this.outWaiter;
    this.outWaiter = null;
    waiter?.();
  }

  private async writeLoop(): Promise<void> {
    for (;;) {
      while (this.control.length === 0 && this.outbox.length === 0) {
        if (this.closed) {
          return;
        }
        await new Promise<void>((resolve) => {
          this.outWaiter = resolve;
        });
      }
      if (this.closed) {
        return;
      }
      if (this.fault !== undefined) {
        throw this.fault;
      }
      const sealed = this.control.shift() ?? this.outbox.shift();
      if (sealed === undefined) {
        continue;
      }
      // Pipelined: the next datagram goes out without waiting for this one's ack. The number in flight is bounded, so
      // a backlog cannot run ahead of the relay without limit.
      const sent = this.sendDatagram(sealed);
      this.inFlight.add(sent);
      void sent.then(() => {
        this.inFlight.delete(sent);
      });
      if (this.inFlight.size >= MAX_FORWARDS_IN_FLIGHT) {
        await Promise.race(this.inFlight);
      }
    }
  }

  private async sendDatagram(sealed: Uint8Array): Promise<void> {
    try {
      await this.hub.forwardSealed(this.peerToken, sealed);
    } catch (error) {
      // A datagram that could not be sent is a lost datagram, which the session repairs. It is no reason to close
      // the route: that would end a session over one hiccup.
      if (!(error instanceof TransferdError)) {
        this.fault = error;
      }
    }
  }
}

/** A registered relay and the sessions multiplexed over it. */
export class RelayHub {
  readonly selfToken: Uint8Array;
  private readonly relayClient: RelayClient;
  private readonly punchTable: PunchTable;
  private readonly identity: HybridIdentity;
  private readonly admit: Admit;
  private readonly onAdopt: Adopt | null;
  private readonly handshakeTimeoutMs: number;
  private readonly peers = new Map<string, RelayLink[]>();
  private readonly early = new Map<string, Uint8Array[]>();
  private readonly answered = new Map<string, Uint8Array>();
  private readonly handshakes = new Map<string, (reply: Uint8Array) => void>();
  private readonly background = new Set<Promise<void>>();
  private renewTimer: ReturnType<typeof setInterval> | null = null;
  private closing = false;

  constructor(
    readonly relay: RelayAddress,
    selfToken: Uint8Array,
    identity: HybridIdentity,
    options: RelayHubOptions = {},
  ) {
    if (selfToken.length !== 32) {
      throw new TransferdError("a relay token is 32 bytes");
    }
    this.selfToken = selfToken;
    this.identity = identity;
    this.admit = options.admit ?? (() => true);
    this.onAdopt = options.onAdopt ?? null;
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS;
    this.relayClient = new RelayClient(relay, options.timeoutMs ?? RELAY_TIMEOUT_MS);
    // The hole punches share the registration socket, so the punch table takes the datagrams it is offered first.
    this.punchTable = new PunchTable(this.relayClient, {
      gateway: options.gateway ?? null,
      relayIsLoopback: isLoopbackHost(relay.host),
    });
  }

  /** The relay client this hub's registration socket belongs to (the hole punches share it). */
  get client(): RelayClient {
    return this.relayClient;
  }

  /** The hole-punch table on this hub's registration socket. */
  get punch(): PunchTable {
    return this.punchTable;
  }

  /** Open the socket, register our token, and start the receive and renewal loops. */
  async start(): Promise<void> {
    await this.relayClient.open();
    try {
      await this.relayClient.register(this.selfToken);
    } catch (error) {
      this.relayClient.close();
      throw error;
    }
    void this.receiveLoop();
    this.renewTimer = setInterval(() => {
      void this.renew();
    }, REREGISTER_EVERY_MS);
    this.renewTimer.unref();
  }

  close(): void {
    this.closing = true;
    if (this.renewTimer !== null) {
      clearInterval(this.renewTimer);
      this.renewTimer = null;
    }
    for (const links of this.peers.values()) {
      for (const link of links) {
        link.close();
      }
    }
    this.relayClient.close();
  }

  // --- inbound ----------------------------------------------------------------------------------

  private async receiveLoop(): Promise<void> {
    for (;;) {
      const delivered = await this.relayClient.nextDelivered();
      if (this.closing) {
        return;
      }
      this.dispatch(delivered.ciphertext);
    }
  }

  /** A failed renewal is retried at the next interval: a restarted relay is reached once one gets through. */
  private async renew(): Promise<void> {
    try {
      await this.relayClient.register(this.selfToken);
    } catch (error) {
      if (!(error instanceof TransferdError)) {
        throw error;
      }
    }
  }

  private dispatch(payload: Uint8Array): void {
    const parts = unpad(payload);
    if (parts === null) {
      return;
    }
    const { prefix, senderToken: sender, body: rest } = parts;
    const key = hexOf(sender);
    if (prefix === PREFIX_HANDSHAKE) {
      this.spawn(this.answerInbound(sender, rest));
    } else if (prefix === PREFIX_HANDSHAKE_REPLY) {
      // An answer nobody waits for any more (a copy, for a resent flight) is dropped.
      const deliverReply = this.handshakes.get(key);
      if (deliverReply !== undefined) {
        this.handshakes.delete(key);
        deliverReply(rest);
      }
    } else if (prefix === PREFIX_DATA) {
      const links = this.peers.get(key);
      if (links !== undefined) {
        // The payload carries no link id, so the keys decide which of the peer's links it is for.
        links.some((link) => link.deliver(rest));
        return;
      }
      let held = this.early.get(key);
      if (held === undefined) {
        if (this.early.size >= EARLY_PEERS) {
          return;
        }
        held = [];
        this.early.set(key, held);
      }
      if (held.length < EARLY_PER_PEER) {
        held.push(rest);
      }
    }
  }

  /**
   * Keeps a background task until it ends. A failed inbound handshake leaves no trace on the wire: the dialler's
   * resends or its timeout report it, so the error is not re-raised here.
   */
  private spawn(task: Promise<void>): void {
    this.background.add(task);
    const done = (): void => {
      this.background.delete(task);
    };
    task.then(done, done);
  }

  /** Answer a handshake a peer dialled through this relay, so a node with no open port can still be reached. */
  private async answerInbound(sender: Uint8Array, flight: Uint8Array): Promise<void> {
    const digest = hexOf(blake3Hash(flight));
    const known = this.answered.get(digest);
    if (known !== undefined) {
      // Our answer was lost and the flight came again: send the same answer, not a second key the dialler never sees.
      await this.sendQuietly(PREFIX_HANDSHAKE_REPLY, sender, known);
      return;
    }
    const answered = answerHandshake(flight, this.identity);
    if (answered === null) {
      return;
    }
    const { keys, peerNodeId, peerHybridPublicKey, reply } = answered;
    // As on the direct listener, a first contact must present the key its invite named. A refused flight gets no
    // answer, so the dialler's handshake times out.
    if (!this.admit(peerNodeId, peerHybridPublicKey)) {
      return;
    }
    if (this.answered.size >= ANSWERS_KEPT) {
      this.answered.clear();
    }
    this.answered.set(digest, reply);
    // The token is derived from the node id, so the two are the same key material.
    const peerToken = relayTokenFor(peerNodeId);
    // The link is registered before the answer goes out, so the dialler's first frames find it.
    const link = this.link(peerToken, keys);
    await this.sendQuietly(PREFIX_HANDSHAKE_REPLY, sender, reply);
    if (this.onAdopt !== null) {
      await this.onAdopt(link, peerNodeId, peerHybridPublicKey, sender);
    }
  }

  private async sendQuietly(prefix: number, peerToken: Uint8Array, body: Uint8Array): Promise<void> {
    try {
      await this.sendPayload(prefix, peerToken, body);
    } catch (error) {
      if (!(error instanceof TransferdError)) {
        throw error;
      }
      // A lost answer is repaired by the dialler's resend.
    }
  }

  // --- outbound ---------------------------------------------------------------------------------

  private async sendPayload(prefix: number, peerToken: Uint8Array, body: Uint8Array): Promise<void> {
    await this.relayClient.forward(peerToken, encapsulate(prefix, this.selfToken, body));
  }

  /** Send one sealed blob to a peer through this relay. */
  async forwardSealed(peerToken: Uint8Array, sealed: Uint8Array): Promise<void> {
    await this.relayClient.forward(peerToken, encapsulate(PREFIX_DATA, this.selfToken, sealed));
  }

  /**
   * Run the authenticated hybrid handshake with a peer over this relay.
   *
   * Returns the link keys (the same derivation as a direct connection, so a relay route and a direct route are
   * interchangeable) and the peer's 2624-byte hybrid public key, from its verified flight. The caller checks that key
   * against the peer's fingerprint.
   */
  async handshake(peerNodeId: string, peerToken: Uint8Array): Promise<RelayHandshake> {
    const key = hexOf(peerToken);
    const { promise: reply, resolve: deliverReply } = deferred<Uint8Array>();
    this.handshakes.set(key, deliverReply);
    try {
      const state = new InitiatorState();
      const flight = buildFlight(TAG_INITIATOR, state.hello(), this.identity).toWire();
      const deadline = Date.now() + this.handshakeTimeoutMs;
      // The same flight again until it is answered: the peer answers a repeat with the answer it already gave.
      let answer: Uint8Array | undefined;
      while (answer === undefined) {
        await this.sendPayload(PREFIX_HANDSHAKE, peerToken, flight);
        const wait = Math.min(FLIGHT_RESEND_MS, Math.max(deadline - Date.now(), 0));
        answer = await valueWithin(reply, wait);
        if (answer === undefined && Date.now() >= deadline) {
          throw new OverlayError(`${peerNodeId} did not answer through ${this.relay.host}:${this.relay.port}`);
        }
      }
      const answerFlight = Flight.parse(answer, TAG_RESPONDER, RESPONDER_HELLO_LEN, RESPONDER_FLIGHT_LEN);
      if (!answerFlight.verify()) {
        throw new HandshakeError("the responder flight signature does not verify");
      }
      if (answerFlight.nodeId !== peerNodeId) {
        throw new HandshakeError(`we dialled ${peerNodeId}, but the peer is ${answerFlight.nodeId}`);
      }
      const sessionKey = state.finish(answerFlight.hello);
      return { keys: deriveLinkKeys(sessionKey), peerHybridPublicKey: answerFlight.identityPk };
    } finally {
      if (this.handshakes.get(key) === deliverReply) {
        this.handshakes.delete(key);
      }
    }
  }

  /** Open a session link to a peer over this relay. Call from a running event loop. */
  link(peerToken: Uint8Array, keys: LinkKeys): RelayLink {
    const link = new RelayLink(this, peerToken, keys, nextLinkId());
    link.start();
    const key = hexOf(peerToken);
    // Anything that overtook the link is delivered first, then the link takes over.
    for (const sealed of this.early.get(key) ?? []) {
      link.deliver(sealed);
    }
    this.early.delete(key);
    const kept = (this.peers.get(key) ?? []).filter((existing) => !existing.isClosed());
    kept.unshift(link);
    while (kept.length > LINKS_PER_PEER) {
      kept.pop()?.close();
    }
    this.peers.set(key, kept);
    return link;
  }

  /** The addresses the relay sees for us and for a peer (STUN-style). This is what makes a hole punch possible. */
  async locate(peerToken: Uint8Array): Promise<Located> {
    return this.relayClient.locate(this.selfToken, peerToken);
  }

  /**
   * The addresses a peer may try for a hole punch to this node.
   *
   * The one the relay sees for the registration socket comes first: it is asked on that same socket, so it is the NAT
   * mapping the punch will use. This machine's own address towards the relay follows when it is not loopback, for a
   * peer on the same network, which a NAT would not loop traffic back to.
   */
  async punchCandidates(peerToken: Uint8Array): Promise<Candidate[]> {
    const located = await this.locate(peerToken);
    const out: Candidate[] = [{ addr: addrText(located.selfAddr), private: false }];
    const port = this.punchTable.localPort();
    // With no route to the relay from this host, only the relay's view is offered.
    const ip = await routeSource(this.relay).catch(() => null);
    if (ip !== null && port !== null) {
      const own: SocketAddr = [ip, port];
      if (addrText(own) !== addrText(located.selfAddr) && acceptableCandidate(own, false)) {
        out.push({ addr: addrText(own), private: true });
      }
    }
    return out;
  }

  /** Register a hole-punch attempt on the registration socket (see `PunchTable.begin`). */
  punchBegin(params: PunchParams): Running {
    return this.punchTable.begin(params);
  }

  /** Forget a peer, because its session ended. */
  forget(peerToken: Uint8Array): void {
    const key = hexOf(peerToken);
    this.peers.delete(key);
    this.early.delete(key);
  }
}

/**
 * Answer an inbound handshake flight. Returns the link keys, the peer's node id and hybrid public key (both from its
 * signed flight), and the answer to send back. Null when the flight does not verify.
 */
export function answerHandshake(flight: Uint8Array, identity: HybridIdentity): AnsweredHandshake | null {
  try {
    const hello = Flight.parse(flight, TAG_INITIATOR, INITIATOR_HELLO_LEN, INITIATOR_FLIGHT_LEN);
    if (!hello.verify()) {
      return null;
    }
    const { responderHello, sessionKey } = respond(hello.hello);
    return {
      keys: swapLinkKeys(deriveLinkKeys(sessionKey)),
      peerNodeId: hello.nodeId,
      peerHybridPublicKey: hello.identityPk,
      reply: buildFlight(TAG_RESPONDER, responderHello, identity).toWire(),
    };
  } catch (error) {
    if (error instanceof TransferdError) {
      return null;
    }
    throw error;
  }
}
