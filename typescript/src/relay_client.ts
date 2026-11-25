/**
 * A client of relayd: register, keepalive, locate and forward, over relayd's own UDP messages.
 *
 * relayd issues a proof-of-work challenge and refuses a register, keepalive, locate or forward whose
 * proof does not match its current challenge. So each of those first fetches the challenge, solves it,
 * and sends the request. A forward's proof is over the destination token, as relayd checks it.
 *
 * The client holds one UDP socket. Replies to requests (challenge, located, error, the ack of a forward)
 * wait in a mailbox for the caller, and payloads delivered to this client wait in another for
 * `delivered()`. Requests run one at a time, so a reply is matched to the request waiting for it. A reply
 * that arrives after its request timed out is dropped before the next request is sent.
 *
 * IPv4 and IPv6 relays are both supported; ICMP errors from the relay are ignored, and the request that
 * they affect times out.
 */
import dgram from "node:dgram";
import { isIPv6 } from "node:net";
import { DecodeError, RelayProtocolError, RelayRefused, RelayTimeout, TransferdError } from "./errors.js";
import {
  Tag,
  type Challenge,
  type Located,
  type RelayError,
  type SocketAddr,
  decodeAckOrDelivered,
  decodeChallenge,
  decodeError,
  decodeLocated,
  encodeForward,
  encodeKeepalive,
  encodeLocate,
  encodeRegister,
  encodeRegisterGhost,
  solvePowYielding,
  split,
} from "./relay.js";
import { type GhostKey, binding } from "./ghostkey.js";

export interface RelayAddress {
  host: string;
  port: number;
}

export interface Delivered {
  senderSeq: number;
  ciphertext: Uint8Array;
}


type Reply =
  | { kind: "challenge"; challenge: Challenge }
  | { kind: "located"; located: Located }
  | { kind: "error"; error: RelayError }
  | { kind: "acked"; senderSeq: number };

/** A FIFO of items with waiters: `take` resolves with the next item, or rejects after a timeout. */
class Mailbox<T> {
  private readonly items: T[] = [];
  private readonly waiting: Array<(item: T) => void> = [];

  put(item: T): void {
    const waiter = this.waiting.shift();
    if (waiter !== undefined) {
      waiter(item);
    } else {
      this.items.push(item);
    }
  }

  drain(): void {
    this.items.length = 0;
  }

  /** Resolves with the next item, waiting as long as it takes. */
  next(): Promise<T> {
    const ready = this.items.shift();
    if (ready !== undefined) {
      return Promise.resolve(ready);
    }
    return new Promise<T>((resolve) => this.waiting.push(resolve));
  }

  take(timeoutMs: number, onTimeout: () => TransferdError): Promise<T> {
    const ready = this.items.shift();
    if (ready !== undefined) {
      return Promise.resolve(ready);
    }
    return new Promise<T>((resolve, reject) => {
      const waiter = (item: T): void => {
        clearTimeout(timer);
        resolve(item);
      };
      const timer = setTimeout(() => {
        const index = this.waiting.indexOf(waiter);
        if (index >= 0) {
          this.waiting.splice(index, 1);
        }
        reject(onTimeout());
      }, timeoutMs);
      this.waiting.push(waiter);
    });
  }
}

function isInvalidPow(reply: Reply): boolean {
  return reply.kind === "error" && reply.error.code === "InvalidPoW";
}

/** Narrows a reply to `kind`, or throws the relay's refusal or a protocol mismatch. */
function expect<K extends Reply["kind"]>(reply: Reply, kind: K): Extract<Reply, { kind: K }> {
  if (reply.kind === "error") {
    throw new RelayRefused(reply.error.code, reply.error.detail);
  }
  if (reply.kind !== kind) {
    throw new RelayProtocolError(`expected a ${kind} reply, got ${reply.kind}`);
  }
  return reply as Extract<Reply, { kind: K }>;
}

/**
 * The address this host sends from towards `relay`. A UDP `connect` sends nothing: it only makes the OS choose the
 * source address it would use, which is the address the relay sees for a socket bound to the wildcard.
 */
export function routeSource(relay: RelayAddress): Promise<string> {
  return new Promise((resolve, reject) => {
    const probe = dgram.createSocket(isIPv6(relay.host) ? "udp6" : "udp4");
    probe.once("error", (error) => {
      probe.close();
      reject(error);
    });
    probe.connect(relay.port, relay.host, () => {
      const { address } = probe.address();
      probe.close();
      resolve(address);
    });
  });
}

export class RelayClient {
  private socket: dgram.Socket | null = null;
  private readonly replies = new Mailbox<Reply>();
  private readonly inbox = new Mailbox<Delivered>();
  private chain: Promise<unknown> = Promise.resolve();
  private seq = 0;
  /** This client's socket address, as the relay sees it. Set by `open()`. */
  localAddr: SocketAddr | null = null;
  /**
   * Offered every datagram before the relay's replies are read. Returns true when it took the datagram. The hole-punch
   * table uses this: its probes arrive on this same socket, from the peers rather than the relay.
   */
  onDatagram: ((datagram: Uint8Array, from: SocketAddr) => boolean) | null = null;

  constructor(
    private readonly relay: RelayAddress,
    private readonly timeoutMs = 5000,
  ) {}

  async open(): Promise<void> {
    const family = isIPv6(this.relay.host) ? "udp6" : "udp4";
    const socket = dgram.createSocket(family);
    // Node hands over Buffers; copy to a plain Uint8Array so every decoded field has one type.
    socket.on("message", (datagram, info) => this.received(new Uint8Array(datagram), [info.address, info.port]));
    // ICMP refusals surface here on Windows; the request they affect times out instead.
    socket.on("error", () => undefined);
    const anyAddress = family === "udp6" ? "::" : "0.0.0.0";
    await new Promise<void>((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(0, anyAddress, () => {
        socket.off("error", reject);
        resolve();
      });
    });
    const { port } = socket.address();
    this.localAddr = [await routeSource(this.relay), port];
    this.socket = socket;
  }

  close(): void {
    this.socket?.close();
    this.socket = null;
  }

  /** The relay's current proof-of-work challenge. */
  async challenge(): Promise<Challenge> {
    const reply = await this.exchange(Uint8Array.of(Tag.CHALLENGE));
    return expect(reply, "challenge").challenge;
  }

  /** Registers `token` at this client's address. Returns once relayd accepts it. */
  async register(token: Uint8Array): Promise<void> {
    const seq = this.nextSeq();
    await this.withProof(token, (nonce) => encodeRegister(token, nonce, seq), "challenge");
  }

  /**
   * Registers `token` with a ghost key certificate (`certificate` is its bincode). The ghost key signs the binding of
   * this token and sequence number, so a certificate someone else saw cannot be reused.
   */
  async registerGhost(token: Uint8Array, certificate: Uint8Array, ghost: GhostKey): Promise<void> {
    const seq = this.nextSeq();
    const signature = ghost.sign(binding(token, seq));
    await this.withProof(
      token,
      (nonce) => encodeRegisterGhost(token, nonce, seq, certificate, signature),
      "challenge",
    );
  }

  /** Refreshes a registration. relayd sends nothing back, so this returns once the datagram is out. */
  async keepalive(token: Uint8Array): Promise<void> {
    const seq = this.nextSeq();
    const current = await this.challenge();
    this.send(encodeKeepalive(token, await solvePowYielding(current.difficulty, current.challenge, token), seq));
  }

  /** The addresses of `selfToken` and `peerToken`, as the relay sees them. `selfToken` must be ours. */
  async locate(selfToken: Uint8Array, peerToken: Uint8Array): Promise<Located> {
    const seq = this.nextSeq();
    const reply = await this.withProof(selfToken, (nonce) => encodeLocate(selfToken, peerToken, nonce, seq), "located");
    if (reply.located.request !== seq) {
      throw new RelayProtocolError("the location answers a different request");
    }
    return reply.located;
  }

  /** Sends `payload` (a relay payload, see `encapsulate`) to the peer registered under `peerToken`. */
  async forward(peerToken: Uint8Array, payload: Uint8Array): Promise<void> {
    const senderSeq = this.nextSeq() & 0xffff;
    const reply = await this.withProof(
      peerToken,
      (nonce) => encodeForward(peerToken, nonce, senderSeq, payload),
      "acked",
    );
    if (reply.senderSeq !== senderSeq) {
      throw new RelayProtocolError("the ack answers a different forward");
    }
  }

  /** The next payload delivered to this client. */
  async delivered(timeoutMs = this.timeoutMs): Promise<Delivered> {
    return this.inbox.take(timeoutMs, () => new RelayTimeout("no payload was delivered in time"));
  }

  private nextSeq(): number {
    this.seq += 1;
    return this.seq;
  }

  /** Sends a datagram from this client's socket to any address (a peer, for a hole punch). */
  sendTo(datagram: Uint8Array, addr: SocketAddr): void {
    if (this.socket === null) {
      throw new TransferdError("the relay client is not open");
    }
    this.socket.send(datagram, addr[1], addr[0]);
  }

  /** The next payload delivered to this client, waiting as long as it takes (for a receive loop). */
  nextDelivered(): Promise<Delivered> {
    return this.inbox.next();
  }

  private send(datagram: Uint8Array): void {
    this.sendTo(datagram, [this.relay.host, this.relay.port]);
  }

  private received(datagram: Uint8Array, from: SocketAddr): void {
    if (this.onDatagram?.(datagram, from) === true) {
      return;
    }
    const message = split(datagram);
    if (message === null) {
      return;
    }
    try {
      switch (message.tag) {
        case Tag.ACK: {
          const ack = decodeAckOrDelivered(message.body);
          if (ack.kind === "delivered") {
            this.inbox.put({ senderSeq: ack.senderSeq, ciphertext: ack.ciphertext });
          } else {
            this.replies.put({ kind: "acked", senderSeq: ack.senderSeq });
          }
          return;
        }
        case Tag.CHALLENGE:
          this.replies.put({ kind: "challenge", challenge: decodeChallenge(message.body) });
          return;
        case Tag.ERROR:
          this.replies.put({ kind: "error", error: decodeError(message.body) });
          return;
        case Tag.LOCATE:
          this.replies.put({ kind: "located", located: decodeLocated(message.body) });
          return;
        default:
          return;
      }
    } catch (error) {
      if (!(error instanceof DecodeError)) {
        throw error;
      }
      // Not a message we can read; the relay's own frames are never this.
    }
  }

  /** Sends one request and waits for its reply. Requests run one at a time. */
  private exchange(datagram: Uint8Array): Promise<Reply> {
    return this.exclusive(async () => {
      this.replies.drain(); // replies to requests that already timed out
      this.send(datagram);
      return this.replies.take(
        this.timeoutMs,
        () => new RelayTimeout(`the relay did not answer within ${this.timeoutMs} ms`),
      );
    });
  }

  private exclusive<T>(task: () => Promise<T>): Promise<T> {
    const run = this.chain.then(task, task);
    this.chain = run.catch(() => undefined);
    return run;
  }

  /** One proof-of-work request on `token`, retried once if the challenge rotated under it. */
  private async withProof<K extends Reply["kind"]>(
    token: Uint8Array,
    build: (nonce: bigint) => Uint8Array,
    kind: K,
  ): Promise<Extract<Reply, { kind: K }>> {
    const first = await this.proofExchange(token, build);
    const reply = isInvalidPow(first) ? await this.proofExchange(token, build) : first;
    return expect(reply, kind);
  }

  private async proofExchange(token: Uint8Array, build: (nonce: bigint) => Uint8Array): Promise<Reply> {
    const current = await this.challenge();
    return this.exchange(build(await solvePowYielding(current.difficulty, current.challenge, token)));
  }
}
