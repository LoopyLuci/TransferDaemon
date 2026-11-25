import { bytesToHex, concatBytes, constantTimeEqual, u16Bytes } from "./bytes.js";
import { blake3DeriveKey, blake3Hash, mlkemDecapsulate, mlkemEncapsulate, mlkemKeypair, randomBytes, x25519Exchange, x25519Generate, x25519Public } from "./crypto.js";
import { HandshakeError } from "./errors.js";
import { HYBRID_PK_LEN, HYBRID_SIG_LEN, HybridIdentity, verifyHybrid } from "./identity.js";
import { type LinkKeys, deriveLinkKeys, swapLinkKeys } from "./tunnel.js";
import { Link, readBlob, writeBlob } from "./wire.js";

/**
 * The authenticated hybrid handshake (§1), protocol version 2, ciphersuite 0x0002.
 *
 *   initiator flight (8568 bytes): tag 0x11 | version u16 LE | suite u16 LE | x25519_pk (32)
 *     | ml_kem_768_ek (1184) | identity_pk (2624) | transcript (32) | signature (4691)
 *   responder flight (8472 bytes): the same, tag 0x12, with the ML-KEM ciphertext (1088).
 */
export const TAG_INITIATOR = 0x11;
export const TAG_RESPONDER = 0x12;
export const PROTOCOL_VERSION = 2;
export const CIPHERSUITE_HYBRID = 0x0002;

export const X25519_PK_LEN = 32;
export const KEM_EK_LEN = 1184;
export const KEM_CT_LEN = 1088;
export const TRANSCRIPT_LEN = 32;
export const INITIATOR_HELLO_LEN = X25519_PK_LEN + KEM_EK_LEN; // 1216
export const RESPONDER_HELLO_LEN = X25519_PK_LEN + KEM_CT_LEN; // 1120
export const INITIATOR_FLIGHT_LEN = 1 + 2 + 2 + INITIATOR_HELLO_LEN + HYBRID_PK_LEN + TRANSCRIPT_LEN + HYBRID_SIG_LEN; // 8568
export const RESPONDER_FLIGHT_LEN = 1 + 2 + 2 + RESPONDER_HELLO_LEN + HYBRID_PK_LEN + TRANSCRIPT_LEN + HYBRID_SIG_LEN; // 8472

export const SESSION_KEY_CONTEXT = "TransferDaemon-v1-hybrid-session-key";

function transcriptOf(tag: number, version: number, suite: number, hello: Uint8Array, identityPk: Uint8Array): Uint8Array {
  return blake3Hash(concatBytes(Uint8Array.of(tag), u16Bytes(version), u16Bytes(suite), hello, identityPk));
}

export function hybridKdf(x25519Ss: Uint8Array, kemSs: Uint8Array): Uint8Array {
  return blake3DeriveKey(SESSION_KEY_CONTEXT, concatBytes(x25519Ss, kemSs));
}

function readU16LE(data: Uint8Array, offset: number): number {
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint16(offset, true);
}

export class Flight {
  constructor(
    readonly tag: number,
    readonly version: number,
    readonly suite: number,
    readonly hello: Uint8Array,
    readonly identityPk: Uint8Array,
    readonly transcript: Uint8Array,
    readonly signature: Uint8Array,
  ) {}

  toWire(): Uint8Array {
    return concatBytes(
      Uint8Array.of(this.tag),
      u16Bytes(this.version),
      u16Bytes(this.suite),
      this.hello,
      this.identityPk,
      this.transcript,
      this.signature,
    );
  }

  static parse(data: Uint8Array, tag: number, helloLen: number, flightLen: number): Flight {
    if (data.length !== flightLen || data[0] !== tag) {
      throw new HandshakeError("flight is malformed");
    }
    let off = 1;
    const version = readU16LE(data, off);
    off += 2;
    const suite = readU16LE(data, off);
    off += 2;
    const hello = data.slice(off, off + helloLen);
    off += helloLen;
    const identityPk = data.slice(off, off + HYBRID_PK_LEN);
    off += HYBRID_PK_LEN;
    const transcript = data.slice(off, off + TRANSCRIPT_LEN);
    off += TRANSCRIPT_LEN;
    const signature = data.slice(off, off + HYBRID_SIG_LEN);
    return new Flight(tag, version, suite, hello, identityPk, transcript, signature);
  }

  /** Recomputes the transcript, then checks the hybrid signature over it. */
  verify(): boolean {
    const expected = transcriptOf(this.tag, this.version, this.suite, this.hello, this.identityPk);
    return constantTimeEqual(expected, this.transcript) && verifyHybrid(this.identityPk, this.transcript, this.signature);
  }

  get nodeId(): string {
    return bytesToHex(this.identityPk.subarray(0, 32));
  }
}

/** A signed flight carrying `hello`. Used by the TCP handshake and by the relay path, which send the same flights. */
export function buildFlight(tag: number, hello: Uint8Array, identity: HybridIdentity): Flight {
  const transcript = transcriptOf(tag, PROTOCOL_VERSION, CIPHERSUITE_HYBRID, hello, identity.publicKey);
  return new Flight(tag, PROTOCOL_VERSION, CIPHERSUITE_HYBRID, hello, identity.publicKey, transcript, identity.sign(transcript));
}

/** The ephemeral keys an initiator holds between its flight and the answer. */
export class InitiatorState {
  private readonly x25519Private: Uint8Array;
  private readonly kemSecret: Uint8Array;
  private readonly kemEk: Uint8Array;

  constructor(kemSeed?: Uint8Array, x25519Key?: Uint8Array) {
    this.x25519Private = x25519Key ?? x25519Generate();
    const kem = mlkemKeypair(kemSeed ?? randomBytes(64));
    this.kemSecret = kem.secretKey;
    this.kemEk = kem.publicKey;
  }

  hello(): Uint8Array {
    return concatBytes(x25519Public(this.x25519Private), this.kemEk);
  }

  /** The session key, from the responder's `x25519_pk || ml_kem_ciphertext`. */
  finish(responderHello: Uint8Array): Uint8Array {
    if (responderHello.length !== RESPONDER_HELLO_LEN) {
      throw new HandshakeError("responder hello has the wrong length");
    }
    const x25519Ss = x25519Exchange(this.x25519Private, responderHello.subarray(0, X25519_PK_LEN));
    const kemSs = mlkemDecapsulate(this.kemSecret, responderHello.subarray(X25519_PK_LEN));
    return hybridKdf(x25519Ss, kemSs);
  }
}

/** The responder's hello and session key, from the initiator's `x25519_pk || ml_kem_ek`. */
export function respond(initiatorHello: Uint8Array): { responderHello: Uint8Array; sessionKey: Uint8Array } {
  if (initiatorHello.length !== INITIATOR_HELLO_LEN) {
    throw new HandshakeError("initiator hello has the wrong length");
  }
  const privateKey = x25519Generate();
  const x25519Ss = x25519Exchange(privateKey, initiatorHello.subarray(0, X25519_PK_LEN));
  let kem: { sharedSecret: Uint8Array; ciphertext: Uint8Array };
  try {
    kem = mlkemEncapsulate(initiatorHello.subarray(X25519_PK_LEN));
  } catch {
    throw new HandshakeError("ML-KEM encapsulation key is invalid");
  }
  return {
    responderHello: concatBytes(x25519Public(privateKey), kem.ciphertext),
    sessionKey: hybridKdf(x25519Ss, kem.sharedSecret),
  };
}

export interface HandshakeResult {
  sessionKey: Uint8Array;
  peerNodeId: string;
  peerHybridPublicKey: Uint8Array;
  keys: LinkKeys;
}

export async function handshakeInitiator(
  link: Link,
  identity: HybridIdentity,
  expectNodeId?: string,
): Promise<HandshakeResult> {
  const state = new InitiatorState();
  const flight = buildFlight(TAG_INITIATOR, state.hello(), identity);
  await writeBlob(link.output, flight.toWire());
  const answer = Flight.parse(await readBlob(link.input), TAG_RESPONDER, RESPONDER_HELLO_LEN, RESPONDER_FLIGHT_LEN);
  if (!answer.verify()) {
    throw new HandshakeError("responder flight signature does not verify");
  }
  if (expectNodeId !== undefined && answer.nodeId !== expectNodeId) {
    throw new HandshakeError(`we dialled ${expectNodeId}, but the peer is ${answer.nodeId}`);
  }
  const sessionKey = state.finish(answer.hello);
  return {
    sessionKey,
    peerNodeId: answer.nodeId,
    peerHybridPublicKey: answer.identityPk,
    keys: deriveLinkKeys(sessionKey),
  };
}

export async function handshakeResponder(link: Link, identity: HybridIdentity): Promise<HandshakeResult> {
  const hello = Flight.parse(await readBlob(link.input), TAG_INITIATOR, INITIATOR_HELLO_LEN, INITIATOR_FLIGHT_LEN);
  if (!hello.verify()) {
    throw new HandshakeError("initiator flight signature does not verify");
  }
  const { responderHello, sessionKey } = respond(hello.hello);
  const answer = buildFlight(TAG_RESPONDER, responderHello, identity);
  await writeBlob(link.output, answer.toWire());
  return {
    sessionKey,
    peerNodeId: hello.nodeId,
    peerHybridPublicKey: hello.identityPk,
    keys: swapLinkKeys(deriveLinkKeys(sessionKey)),
  };
}
