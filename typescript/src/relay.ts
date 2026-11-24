import { Reader, Writer } from "./bincode.js";
import { concatBytes, u32Bytes, u64Bytes } from "./bytes.js";
import { blake3Hash } from "./crypto.js";
import { TransferdError, DecodeError } from "./errors.js";
import { ipFromBytes, ipToBytes, type IpFamily } from "./addr.js";

/** The relay's message tags (relayd's protocol). */
export const Tag = {
  REGISTER: 0x01,
  FORWARD: 0x02,
  KEEPALIVE: 0x03,
  CHALLENGE: 0x04,
  ERROR: 0x05,
  ACK: 0x06,
  REGISTER_GHOST: 0x07,
  LOCATE: 0x08,
} as const;

/** Error codes travel as the enum's variant index (a u32), in this order. */
export const ERROR_CODES: readonly string[] = [
  "InvalidPoW",
  "TokenNotFound",
  "TokenAlreadyExists",
  "PayloadTooLarge",
  "RateLimited",
  "SeqReplay",
  "BandwidthExceeded",
  "GhostRequired",
  "GhostRejected",
  "InternalError",
];

export function errorCodeName(index: number): string {
  return index >= 0 && index < ERROR_CODES.length ? ERROR_CODES[index] : `Unknown(${index})`;
}

// --- Overlay relay payload ------------------------------------------------------------------------

export const PREFIX_HANDSHAKE = 0x01;
export const PREFIX_DATA = 0x02;
export const PREFIX_HANDSHAKE_REPLY = 0x03;

/** `len u32 LE || data`, zero-padded to a power of two of at least 64 bytes (the length is included). */
export function pad(data: Uint8Array): Uint8Array {
  let power = 64;
  while (power < data.length + 4) {
    power *= 2;
  }
  const out = new Uint8Array(power);
  out.set(u32Bytes(data.length), 0);
  out.set(data, 4);
  return out;
}

export interface Unpadded {
  prefix: number;
  senderToken: Uint8Array;
  body: Uint8Array;
}

/** Returns `(prefix, sender token, body)`, or `null` when the padding does not describe the bytes. */
export function unpad(data: Uint8Array): Unpadded | null {
  if (data.length < 4) {
    return null;
  }
  const length = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(0, true);
  if (4 + length > data.length) {
    return null;
  }
  const body = data.subarray(4, 4 + length);
  if (body.length < 33) {
    return null;
  }
  return { prefix: body[0], senderToken: body.slice(1, 33), body: body.slice(33) };
}

export function encapsulate(prefix: number, senderToken: Uint8Array, body: Uint8Array): Uint8Array {
  if (senderToken.length !== 32) {
    throw new TransferdError("a sender token is 32 bytes");
  }
  return pad(concatBytes(Uint8Array.of(prefix), senderToken, body));
}

// --- Proof of work --------------------------------------------------------------------------------

/** `blake3(challenge || token || nonce u64 LE)` must start with `difficulty` zero bits. */
export function powOk(difficulty: number, challenge: Uint8Array, token: Uint8Array, nonce: bigint): boolean {
  const digest = blake3Hash(concatBytes(challenge, token, u64Bytes(nonce)));
  const full = Math.floor(difficulty / 8);
  const tail = difficulty % 8;
  if (full >= digest.length) {
    return false;
  }
  for (let i = 0; i < full; i++) {
    if (digest[i] !== 0) {
      return false;
    }
  }
  if (tail !== 0) {
    return digest[full] >> (8 - tail) === 0;
  }
  return true;
}

export function solvePow(difficulty: number, challenge: Uint8Array, token: Uint8Array, start = 0n): bigint {
  let nonce = start;
  while (!powOk(difficulty, challenge, token, nonce)) {
    nonce += 1n;
  }
  return nonce;
}

// --- Messages -------------------------------------------------------------------------------------

export interface SplitMessage {
  tag: number;
  body: Uint8Array;
}

export function split(datagram: Uint8Array): SplitMessage | null {
  if (datagram.length === 0) {
    return null;
  }
  const tag = datagram[0];
  if (!(Object.values(Tag) as number[]).includes(tag)) {
    return null;
  }
  return { tag, body: datagram.slice(1) };
}

export type SocketAddr = [string, number];

function writeSocketAddr(w: Writer, addr: SocketAddr): void {
  const { family, bytes } = ipToBytes(addr[0]);
  w.u32(family === 4 ? 0 : 1);
  w.raw(bytes);
  w.u16(addr[1]);
}

function readSocketAddr(r: Reader): SocketAddr {
  const variant = r.u32();
  let family: IpFamily;
  let bytes: Uint8Array;
  if (variant === 0) {
    family = 4;
    bytes = r.raw(4);
  } else if (variant === 1) {
    family = 6;
    bytes = r.raw(16);
  } else {
    throw new DecodeError("socket address variant is neither V4 nor V6");
  }
  return [ipFromBytes(family, bytes), r.u16()];
}

function tagged(tag: number, write: (w: Writer) => void): Uint8Array {
  const w = new Writer();
  write(w);
  return concatBytes(Uint8Array.of(tag), w.getValue());
}

export function encodeRegister(sessionToken: Uint8Array, powNonce: bigint, seq: number): Uint8Array {
  return tagged(Tag.REGISTER, (w) => {
    w.raw(sessionToken);
    w.u64(powNonce);
    w.u32(seq);
  });
}

export function encodeKeepalive(sessionToken: Uint8Array, powNonce: bigint, seq: number): Uint8Array {
  return tagged(Tag.KEEPALIVE, (w) => {
    w.raw(sessionToken);
    w.u64(powNonce);
    w.u32(seq);
  });
}

export function encodeForward(sessionToken: Uint8Array, powNonce: bigint, senderSeq: number, ciphertext: Uint8Array): Uint8Array {
  return tagged(Tag.FORWARD, (w) => {
    w.raw(sessionToken);
    w.u64(powNonce);
    w.u16(senderSeq);
    w.bytes(ciphertext);
  });
}

export function encodeChallenge(challenge: Uint8Array, expiresAt: number, difficulty: number): Uint8Array {
  return tagged(Tag.CHALLENGE, (w) => {
    w.raw(challenge);
    w.u64(expiresAt);
    w.u32(difficulty);
  });
}

export function encodeLocate(selfToken: Uint8Array, peerToken: Uint8Array, powNonce: bigint, seq: number): Uint8Array {
  return tagged(Tag.LOCATE, (w) => {
    w.raw(selfToken);
    w.raw(peerToken);
    w.u64(powNonce);
    w.u32(seq);
  });
}

export function encodeLocated(selfAddr: SocketAddr, peerAddr: SocketAddr | null, request: number): Uint8Array {
  return tagged(Tag.LOCATE, (w) => {
    writeSocketAddr(w, selfAddr);
    w.option(peerAddr, writeSocketAddr);
    w.u32(request);
  });
}

export function encodeError(codeIndex: number, seq: number, detail: string): Uint8Array {
  return tagged(Tag.ERROR, (w) => {
    w.u32(codeIndex);
    w.u32(seq);
    w.string(detail);
  });
}

export function encodeAck(senderSeq: number): Uint8Array {
  return tagged(Tag.ACK, (w) => w.u16(senderSeq));
}

export function encodeDelivered(senderSeq: number, ciphertext: Uint8Array): Uint8Array {
  return tagged(Tag.ACK, (w) => {
    w.u16(senderSeq);
    w.bytes(ciphertext);
  });
}

export interface Challenge {
  challenge: Uint8Array;
  expiresAt: number;
  difficulty: number;
}

export interface Located {
  selfAddr: SocketAddr;
  peerAddr: SocketAddr | null;
  request: number;
}

export interface RelayError {
  code: string;
  seq: number;
  detail: string;
}

export type AckOrDelivered =
  | { kind: "acked"; senderSeq: number }
  | { kind: "delivered"; senderSeq: number; ciphertext: Uint8Array };

export function decodeChallenge(body: Uint8Array): Challenge {
  const r = new Reader(body);
  return { challenge: r.raw(16), expiresAt: r.u64(), difficulty: r.u32() };
}

export function decodeLocated(body: Uint8Array): Located {
  const r = new Reader(body);
  const selfAddr = readSocketAddr(r);
  const peerAddr = r.option(readSocketAddr);
  return { selfAddr, peerAddr, request: r.u32() };
}

export function decodeError(body: Uint8Array): RelayError {
  const r = new Reader(body);
  const code = errorCodeName(r.u32());
  return { code, seq: r.u32(), detail: r.string() };
}

/** A tag 0x06 body: two bytes is an ACK; anything longer is a DELIVERED. */
export function decodeAckOrDelivered(body: Uint8Array): AckOrDelivered {
  if (body.length === 2) {
    return { kind: "acked", senderSeq: new Reader(body).u16() };
  }
  const r = new Reader(body);
  const senderSeq = r.u16();
  return { kind: "delivered", senderSeq, ciphertext: r.bytes() };
}
