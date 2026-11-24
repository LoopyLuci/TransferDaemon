import { concatBytes, constantTimeEqual, u32Bytes, u64Bytes, utf8 } from "./bytes.js";
import { blake3DeriveKey, blake3Keyed } from "./crypto.js";
import { ipFromBytes, ipToBytes } from "./addr.js";

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
