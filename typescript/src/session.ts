/**
 * The opening of a session: a handshake, then the HELLO / HELLO_ACK exchange that agrees a version.
 *
 * The initiator sends HELLO, advertising its version range and a nonce. The responder answers
 * HELLO_ACK with the single version both sides support, echoing the nonce. A session that cannot
 * agree is refused with version 0 and a reason. The stream engine (OPEN, DATA, ACK, ...) runs after
 * this and is not here.
 */
import { constantTimeEqual } from "./bytes.js";
import { randomBytes } from "./crypto.js";
import { handshakeInitiator, handshakeResponder } from "./handshake.js";
import { HybridIdentity } from "./identity.js";
import { SessionError } from "./errors.js";
import {
  Frame,
  HELLO,
  HELLO_ACK,
  VERSION_CURRENT,
  VERSION_MIN,
  encodeHelloExt,
  negotiate,
  type Hello,
  type HelloAck,
  type ServiceInfo,
} from "./frames.js";
import { Sealer, TunnelReader, writeFrame, type LinkKeys } from "./tunnel.js";
import type { Link } from "./wire.js";

/** The frame version HELLO and HELLO_ACK carry. The negotiated version is in their bodies. */
export const HELLO_FRAME_VERSION = 2;

export interface Session {
  peerNodeId: string;
  version: number;
  peerName: string;
  peerServices: ServiceInfo[];
  keys: LinkKeys;
  sealer: Sealer;
  inbound: TunnelReader;
  link: Link;
}

export interface ConnectOptions {
  name?: string;
  expectNodeId?: string;
  nonce?: Uint8Array;
}

export interface AcceptOptions {
  name?: string;
}

/** Opens a session as the initiator: handshake, then HELLO and its answer. */
export async function connect(link: Link, identity: HybridIdentity, options: ConnectOptions = {}): Promise<Session> {
  const handshake = await handshakeInitiator(link, identity, options.expectNodeId);
  const sealer = new Sealer(handshake.keys.send);
  const inbound = new TunnelReader(handshake.keys);
  const nonce = options.nonce ?? randomBytes(16);
  const hello: Hello = {
    minVersion: VERSION_MIN,
    maxVersion: VERSION_CURRENT,
    nodeId: identity.nodeId,
    name: options.name ?? "",
    services: [],
    ext: encodeHelloExt({ pairing: null, direct: [] }),
    nonce,
  };
  await writeFrame(link.output, sealer, Frame.withBody(HELLO_FRAME_VERSION, HELLO, 1, hello));

  const answer = await inbound.nextFrame(link.input);
  if (answer.kind !== HELLO_ACK) {
    throw new SessionError(`expected HELLO_ACK, got kind 0x${answer.kind.toString(16).padStart(2, "0")}`);
  }
  const ack = answer.decode() as HelloAck;
  if (!constantTimeEqual(ack.nonce, nonce)) {
    throw new SessionError("the answer echoes a different hello nonce");
  }
  if (ack.version === 0) {
    throw new SessionError(`the peer refused the session: ${ack.reason}`);
  }
  if (ack.nodeId !== handshake.peerNodeId) {
    throw new SessionError("the hello answer names a different node than the handshake proved");
  }
  if (ack.version < VERSION_MIN || ack.version > VERSION_CURRENT) {
    throw new SessionError(`the peer agreed to version ${ack.version}, outside our range`);
  }
  return {
    peerNodeId: ack.nodeId,
    version: ack.version,
    peerName: ack.name,
    peerServices: ack.services,
    keys: handshake.keys,
    sealer,
    inbound,
    link,
  };
}

/** Opens a session as the responder: handshake, then the HELLO and our answer to it. */
export async function accept(link: Link, identity: HybridIdentity, options: AcceptOptions = {}): Promise<Session> {
  const handshake = await handshakeResponder(link, identity);
  const sealer = new Sealer(handshake.keys.send);
  const inbound = new TunnelReader(handshake.keys);
  const first = await inbound.nextFrame(link.input);
  if (first.kind !== HELLO) {
    throw new SessionError(`expected HELLO, got kind 0x${first.kind.toString(16).padStart(2, "0")}`);
  }
  const hello = first.decode() as Hello;

  let reason = "";
  let agreed: number | null = null;
  if (hello.nodeId !== handshake.peerNodeId) {
    reason = `the hello names ${hello.nodeId} but the handshake proved ${handshake.peerNodeId}`;
  } else {
    agreed = negotiate(hello.minVersion, hello.maxVersion);
    if (agreed === null) {
      reason = `no common protocol version: it speaks ${hello.minVersion}-${hello.maxVersion}`;
    }
  }
  const ack: HelloAck = {
    version: agreed ?? 0,
    nodeId: identity.nodeId,
    name: options.name ?? "",
    services: [],
    nonce: hello.nonce,
    reason,
    ext: new Uint8Array(0),
  };
  await writeFrame(link.output, sealer, Frame.withBody(HELLO_FRAME_VERSION, HELLO_ACK, 1, ack));
  if (agreed === null) {
    throw new SessionError(`refused the session: ${reason}`);
  }
  return {
    peerNodeId: hello.nodeId,
    version: agreed,
    peerName: hello.name,
    peerServices: hello.services,
    keys: handshake.keys,
    sealer,
    inbound,
    link,
  };
}
