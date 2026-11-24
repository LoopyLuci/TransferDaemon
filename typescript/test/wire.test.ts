import assert from "node:assert/strict";
import { test } from "node:test";
import { ipFromBytes, ipToBytes } from "../src/addr.js";
import { bytesToHex, concatBytes, hexToBytes, u64Bytes, utf8 } from "../src/bytes.js";
import { FrameError, InviteError, TunnelError } from "../src/errors.js";
import * as F from "../src/frames.js";
import { HybridIdentity } from "../src/identity.js";
import { acceptInvite, makeInvite } from "../src/invite.js";
import { PROBE_LEN, decodeProbe, derivePunchKeys, encodeProbe, gatewayUnwrap, gatewayWrap } from "../src/punch.js";
import * as R from "../src/relay.js";
import { FrameCounter, Opener, ReplayWindow, Sealer, deriveLinkKeys } from "../src/tunnel.js";
import { loadVectors, pattern, pattern32 } from "./helpers.js";

const wire = loadVectors("wire.json");
const fill = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v);

// --- Addresses ------------------------------------------------------------------------------------

test("IPv4 and IPv6 addresses round-trip through their octets", () => {
  const v4 = ipToBytes("203.0.113.5");
  assert.equal(v4.family, 4);
  assert.equal(ipFromBytes(4, v4.bytes), "203.0.113.5");
  const v6 = ipToBytes("2001:db8::1");
  assert.equal(v6.family, 6);
  assert.equal(v6.bytes.length, 16);
  assert.equal(ipFromBytes(6, v6.bytes), "2001:db8::1");
  assert.equal(ipFromBytes(6, ipToBytes("::").bytes), "::");
  assert.throws(() => ipToBytes("not an address"));
});

// --- Tunnel ---------------------------------------------------------------------------------------

test("link keys match the reference", () => {
  const t = wire.tunnel;
  const keys = deriveLinkKeys(hexToBytes(t.session_key));
  assert.equal(bytesToHex(keys.send), t.c2s);
  assert.equal(bytesToHex(keys.recv), t.s2c);
});

test("sealed frames match the reference byte for byte", () => {
  const sealer = new Sealer(hexToBytes(wire.tunnel.c2s));
  for (const f of wire.tunnel.frames) {
    assert.equal(bytesToHex(sealer.seal(hexToBytes(f.plaintext), BigInt(f.counter))), f.sealed);
  }
});

test("a shared counter hands out 0, 1, 2 and seals with them", () => {
  const counter = new FrameCounter();
  const sealer = new Sealer(hexToBytes(wire.tunnel.c2s), counter);
  const first = sealer.seal(new Uint8Array(0));
  assert.equal(bytesToHex(first.subarray(4, 12)), bytesToHex(u64Bytes(0n, false)));
  assert.equal(counter.next(), 1n);
});

test("reference frames open, and a replay is refused", () => {
  const t = wire.tunnel;
  const opener = new Opener(hexToBytes(t.c2s));
  for (const f of t.frames) {
    assert.deepEqual(opener.open(hexToBytes(f.sealed)), hexToBytes(f.plaintext));
  }
  assert.throws(() => opener.open(hexToBytes(t.frames[0].sealed)), TunnelError);
});

test("a flipped bit or a changed length does not authenticate", () => {
  const key = hexToBytes(wire.tunnel.c2s);
  const sealed = hexToBytes(wire.tunnel.frames[2].sealed);
  const flipped = new Uint8Array(sealed);
  flipped[flipped.length - 1] ^= 1;
  assert.throws(() => new Opener(key).open(flipped), TunnelError);
  const lengthened = new Uint8Array(sealed);
  lengthened[3] ^= 0x7f;
  assert.throws(() => new Opener(key).open(lengthened), TunnelError);
});

test("the replay window is 4096 wide", () => {
  const w = new ReplayWindow();
  assert.equal(w.accept(0n), true);
  assert.equal(w.accept(5n), true);
  assert.equal(w.accept(3n), true, "late but inside the window");
  assert.equal(w.accept(3n), false, "the same counter twice");
  assert.equal(w.accept(5n + 4096n), true);
  assert.equal(w.accept(5n), false, "fell out of the window");
  assert.equal(w.accept(100_000n), true);
  assert.equal(w.accept(100_000n - 4000n), true);
  assert.equal(w.accept(100_000n - 4000n), false);
});

// --- Overlay frames -------------------------------------------------------------------------------

const nodeA = "ab".repeat(32);
const nodeB = "cd".repeat(32);
const services = [{ name: "chat", description: "text" }];
const helloExtBytes = F.encodeHelloExt({ pairing: fill(16, 7), direct: ["192.0.2.1:4000"] });

interface FrameCase {
  name: string;
  kind: number;
  version: number;
  seq: number;
  obj: unknown;
  ackBase?: boolean;
}

const frameCases: FrameCase[] = [
  {
    name: "HELLO",
    kind: F.HELLO,
    version: 2,
    seq: 1,
    obj: { minVersion: 1, maxVersion: 3, nodeId: nodeA, name: "node-a", services, ext: helloExtBytes, nonce: fill(16, 9) },
  },
  {
    name: "HELLO_ACK",
    kind: F.HELLO_ACK,
    version: 2,
    seq: 2,
    obj: { version: 2, nodeId: nodeB, name: "", services: [], nonce: fill(16, 9), reason: "", ext: new Uint8Array(0) },
  },
  { name: "OPEN", kind: F.OPEN, version: 2, seq: 3, obj: { stream: 3, service: "chat", nodeId: nodeA } },
  { name: "OPEN_OK", kind: F.OPEN_OK, version: 2, seq: 4, obj: { stream: 3, route: "relay" } },
  { name: "OPEN_ERR", kind: F.OPEN_ERR, version: 2, seq: 5, obj: { stream: 3, code: "denied", reason: "nope" } },
  { name: "DATA", kind: F.DATA, version: 2, seq: 6, obj: { stream: 3, seq: 5, fin: false, payload: utf8("hello") } },
  { name: "DATA_FIN", kind: F.DATA, version: 2, seq: 7, obj: { stream: 3, seq: 6, fin: true, payload: new Uint8Array(0) } },
  { name: "ACK", kind: F.ACK, version: 2, seq: 8, obj: { stream: 3, seq: 6, sack: [[8, 10], [12, 13]] } },
  { name: "ACK_BASE", kind: F.ACK, version: 2, seq: 9, obj: null, ackBase: true },
  { name: "WINDOW", kind: F.WINDOW, version: 2, seq: 10, obj: { stream: 3, credit: 262144 } },
  { name: "CLOSE", kind: F.CLOSE, version: 2, seq: 11, obj: { stream: 3, code: "ok", reason: "bye" } },
  { name: "CTRL_ACK", kind: F.CTRL_ACK, version: 2, seq: 12, obj: { seq: 42 } },
  { name: "PING", kind: F.PING, version: 2, seq: 13, obj: { nonce: 7n, sentUs: 1234567n } },
  { name: "PONG", kind: F.PONG, version: 2, seq: 14, obj: { nonce: 7n, sentUs: 1234567n } },
  {
    name: "ROUTES",
    kind: F.ROUTES,
    version: 2,
    seq: 15,
    obj: {
      routes: [
        {
          kind: "relay",
          rttMs: 12.5,
          loss: 0.01,
          mbps: 2.0,
          active: true,
          cwnd: 65536,
          inFlight: 1024,
          srttMs: 13.0,
          rtoMs: 300.0,
          sentBytes: 1000,
          retxBytes: 10,
        },
      ],
    },
  },
  {
    name: "CANDIDATE",
    kind: F.CANDIDATE,
    version: 3,
    seq: 16,
    obj: {
      id: 99n,
      reply: false,
      nonce: fill(32, 5),
      candidates: [
        { addr: "203.0.113.7:50000", private: false },
        { addr: "10.0.0.2:50000", private: true },
      ],
    },
  },
  { name: "BYE", kind: F.BYE, version: 2, seq: 17, obj: undefined },
];

for (const c of frameCases) {
  test(`frame ${c.name} matches the reference`, () => {
    const entry = wire.frames.find((f: { name: string }) => f.name === c.name);
    assert.ok(entry, `no vector named ${c.name}`);
    assert.equal(entry.kind, c.kind);
    assert.equal(entry.version, c.version);
    assert.equal(entry.seq, c.seq);
    const body = c.ackBase ? concatBytes(u64Bytes(3n), u64Bytes(6n)) : F.encodeBody(c.kind, c.obj);
    assert.equal(bytesToHex(body), entry.body);
    const frame = new F.Frame(c.version, c.kind, 0, c.seq, body);
    assert.equal(bytesToHex(frame.encode()), entry.frame);
    const decoded = F.decodeFrame(hexToBytes(entry.frame));
    assert.ok(decoded, "a complete frame decodes");
    assert.equal(decoded.used, hexToBytes(entry.frame).length);
    // ACK_BASE is covered by its own test below, since its expected value is not the body object.
    if (c.kind !== F.BYE && !c.ackBase) {
      assert.deepEqual(F.decodeBody(c.kind, decoded.frame.body), c.obj);
    }
  });
}

test("the ACK_BASE form reads as an ACK with no ranges", () => {
  const entry = wire.frames.find((f: { name: string }) => f.name === "ACK_BASE");
  const decoded = F.decodeFrame(hexToBytes(entry.frame));
  assert.ok(decoded);
  assert.deepEqual(F.decodeBody(F.ACK, decoded.frame.body), { stream: 3, seq: 6, sack: [] });
});

test("the flag bits survive the header", () => {
  const entry = wire.frames.find((f: { name: string }) => f.name === "flags_mirror_bulk");
  const decoded = F.decodeFrame(hexToBytes(entry.frame));
  assert.ok(decoded);
  assert.equal(decoded.frame.flags, 3);
  assert.equal(decoded.frame.isMirrored, true);
  assert.equal(decoded.frame.isBulk, true);
  assert.equal(decoded.frame.seq, 18);
});

test("the hello extension matches the reference", () => {
  const h = wire.hello_ext;
  const ext = { pairing: hexToBytes(h.pairing), direct: h.direct as string[] };
  assert.equal(bytesToHex(F.encodeHelloExt(ext)), h.bytes);
  assert.deepEqual(F.decodeHelloExt(hexToBytes(h.bytes)), ext);
});

test("an older extension with only the pairing still reads", () => {
  const old = F.encodeHelloExt({ pairing: fill(16, 3), direct: [] }).slice(0, 17);
  assert.deepEqual(F.decodeHelloExt(old), { pairing: fill(16, 3), direct: [] });
});

test("an unreadable extension is an empty one", () => {
  assert.deepEqual(F.decodeHelloExt(utf8("\u0009garbage")), { pairing: null, direct: [] });
});

test("an unknown kind is skipped, and known kinds pass", () => {
  const reader = new F.FrameReader();
  const unknown = new F.Frame(2, 0x55, 0, 1, utf8("xyz")).encode();
  const known = F.Frame.withBody(2, F.PING, 2, { nonce: 1n, sentUs: 2n }).encode();
  assert.deepEqual(
    reader.push(concatBytes(unknown, known)).map((f) => f.kind),
    [F.PING],
  );
});

test("bytes that are not ours empty the buffer", () => {
  const reader = new F.FrameReader();
  assert.deepEqual(reader.push(concatBytes(utf8("NOPE"), new Uint8Array(20))), []);
  assert.equal(reader.buffered(), 0);
  assert.throws(() => F.decodeFrame(concatBytes(utf8("NOPE"), new Uint8Array(20))), FrameError);
});

test("version negotiation picks the highest common version", () => {
  assert.equal(F.negotiate(1, 3, 1, 3), 3);
  assert.equal(F.negotiate(1, 2, 1, 3), 2);
  assert.equal(F.negotiate(4, 5, 1, 3), null);
});

// --- Invites --------------------------------------------------------------------------------------

test("the reference invite is accepted and its fields match", () => {
  const inv = wire.invite;
  const verified = acceptInvite(inv.invite, { now: inv.expires_at - 1 });
  assert.equal(verified.nodeId, inv.node_id);
  assert.equal(verified.name, inv.verified_name);
  assert.equal(bytesToHex(verified.keyFingerprint), inv.key_fingerprint);
  assert.equal(bytesToHex(verified.nonce), inv.nonce);
  assert.deepEqual(verified.relays, inv.relays);
  assert.deepEqual(verified.direct, inv.direct);
});

test("the reference refuses these invites, and so do we", () => {
  const inv = wire.invite;
  for (const refused of inv.refused) {
    assert.throws(() => acceptInvite(refused.invite, { now: inv.expires_at - 1 }), InviteError, refused.case);
  }
});

test("an expired invite is refused", () => {
  assert.throws(() => acceptInvite(wire.invite.invite, { now: wire.invite.expires_at + 1 }), InviteError);
});

test("an invite we make is accepted by our own reader", () => {
  const identity = HybridIdentity.generate("alpha");
  const made = makeInvite(identity, ["relay.example:4433"], ["192.0.2.10:4000"], 600, { now: 1_000_000 });
  const verified = acceptInvite(made.text, { now: 1_000_001 });
  assert.equal(verified.nodeId, identity.nodeId);
  assert.equal(bytesToHex(verified.nonce), bytesToHex(made.nonce));
});

// --- Hole punching --------------------------------------------------------------------------------

// The generator's attempt id. It is above 2^53, so it is written here rather than read from JSON.
const PUNCH_ID = 0x0102030405060708n;

test("punch keys match the reference", () => {
  const p = wire.punch;
  const keys = derivePunchKeys(PUNCH_ID, hexToBytes(p.initiator_nonce), hexToBytes(p.responder_nonce));
  assert.equal(bytesToHex(keys.probe), p.probe_key);
  assert.equal(bytesToHex(keys.link), p.link_key);
});

test("probes match the reference and decode", () => {
  const p = wire.punch;
  const keys = derivePunchKeys(PUNCH_ID, hexToBytes(p.initiator_nonce), hexToBytes(p.responder_nonce));
  for (const entry of p.probes) {
    const probe = { kind: entry.kind, fromInitiator: entry.from_initiator, id: PUNCH_ID, seq: entry.seq };
    const datagram = encodeProbe(keys, probe);
    assert.equal(bytesToHex(datagram), entry.datagram);
    assert.equal(datagram.length, PROBE_LEN);
    assert.deepEqual(decodeProbe(keys, datagram), probe);
  }
});

test("a probe under another key does not decode", () => {
  const p = wire.punch;
  const other = derivePunchKeys(PUNCH_ID + 1n, hexToBytes(p.initiator_nonce), hexToBytes(p.responder_nonce));
  assert.equal(decodeProbe(other, hexToBytes(p.probes[0].datagram)), null);
});

test("the gateway envelope round-trips for IPv4 and IPv6", () => {
  const datagram = utf8("datagram");
  assert.deepEqual(gatewayUnwrap(gatewayWrap(["2001:db8::5", 4500], datagram)), {
    addr: ["2001:db8::5", 4500],
    datagram,
  });
  assert.deepEqual(gatewayUnwrap(gatewayWrap(["198.51.100.1", 9], utf8("x"))), {
    addr: ["198.51.100.1", 9],
    datagram: utf8("x"),
  });
});

// --- Relay padding, payloads and messages ---------------------------------------------------------

test("padding matches the reference and is a power of two of at least 64 bytes", () => {
  for (const entry of wire.padding) {
    const padded = R.pad(hexToBytes(entry.input));
    assert.equal(bytesToHex(padded), entry.padded);
    assert.ok(padded.length >= 64 && (padded.length & (padded.length - 1)) === 0);
  }
});

test("the relay payload matches the reference", () => {
  const p = wire.payload;
  const token = hexToBytes(p.sender_token);
  const body = hexToBytes(p.body);
  assert.equal(bytesToHex(R.encapsulate(R.PREFIX_DATA, token, body)), p.padded);
  assert.deepEqual(R.unpad(hexToBytes(p.padded)), { prefix: R.PREFIX_DATA, senderToken: token, body });
});

test("relay messages match the reference", () => {
  const relay = wire.relay;
  const token = hexToBytes(relay.token);
  const challenge = hexToBytes(relay.challenge);
  const nonce = BigInt(relay.valid_nonce);
  const expected: Record<string, Uint8Array> = {
    register: R.encodeRegister(token, nonce, 7),
    forward: R.encodeForward(token, nonce, 9, pattern(40, 92)),
    keepalive: R.encodeKeepalive(token, nonce, 8),
    challenge: R.encodeChallenge(challenge, 1_900_000_000, 12),
    locate: R.encodeLocate(token, pattern32(93), nonce, 11),
    located_v4: R.encodeLocated(["203.0.113.5", 4433], ["198.51.100.9", 50000], 5),
    located_v6: R.encodeLocated(["2001:db8::1", 4433], null, 6),
    error: R.encodeError(1, 3, "no such token"),
    ack: R.encodeAck(9),
    delivered: R.encodeDelivered(9, pattern(40, 94)),
  };
  for (const m of relay.messages) {
    assert.equal(bytesToHex(expected[m.name]), m.bytes, m.name);
  }
});

test("relay bodies decode back to their fields", () => {
  const relay = wire.relay;
  const messages = new Map<string, Uint8Array>(relay.messages.map((m: { name: string; bytes: string }) => [m.name, hexToBytes(m.bytes)]));
  const challengeSplit = R.split(messages.get("challenge")!);
  assert.equal(challengeSplit?.tag, R.Tag.CHALLENGE);
  const challenge = R.decodeChallenge(challengeSplit!.body);
  assert.equal(bytesToHex(challenge.challenge), relay.challenge);
  assert.equal(challenge.difficulty, 12);

  const located6 = R.decodeLocated(R.split(messages.get("located_v6")!)!.body);
  assert.deepEqual(located6.selfAddr, ["2001:db8::1", 4433]);
  assert.equal(located6.peerAddr, null);

  const error = R.decodeError(R.split(messages.get("error")!)!.body);
  assert.equal(error.code, "TokenNotFound");
  assert.equal(error.seq, 3);

  const acked = R.decodeAckOrDelivered(R.split(messages.get("ack")!)!.body);
  assert.deepEqual(acked, { kind: "acked", senderSeq: 9 });

  const delivered = R.decodeAckOrDelivered(R.split(messages.get("delivered")!)!.body);
  assert.deepEqual(delivered, { kind: "delivered", senderSeq: 9, ciphertext: pattern(40, 94) });
});

test("proof of work matches the reference", () => {
  const relay = wire.relay;
  const challenge = hexToBytes(relay.challenge);
  const token = hexToBytes(relay.token);
  assert.equal(R.powOk(relay.difficulty, challenge, token, BigInt(relay.valid_nonce)), true);
  assert.equal(R.powOk(relay.difficulty, challenge, token, BigInt(relay.check_nonce)), relay.check_result);
  assert.equal(R.solvePow(relay.difficulty, challenge, token), BigInt(relay.valid_nonce));
});
