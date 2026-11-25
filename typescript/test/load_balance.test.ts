/**
 * Load balancing across routes: a route is charged for the bytes it still has to clear, a frame that one route refuses
 * goes out on the next, and a control frame is not held up behind bulk data.
 *
 * Mirrors `crates/transferd-overlay/src/link.rs` (route cost, ranked routes) and `session.rs` (dispatch, flush).
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import net from "node:net";
import { test } from "node:test";
import { DATA, FLAG_BULK, Frame, VERSION_CURRENT, WINDOW } from "../src/frames.js";
import { HybridIdentity } from "../src/identity.js";
import {
  MemoryRoute,
  Route,
  SEND_QUEUE,
  TcpRoute,
  rankedRoutes,
  routeCost,
  type RouteMetrics,
} from "../src/link.js";
import { type OverlaySession, type SessionEvent, type SessionSetup, spawn } from "../src/overlay.js";
import { EventQueue } from "../src/queue.js";
import { deriveLinkKeys } from "../src/tunnel.js";
import { Link as WireLink } from "../src/wire.js";

/** Rejects if `promise` has not settled within `ms` milliseconds. */
async function within<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${ms} ms: ${what}`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function setupFor(me: HybridIdentity, peer: HybridIdentity): SessionSetup {
  return { peerNodeId: peer.nodeId, peerName: peer.name, identity: me };
}

/** Waits for the next stream the peer asks to open, accepts it, and returns its id. */
async function nextOpen(session: OverlaySession, events: EventQueue<SessionEvent>): Promise<number> {
  for (;;) {
    const event = await within(events.next(), 10_000, "an open request");
    if (event.kind === "open_request" && event.stream !== undefined && event.service !== undefined) {
      await session.authorize(event.stream, event.service, true);
      return event.stream;
    }
  }
}

/** Reads a stream until its end. */
async function readAll(session: OverlaySession, stream: number): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for (;;) {
    const chunk = await within(session.recv(stream), 30_000, "stream data");
    if (chunk === null) {
      return Buffer.concat(parts);
    }
    parts.push(chunk);
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
}

/** A route that refuses every frame, as a route whose queue is full does. It counts the attempts. */
class RefusingRoute extends Route {
  attempts = 0;

  constructor(id: number) {
    super(id, "direct", "refusing");
  }

  send(_frame: Frame): boolean {
    this.attempts += 1;
    return false;
  }

  tryRecv(): Frame | undefined {
    return undefined;
  }
}

test("a route's cost charges its backlog in time, at its measured speed", () => {
  const busy: RouteMetrics = { rttMs: 10, loss: 0, mbps: 100, active: 1, outstandingBytes: 1_000_000, up: true };
  // 1 MB is 8 Mbit. At 100 Mbit/s that is 80 ms, on top of the 10 ms round trip.
  assert.ok(Math.abs(routeCost(busy) - 90) < 1e-9, `got ${routeCost(busy)}`);
  assert.equal(routeCost({ ...busy, active: 0, outstandingBytes: 0 }), 10);
});

test("the route with the smaller backlog ranks first", () => {
  const [busy] = MemoryRoute.pair("direct", 1, 1);
  const [idle] = MemoryRoute.pair("direct", 2, 2);
  busy.stats.recordRtt(10);
  idle.stats.recordRtt(10);
  busy.stats.recordDataOut(1_000_000);
  assert.deepEqual(rankedRoutes([busy, idle]).map((route) => route.id), [2, 1]);
});

test("a frame that one route refuses goes out on the next route", { timeout: 60_000 }, async () => {
  const desk = HybridIdentity.generate("desktop");
  const phone = HybridIdentity.generate("phone");
  const deskEvents = new EventQueue<SessionEvent>();
  const refusing = new RefusingRoute(1);
  const [working, phoneEnd] = MemoryRoute.pair("direct", 2, 2);
  const deskSession = spawn(setupFor(desk, phone), [refusing, working], deskEvents);
  const phoneSession = spawn(setupFor(phone, desk), [phoneEnd], new EventQueue<SessionEvent>());

  const upload = randomBytes(200 * 1024);
  const download = randomBytes(200 * 1024);
  const opening = phoneSession.open("cfs");
  const stream = await within(nextOpen(deskSession, deskEvents), 5000, "the open");
  assert.equal(await within(opening, 5000, "the open's answer"), stream);

  // The desk's replies (window updates, acknowledgements) try the refusing route first, every time.
  await phoneSession.send(stream, upload, true);
  assert.ok(sameBytes(await readAll(deskSession, stream), upload), "the desk gets every uploaded byte");

  // The desk's own data falls back the same way.
  await deskSession.send(stream, download, true);
  assert.ok(sameBytes(await readAll(phoneSession, stream), download), "the phone gets every downloaded byte");

  assert.ok(refusing.attempts > 0, "the refusing route was tried before the session fell back");
  await deskSession.shutdown();
  await phoneSession.shutdown();
});

test("a control frame is accepted while the bulk queue is full", { timeout: 30_000 }, async () => {
  const keys = deriveLinkKeys(randomBytes(32));
  const server = net.createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("the test server has no port");
  }
  // The server accepts and never reads, so the sender's socket backs up and its writer stops taking frames.
  const accepting = once(server, "connection");
  const client = net.connect(address.port, "127.0.0.1");
  await once(client, "connect");
  const [accepted] = await within(accepting, 5000, "the accepted connection");

  const sender = new TcpRoute(1, new WireLink(client), keys);
  sender.start();

  // Queue bulk frames synchronously, so the writer cannot drain any of them while they are added.
  const bulk = (seq: number): Frame => new Frame(VERSION_CURRENT, DATA, FLAG_BULK, seq, new Uint8Array(64 * 1024));
  let queued = 0;
  while (sender.send(bulk(queued))) {
    queued += 1;
  }
  assert.equal(queued, SEND_QUEUE, "the bulk queue holds SEND_QUEUE frames");
  assert.equal(sender.send(bulk(queued)), false, "a bulk frame is refused once the bulk queue is full");

  const control = new Frame(VERSION_CURRENT, WINDOW, 0, queued, new Uint8Array(0));
  assert.equal(sender.send(control), true, "a control frame is still accepted: it has its own queue");

  sender.close();
  client.destroy();
  accepted.destroy();
  server.close();
});
