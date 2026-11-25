/**
 * The overlay session: routes, streams and failover, run on in-memory and TCP routes.
 *
 * Mirrors `python/tests/test_overlay.py`. The two restart tests are ported from the reference's `session.rs` tests.
 * The others cover what the reference engine promises: a stream's bytes arrive whole and in order over one route,
 * bulk data is striped across every route, a stream survives a route that stops delivering, a refused open reaches
 * the opener, and a session runs over real sockets after the handshake.
 */

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import net from "node:net";
import { test } from "node:test";
import { Closed, NoSuchService } from "../src/errors.js";
import { type Frame } from "../src/frames.js";
import { handshakeInitiator, handshakeResponder } from "../src/handshake.js";
import { HybridIdentity } from "../src/identity.js";
import { MemoryRoute, TcpRoute } from "../src/link.js";
import { type OverlaySession, type SessionEvent, type SessionSetup, spawn } from "../src/overlay.js";
import { EventQueue } from "../src/queue.js";
import { Link as WireLink } from "../src/wire.js";

/** A route that can stop delivering: once dead, its sends count as sent and never arrive. */
class Blackhole extends MemoryRoute {
  dead = false;

  override send(frame: Frame): boolean {
    if (this.dead) {
      this.stats.recordSent(frame.body.length);
      return true;
    }
    return super.send(frame);
  }
}

function blackholePair(linkId: number): [Blackhole, Blackhole] {
  const a = new Blackhole(linkId, "direct", "memory");
  const b = new Blackhole(linkId, "direct", "memory");
  MemoryRoute.join(a, b);
  return [a, b];
}

/** A pair of in-memory routes with the same id at both ends, as the reference's tests use. */
function pair(linkId: number): [MemoryRoute, MemoryRoute] {
  return MemoryRoute.pair("direct", linkId, linkId);
}

function setupFor(me: HybridIdentity, peer: HybridIdentity): SessionSetup {
  return { peerNodeId: peer.nodeId, peerName: peer.name, identity: me };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

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

/** The text of one chunk; an end of stream reads as the empty string. */
function text(chunk: Uint8Array | null): string {
  return chunk === null ? "" : Buffer.from(chunk).toString();
}

/** A desktop and a phone on one in-memory route, with a stream the phone opened and the desktop accepted. */
async function openStreamPair(linkId: number): Promise<{ desk: OverlaySession; phone: OverlaySession; stream: number }> {
  const deskId = HybridIdentity.generate("desktop");
  const phoneId = HybridIdentity.generate("phone");
  const deskEvents = new EventQueue<SessionEvent>();
  const [route, phoneEnd] = pair(linkId);
  const desk = spawn(setupFor(deskId, phoneId), [route], deskEvents);
  const phone = spawn(setupFor(phoneId, deskId), [phoneEnd], new EventQueue<SessionEvent>());
  const opening = phone.open("cfs");
  const stream = await within(nextOpen(desk, deskEvents), 5000, "the open");
  assert.equal(await within(opening, 5000, "the open's answer"), stream);
  return { desk, phone, stream };
}

// A session that ends while a read waits is an error to that read. Silence is not the end of a stream: nothing says
// the stream was complete, so the reader must not take it for a finished transfer.
test("a read waiting when the session ends fails rather than ending the stream", { timeout: 30_000 }, async () => {
  const { desk, phone, stream } = await openStreamPair(3);
  const waiting = desk.recv(stream).then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );
  await sleep(50);
  await desk.shutdown();
  const outcome = await within(waiting, 5000, "the waiting read");
  if (outcome.ok) {
    assert.fail(`the read ended the stream with ${outcome.value === null ? "its end" : "bytes"}`);
  }
  assert.ok(outcome.error instanceof Closed, `got ${String(outcome.error)}`);
  await phone.shutdown();
});

test("a read waiting when the peer closes the stream gets the end", { timeout: 30_000 }, async () => {
  const { desk, phone, stream } = await openStreamPair(4);
  const waiting = desk.recv(stream);
  await sleep(50);
  await phone.close(stream);
  assert.equal(await within(waiting, 5000, "the waiting read"), null);
  await desk.shutdown();
  await phone.shutdown();
});

test("a read waiting when we close the stream gets the end", { timeout: 30_000 }, async () => {
  const { desk, phone, stream } = await openStreamPair(5);
  const waiting = desk.recv(stream);
  await sleep(50);
  await desk.close(stream);
  assert.equal(await within(waiting, 5000, "the waiting read"), null);
  await desk.shutdown();
  await phone.shutdown();
});

test("a restarted peer is heard on the session it comes back to", { timeout: 60_000 }, async () => {
  const desk = HybridIdentity.generate("desktop");
  const phone = HybridIdentity.generate("phone");
  const deskEvents = new EventQueue<SessionEvent>();
  const [oldRoute, phoneOldEnd] = pair(1);
  const deskSession = spawn(setupFor(desk, phone), [oldRoute], deskEvents);

  // The first phone process opens a stream, and the desktop accepts it.
  const phoneFirst = spawn(setupFor(phone, desk), [phoneOldEnd], new EventQueue<SessionEvent>());
  const first = phoneFirst.open("cfs");
  const accepted = await within(nextOpen(deskSession, deskEvents), 5000, "the first open");
  assert.notEqual(accepted, undefined);
  await within(first, 5000, "the first open's answer");

  // The old process is gone, so its route carries nothing more. The desktop's session stays up and takes the
  // restarted phone on a new route.
  oldRoute.markDown();
  const [newRoute, phoneNewEnd] = pair(2);
  await deskSession.addRoute(newRoute);
  const phoneRestarted = spawn(setupFor(phone, desk), [phoneNewEnd], new EventQueue<SessionEvent>());
  const second = phoneRestarted.open("cfs");
  const heard = await within(nextOpen(deskSession, deskEvents), 5000, "the restarted peer's open");
  assert.notEqual(heard, undefined, "the desktop hears the restarted peer's open");
  await within(second, 5000, "the restarted peer's open answer");

  await deskSession.shutdown();
  await phoneFirst.shutdown();
  await phoneRestarted.shutdown();
});

test("a restarted peer's first stream delivers its bytes", { timeout: 60_000 }, async () => {
  const desk = HybridIdentity.generate("desktop");
  const phone = HybridIdentity.generate("phone");
  const deskEvents = new EventQueue<SessionEvent>();
  const [oldRoute, phoneOldEnd] = pair(1);
  const deskSession = spawn(setupFor(desk, phone), [oldRoute], deskEvents);

  const phoneFirst = spawn(setupFor(phone, desk), [phoneOldEnd], new EventQueue<SessionEvent>());
  const opening = phoneFirst.open("cfs");
  const firstStream = await within(nextOpen(deskSession, deskEvents), 5000, "the first open");
  assert.equal(await within(opening, 5000, "the first open's answer"), firstStream);
  await phoneFirst.send(firstStream, Buffer.from("first"));
  assert.equal(
    text(await within(deskSession.recv(firstStream), 5000, "the first bytes")),
    "first",
    "the desktop reads the first stream",
  );

  // The old process is gone. The desktop keeps its session and takes the restarted phone on a new route.
  await phoneFirst.shutdown();
  oldRoute.markDown();
  const [newRoute, phoneNewEnd] = pair(2);
  await deskSession.addRoute(newRoute);
  const phoneRestarted = spawn(setupFor(phone, desk), [phoneNewEnd], new EventQueue<SessionEvent>());
  const restartedOpening = phoneRestarted.open("cfs");
  const secondStream = await within(nextOpen(deskSession, deskEvents), 5000, "the restarted open");
  assert.equal(await within(restartedOpening, 5000, "the restarted open's answer"), secondStream);
  await phoneRestarted.send(secondStream, Buffer.from("second"));
  assert.equal(
    text(await within(deskSession.recv(secondStream), 5000, "the restarted bytes")),
    "second",
    "the desktop reads the restarted peer's bytes",
  );

  await deskSession.shutdown();
  await phoneRestarted.shutdown();
});

test("a stream carries its bytes whole and in order over one route", { timeout: 60_000 }, async () => {
  const desk = HybridIdentity.generate("desktop");
  const phone = HybridIdentity.generate("phone");
  const deskEvents = new EventQueue<SessionEvent>();
  const [a, b] = pair(1);
  const deskSession = spawn(setupFor(desk, phone), [a], deskEvents);
  const phoneSession = spawn(setupFor(phone, desk), [b], new EventQueue<SessionEvent>());

  const payload = randomBytes(300 * 1024);
  const opening = phoneSession.open("cfs");
  const stream = await within(nextOpen(deskSession, deskEvents), 5000, "the open");
  assert.equal(await within(opening, 5000, "the open's answer"), stream);
  await phoneSession.send(stream, payload, true);
  assert.ok(sameBytes(await readAll(deskSession, stream), payload), "every byte arrives whole and in order");

  await deskSession.shutdown();
  await phoneSession.shutdown();
});

test("bulk data is striped across every route", { timeout: 120_000 }, async () => {
  const desk = HybridIdentity.generate("desktop");
  const phone = HybridIdentity.generate("phone");
  const deskEvents = new EventQueue<SessionEvent>();
  const [a1, b1] = pair(1);
  const [a2, b2] = pair(2);
  const deskSession = spawn(setupFor(desk, phone), [a1, a2], deskEvents);
  const phoneSession = spawn(setupFor(phone, desk), [b1, b2], new EventQueue<SessionEvent>());

  const payload = randomBytes(2 * 1024 * 1024);
  const opening = phoneSession.open("bulk");
  const stream = await within(nextOpen(deskSession, deskEvents), 5000, "the open");
  assert.equal(await within(opening, 5000, "the open's answer"), stream);
  await phoneSession.send(stream, payload, true);
  assert.ok(sameBytes(await readAll(deskSession, stream), payload));
  assert.ok(b1.stats.framesSent() > 0 && b2.stats.framesSent() > 0, "both routes carried bulk frames");

  await deskSession.shutdown();
  await phoneSession.shutdown();
});

test("a stream survives a route that stops delivering", { timeout: 120_000 }, async () => {
  const desk = HybridIdentity.generate("desktop");
  const phone = HybridIdentity.generate("phone");
  const deskEvents = new EventQueue<SessionEvent>();
  const [goodA, goodB] = pair(2);
  const [dyingA, dyingB] = blackholePair(1);
  const deskSession = spawn(setupFor(desk, phone), [dyingA, goodA], deskEvents);
  const phoneSession = spawn(setupFor(phone, desk), [dyingB, goodB], new EventQueue<SessionEvent>());

  const payload = randomBytes(600 * 1024);
  const opening = phoneSession.open("cfs");
  const stream = await within(nextOpen(deskSession, deskEvents), 5000, "the open");
  assert.equal(await within(opening, 5000, "the open's answer"), stream);

  await phoneSession.send(stream, payload.subarray(0, 100 * 1024));
  await sleep(200);
  // The first route now swallows everything, in both directions, the way a dead path does.
  dyingA.dead = true;
  dyingB.dead = true;
  await phoneSession.send(stream, payload.subarray(100 * 1024), true);

  const received = await within(readAll(deskSession, stream), 60_000, "the stream to finish");
  assert.ok(sameBytes(received, payload), "every byte arrives, over the route that still works");

  await deskSession.shutdown();
  await phoneSession.shutdown();
});

test("routes are probed and stay up while they answer", { timeout: 30_000 }, async () => {
  const desk = HybridIdentity.generate("desktop");
  const phone = HybridIdentity.generate("phone");
  const [a, b] = pair(1);
  const deskSession = spawn(setupFor(desk, phone), [a], new EventQueue<SessionEvent>());
  const phoneSession = spawn(setupFor(phone, desk), [b], new EventQueue<SessionEvent>());
  assert.ok(await deskSession.ready(5000));
  await sleep(1300);
  const routes = deskSession.routes();
  assert.equal(routes.length, 1);
  assert.equal(routes[0]?.kind, "direct");
  assert.ok(routes[0]?.active, "a route that answers its probes stays up");
  assert.equal(deskSession.version(), phoneSession.version());
  assert.notEqual(deskSession.version(), 0);

  await deskSession.shutdown();
  await phoneSession.shutdown();
});

test("a refused open reaches the opener with its reason", { timeout: 30_000 }, async () => {
  const desk = HybridIdentity.generate("desktop");
  const phone = HybridIdentity.generate("phone");
  const deskEvents = new EventQueue<SessionEvent>();
  const [a, b] = pair(1);
  const deskSession = spawn(setupFor(desk, phone), [a], deskEvents);
  const phoneSession = spawn(setupFor(phone, desk), [b], new EventQueue<SessionEvent>());

  const opening = phoneSession.open("missing");
  for (;;) {
    const event = await within(deskEvents.next(), 5000, "the open request");
    if (event.kind === "open_request" && event.stream !== undefined && event.service !== undefined) {
      await deskSession.authorize(event.stream, event.service, false, "no such service");
      break;
    }
  }
  await assert.rejects(
    within(opening, 5000, "the refused open"),
    (error: unknown) => error instanceof NoSuchService && error.service === "missing",
  );

  await deskSession.shutdown();
  await phoneSession.shutdown();
});

test("a session runs over real sockets after the handshake", { timeout: 60_000 }, async () => {
  const desk = HybridIdentity.generate("desktop");
  const phone = HybridIdentity.generate("phone");
  let serverRoute: ((route: TcpRoute) => void) | undefined;
  const serverSide = new Promise<TcpRoute>((resolve) => {
    serverRoute = resolve;
  });
  const server = net.createServer((socket) => {
    const link = new WireLink(socket);
    void handshakeResponder(link, desk).then((result) => {
      const route = new TcpRoute(1, link, result.keys, "direct", "tcp");
      route.start();
      serverRoute?.(route);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port;
  const socket = net.connect(port, "127.0.0.1");
  const routes: TcpRoute[] = [];
  try {
    await once(socket, "connect");
    const link = new WireLink(socket);
    const result = await within(handshakeInitiator(link, phone, desk.nodeId), 5000, "the handshake");
    const client = new TcpRoute(1, link, result.keys, "direct", "tcp");
    client.start();
    routes.push(client);

    const deskEvents = new EventQueue<SessionEvent>();
    const serverRouteValue = await within(serverSide, 5000, "the server side of the handshake");
    routes.push(serverRouteValue);
    const deskSession = spawn(setupFor(desk, phone), [serverRouteValue], deskEvents);
    const phoneSession = spawn(setupFor(phone, desk), [client], new EventQueue<SessionEvent>());

    const payload = randomBytes(200 * 1024);
    const opening = phoneSession.open("cfs");
    const stream = await within(nextOpen(deskSession, deskEvents), 5000, "the open");
    assert.equal(await within(opening, 5000, "the open's answer"), stream);
    await phoneSession.send(stream, payload, true);
    assert.ok(sameBytes(await readAll(deskSession, stream), payload));

    await deskSession.shutdown();
    await phoneSession.shutdown();
  } finally {
    // The routes own the sockets, and shutdown does not close them: close them here so the process can end.
    for (const route of routes) {
      route.close();
    }
    socket.destroy();
    server.close();
  }
});
