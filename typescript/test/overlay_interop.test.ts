/**
 * The overlay session against the reference's own session engine, in both directions.
 *
 * Mirrors `python/tests/test_overlay_interop.py`. `interop_peer overlay-echo` runs the node's session engine over TCP
 * and echoes every stream for `echo`: here TypeScript dials it, opens `echo`, sends 300 KiB and checks the echo. The
 * other direction runs `interop_peer overlay-stream`, which dials this test's listener, opens `echo`, sends 600 KiB,
 * and checks the echo, while TypeScript plays the echo side through its own session engine.
 *
 * Build the example and point `TRANSFERD_INTEROP_PEER` at it. Without the variable the tests are skipped.
 */

import assert from "node:assert/strict";
import { spawn as spawnProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { once } from "node:events";
import net from "node:net";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { handshakeInitiator, handshakeResponder } from "../src/handshake.js";
import { HybridIdentity } from "../src/identity.js";
import { TcpRoute } from "../src/link.js";
import { type OverlaySession, type SessionEvent, spawn } from "../src/overlay.js";
import { EventQueue } from "../src/queue.js";
import { Link as WireLink } from "../src/wire.js";

const PEER = process.env.TRANSFERD_INTEROP_PEER ?? "";
const SKIP = PEER === "" || !existsSync(PEER) ? "set TRANSFERD_INTEROP_PEER to the built interop_peer example" : false;

const RUST_SEED = Uint8Array.from({ length: 64 }, (_, i) => i);
const TS_SEED = Uint8Array.from({ length: 64 }, (_, i) => (i * 7 + 3) & 0xff);
const STREAM_BYTES = 600 * 1024;

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
}

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

async function readAll(session: OverlaySession, stream: number): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for (;;) {
    const chunk = await within(session.recv(stream), 60_000, "stream data");
    if (chunk === null) {
      return Buffer.concat(parts);
    }
    parts.push(chunk);
  }
}

test(
  "TypeScript dials the reference overlay and gets its echo",
  { skip: SKIP, timeout: 120_000 },
  async () => {
    const rust = new HybridIdentity(RUST_SEED, "rust");
    const ts = new HybridIdentity(TS_SEED, "typescript");
    const child = spawnProcess(PEER, ["overlay-echo", "0", hex(RUST_SEED)], { stdio: ["ignore", "pipe", "pipe"] });
    const lines = createInterface({ input: child.stdout });
    let socket: net.Socket | undefined;
    let route: TcpRoute | undefined;
    let session: OverlaySession | undefined;
    try {
      const [first] = await within(once(lines, "line"), 10_000, "the reference's listening line");
      const listening = JSON.parse(String(first)).listening as string;
      const colon = listening.lastIndexOf(":");
      socket = net.connect(Number(listening.slice(colon + 1)), listening.slice(0, colon));
      await within(once(socket, "connect"), 5000, "the connection");
      const link = new WireLink(socket);
      const result = await within(handshakeInitiator(link, ts, rust.nodeId), 10_000, "the handshake");
      route = new TcpRoute(1, link, result.keys, "direct", "tcp");
      route.start();
      session = spawn(
        { peerNodeId: rust.nodeId, peerName: "rust", identity: ts },
        [route],
        new EventQueue<SessionEvent>(),
      );
      assert.ok(await session.ready(10_000), "the reference answers our hello");
      const stream = await within(session.open("echo"), 10_000, "the open");
      const payload = randomBytes(300 * 1024);
      await session.send(stream, payload, true);
      assert.ok(sameBytes(await readAll(session, stream), payload), "every echoed byte matches");
    } finally {
      if (session !== undefined) {
        await session.shutdown();
      }
      route?.close();
      socket?.destroy();
      lines.close();
      child.kill();
    }
  },
);

test(
  "the reference overlay dials TypeScript and TypeScript echoes",
  { skip: SKIP, timeout: 180_000 },
  async () => {
    const rust = new HybridIdentity(RUST_SEED, "rust");
    const ts = new HybridIdentity(TS_SEED, "typescript");
    const echoed: { bytes?: number; service?: string } = {};
    const sessions: OverlaySession[] = [];
    const routes: TcpRoute[] = [];
    const sockets: net.Socket[] = [];

    async function echoOne(session: OverlaySession, stream: number, service: string): Promise<void> {
      let total = 0;
      for (;;) {
        const chunk = await session.recv(stream);
        if (chunk === null) {
          break;
        }
        total += chunk.length;
        await session.send(stream, chunk);
      }
      echoed.bytes = total;
      echoed.service = service;
      await session.send(stream, new Uint8Array(0), true);
    }

    async function serveOne(socket: net.Socket): Promise<void> {
      sockets.push(socket);
      const link = new WireLink(socket);
      const result = await handshakeResponder(link, ts);
      const route = new TcpRoute(1, link, result.keys, "direct", "tcp");
      route.start();
      routes.push(route);
      const events = new EventQueue<SessionEvent>();
      const session = spawn({ peerNodeId: rust.nodeId, peerName: "rust", identity: ts }, [route], events);
      sessions.push(session);
      for (;;) {
        const event = await events.next();
        if (event.kind === "open_request" && event.stream !== undefined && event.service !== undefined) {
          if (event.service !== "echo") {
            await session.authorize(event.stream, event.service, false, "no such service");
            continue;
          }
          await session.authorize(event.stream, event.service, true);
          void echoOne(session, event.stream, event.service);
        } else if (event.kind === "down" || event.kind === "refused") {
          return;
        }
      }
    }

    const server = net.createServer((socket) => {
      serveOne(socket).catch(() => undefined);
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const port = (server.address() as net.AddressInfo).port;
      const child = spawnProcess(
        PEER,
        ["overlay-stream", String(port), hex(RUST_SEED), ts.nodeId],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      let out = "";
      let err = "";
      child.stdout.on("data", (chunk: Buffer) => {
        out += chunk.toString();
      });
      child.stderr.on("data", (chunk: Buffer) => {
        err += chunk.toString();
      });
      const [code] = await within(once(child, "close") as Promise<[number | null]>, 180_000, "the reference run");
      assert.equal(code, 0, `the reference failed: ${err}`);
      const summary = JSON.parse(out.trim().split("\n").at(-1) ?? "{}");
      assert.deepEqual(summary, {
        role: "overlay_stream",
        peer: ts.nodeId,
        bytes: STREAM_BYTES,
        verified: true,
      });
      assert.deepEqual(echoed, { bytes: STREAM_BYTES, service: "echo" });
    } finally {
      for (const session of sessions) {
        await session.shutdown();
      }
      for (const route of routes) {
        route.close();
      }
      for (const socket of sockets) {
        socket.destroy();
      }
      server.close();
    }
  },
);
