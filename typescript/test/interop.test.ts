/**
 * Interop with the Rust reference: its handshake and HELLO exchange, in both directions.
 *
 * These tests run the reference's `interop_peer` example. Build it, then point `TRANSFERD_INTEROP_PEER`
 * at the executable, for example:
 *
 *     cargo build -p transferd-overlay --example interop_peer
 *     TRANSFERD_INTEROP_PEER=H:/Projects/Transferd/target/debug/examples/interop_peer.exe npm test
 *
 * Without the variable the tests are skipped.
 */
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { bytesToHex } from "../src/bytes.js";
import { HybridIdentity } from "../src/identity.js";
import { accept, connect, type Session } from "../src/session.js";
import { Link } from "../src/wire.js";

const PEER = process.env.TRANSFERD_INTEROP_PEER ?? "";
const SKIP: string | false = PEER !== "" && existsSync(PEER) ? false : "set TRANSFERD_INTEROP_PEER to the built interop_peer example";

/** Seeds shared with the reference peer. Node ids are derived from the same seeds on both sides. */
const RUST_SEED = Uint8Array.from({ length: 64 }, (_, i) => i);
const RUST_DIAL_SEED = Uint8Array.from({ length: 64 }, (_, i) => (i * 11 + 5) & 0xff);
const TS_SEED = Uint8Array.from({ length: 64 }, (_, i) => (i * 13 + 1) & 0xff);

interface Peer {
  child: ChildProcess;
  lines: AsyncIterator<string>;
  exited: Promise<[number | null, NodeJS.Signals | null]>;
  stderr: () => string;
}

function spawnPeer(args: string[]): Peer {
  const child = spawn(PEER, args, { stdio: ["ignore", "pipe", "pipe"] });
  let err = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    err += chunk;
  });
  const rl = createInterface({ input: child.stdout });
  const exited = once(child, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
  return { child, lines: rl[Symbol.asyncIterator](), exited, stderr: () => err };
}

async function nextLine(peer: Peer): Promise<string> {
  const next = await peer.lines.next();
  if (next.done) {
    throw new Error(`the peer closed its output: ${peer.stderr()}`);
  }
  return next.value;
}

test("a TypeScript initiator and the Rust responder agree on the session", { skip: SKIP, timeout: 60_000 }, async () => {
  const rust = new HybridIdentity(RUST_SEED, "rust");
  const ts = new HybridIdentity(TS_SEED, "ts");
  const peer = spawnPeer(["serve", "0", bytesToHex(RUST_SEED)]);
  const { listening } = JSON.parse(await nextLine(peer)) as { listening: string };
  const port = Number(listening.slice(listening.lastIndexOf(":") + 1));

  const socket = net.connect(port, "127.0.0.1");
  await once(socket, "connect");
  const session = await connect(new Link(socket), ts, { name: "ts", expectNodeId: rust.nodeId }).finally(() =>
    socket.end(),
  );

  assert.equal(session.peerNodeId, rust.nodeId);
  assert.equal(session.version, 3);
  assert.equal(session.peerName, "interop-responder");
  assert.deepEqual(JSON.parse(await nextLine(peer)), {
    role: "responder",
    peer: ts.nodeId,
    peer_name: "ts",
    version: 3,
  });
  const [code] = await peer.exited;
  assert.equal(code, 0, peer.stderr());
});

test("the Rust initiator and a TypeScript responder agree on the session", { skip: SKIP, timeout: 60_000 }, async () => {
  const rust = new HybridIdentity(RUST_DIAL_SEED, "rust-dial");
  const ts = new HybridIdentity(TS_SEED, "ts");

  let resolveSession!: (session: Session) => void;
  let rejectSession!: (error: unknown) => void;
  const accepted = new Promise<Session>((resolve, reject) => {
    resolveSession = resolve;
    rejectSession = reject;
  });
  const server = net.createServer((socket) => {
    accept(new Link(socket), ts, { name: "ts" })
      .then(resolveSession, rejectSession)
      .finally(() => socket.end());
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;

  try {
    const peer = spawnPeer(["dial", String(port), bytesToHex(RUST_DIAL_SEED), ts.nodeId]);
    // If the peer exits before it connects, fail now rather than wait out the timeout.
    const session = await Promise.race([
      accepted,
      peer.exited.then(([code]) => {
        throw new Error(`the peer exited with ${code} before the session opened: ${peer.stderr()}`);
      }),
    ]);

    assert.equal(session.peerNodeId, rust.nodeId);
    assert.equal(session.version, 3);
    assert.equal(session.peerName, "interop-initiator");
    assert.deepEqual(JSON.parse(await nextLine(peer)), {
      role: "initiator",
      peer: ts.nodeId,
      peer_name: "ts",
      version: 3,
    });
    const [code] = await peer.exited;
    assert.equal(code, 0, peer.stderr());
  } finally {
    server.close();
  }
});
