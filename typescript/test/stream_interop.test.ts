/**
 * Streams against the Rust reference: a stream opened by TypeScript is echoed back by the reference's multiplexer.
 *
 * The reference runs `interop_peer echo`: after the handshake and HELLO, every stream the peer opens for the service
 * `echo` is echoed back, using the reference's own `Mux`. Payloads larger than the 256 KiB window need WINDOW credit in
 * both directions, so this checks the window as well as the frames. Build the example and point
 * `TRANSFERD_INTEROP_PEER` at it, as in `interop.test.ts`. Without the variable the tests are skipped.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import net from "node:net";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { randomBytes } from "node:crypto"; // the library's helper is capped at 64 KiB per call; payloads here are larger
import { bytesToHex } from "../src/bytes.js";
import { HybridIdentity } from "../src/identity.js";
import { connect } from "../src/session.js";
import { StreamSession } from "../src/stream_session.js";
import { Link } from "../src/wire.js";

const PEER = process.env.TRANSFERD_INTEROP_PEER ?? "";
const SKIP: string | false = PEER !== "" && existsSync(PEER) ? false : "set TRANSFERD_INTEROP_PEER to the built interop_peer example";

const RUST_SEED = Uint8Array.from({ length: 64 }, (_, i) => i);
const TS_SEED = Uint8Array.from({ length: 64 }, (_, i) => (i * 13 + 1) & 0xff);

test("a stream opened by TypeScript is echoed by the Rust reference", { skip: SKIP, timeout: 120_000 }, async () => {
  const rust = new HybridIdentity(RUST_SEED, "rust");
  const ts = new HybridIdentity(TS_SEED, "ts");
  const child = spawn(PEER, ["echo", "0", bytesToHex(RUST_SEED)], { stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const exited = once(child, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  try {
    const listening = await lines.next();
    if (listening.done) {
      throw new Error(`the reference printed nothing: ${stderr}`);
    }
    const { listening: address } = JSON.parse(listening.value) as { listening: string };
    const port = Number(address.slice(address.lastIndexOf(":") + 1));

    const payload = new Uint8Array(randomBytes(600 * 1024)); // more than one window, so credit must come back both ways
    const socket = net.connect(port, "127.0.0.1");
    await once(socket, "connect");
    const session = await connect(new Link(socket), ts, { name: "ts", expectNodeId: rust.nodeId });
    const streams = new StreamSession(session, { nodeId: ts.nodeId, odd: false });
    streams.start();
    try {
      const sid = await streams.open("echo");
      const sent = streams.write(sid, payload, true);
      const parts: Uint8Array[] = [];
      for (;;) {
        const chunk = await streams.read(sid);
        if (chunk.length === 0) {
          break;
        }
        parts.push(chunk);
      }
      await sent;
      await streams.close(sid);
      assert.deepEqual(new Uint8Array(Buffer.concat(parts)), payload);
    } finally {
      streams.aclose();
      socket.end();
    }

    const summary = await lines.next();
    if (summary.done) {
      throw new Error(`the reference printed no summary: ${stderr}`);
    }
    assert.deepEqual(JSON.parse(summary.value), {
      role: "echo",
      peer: ts.nodeId,
      stream_bytes_in: payload.length,
      stream_bytes_out: payload.length,
      streams: 1,
    });
    const [code] = await exited;
    assert.equal(code, 0, stderr);
  } finally {
    if (child.exitCode === null) {
      child.kill();
    }
  }
});
