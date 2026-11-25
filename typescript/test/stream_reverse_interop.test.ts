/**
 * Streams the other way round: the Rust reference opens a stream, and TypeScript echoes it back.
 *
 * `stream_interop.test.ts` has TypeScript open the stream to the reference's echo. Here the reference's
 * `interop_peer stream` dials this test's listener, opens a stream for the service `echo`, sends 600 KiB and
 * checks every byte that comes back. TypeScript plays the echo side with `StreamSession` and accepts the stream
 * the way any responder would. The run ends at the reference's close, so this covers the accept path against the
 * reference's own opener, which the loopback tests cannot. Build the example and point `TRANSFERD_INTEROP_PEER`
 * at it. Without the variable the test is skipped.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import net from "node:net";
import { test } from "node:test";
import { bytesToHex } from "../src/bytes.js";
import { HybridIdentity } from "../src/identity.js";
import { accept } from "../src/session.js";
import { StreamSession } from "../src/stream_session.js";
import { Link } from "../src/wire.js";

const PEER = process.env.TRANSFERD_INTEROP_PEER ?? "";
const SKIP: string | false = PEER !== "" && existsSync(PEER) ? false : "set TRANSFERD_INTEROP_PEER to the built interop_peer example";

const RUST_SEED = Uint8Array.from({ length: 64 }, (_, i) => i);
const TS_SEED = Uint8Array.from({ length: 64 }, (_, i) => (i * 13 + 1) & 0xff);
const BYTES = 600 * 1024;

test("a stream opened by the Rust reference is echoed by TypeScript", { skip: SKIP, timeout: 180_000 }, async () => {
  const ts = new HybridIdentity(TS_SEED, "ts");
  const echoed = { service: "", bytes: 0 };
  let serverError: unknown = null;

  const serve = async (socket: net.Socket): Promise<void> => {
    try {
      const session = await accept(new Link(socket), ts, { name: "ts" });
      const streams = new StreamSession(session, { nodeId: ts.nodeId, odd: false });
      streams.start();
      try {
        const [sid, service] = await streams.nextRequest();
        echoed.service = service;
        if (service !== "echo") {
          await streams.refuse(sid, "no_such_service", `no service named ${service}`);
          return;
        }
        await streams.accept(sid);
        let total = 0;
        for (;;) {
          const chunk = await streams.read(sid);
          if (chunk.length === 0) {
            break;
          }
          total += chunk.length;
          await streams.write(sid, chunk);
        }
        await streams.write(sid, new Uint8Array(0), true);
        echoed.bytes = total;
        await streams.close(sid);
      } finally {
        streams.aclose();
      }
    } catch (error) {
      serverError = error;
    } finally {
      socket.end();
    }
  };

  const server = net.createServer((socket) => {
    void serve(socket);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = (server.address() as net.AddressInfo).port;

  const child = spawn(PEER, ["stream", String(port), bytesToHex(RUST_SEED), ts.nodeId], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const [code] = (await once(child, "exit")) as [number | null];
  server.close();

  assert.equal(serverError, null, `the echo side failed: ${String(serverError)}`);
  assert.equal(code, 0, `the reference failed: ${stderr}`);
  const summary = JSON.parse(stdout.trim().split("\n").at(-1) ?? "{}") as Record<string, unknown>;
  assert.deepEqual(summary, {
    role: "stream",
    peer: ts.nodeId,
    stream_bytes_out: BYTES,
    stream_bytes_in: BYTES,
    streams: 1,
  });
  assert.deepEqual(echoed, { service: "echo", bytes: BYTES });
});
