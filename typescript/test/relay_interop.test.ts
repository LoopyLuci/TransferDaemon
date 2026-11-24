/**
 * Interop with the reference relay: relayd, run as a UDP server, driven by the TypeScript client.
 *
 * Build the relay, then point `TRANSFERD_RELAYD` at the executable, for example:
 *
 *     cargo build -p relayd --bin relayd
 *     TRANSFERD_RELAYD=H:/Projects/Transferd/target/debug/relayd.exe npm test
 *
 * Without the variable the tests are skipped. Each test starts its own relayd on a free UDP port,
 * at a low proof-of-work difficulty so the client solves quickly.
 */
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import dgram from "node:dgram";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { utf8, utf8Decode } from "../src/bytes.js";
import { RelayRefused } from "../src/errors.js";
import { HybridIdentity, relayTokenFor } from "../src/identity.js";
import { PREFIX_DATA, encapsulate, unpad } from "../src/relay.js";
import { RelayClient, type RelayAddress } from "../src/relay_client.js";

const RELAYD = process.env.TRANSFERD_RELAYD ?? "";
const SKIP: string | false = RELAYD !== "" && existsSync(RELAYD) ? false : "set TRANSFERD_RELAYD to the built relayd binary";

const DIFFICULTY = 12;
const ALICE_SEED = Uint8Array.from({ length: 64 }, (_, i) => (i * 5 + 9) & 0xff);
const BOB_SEED = Uint8Array.from({ length: 64 }, (_, i) => (i * 3 + 17) & 0xff);

async function freeUdpPort(): Promise<number> {
  const probe = dgram.createSocket("udp4");
  await new Promise<void>((resolve, reject) => {
    probe.once("error", reject);
    probe.bind(0, "127.0.0.1", () => resolve());
  });
  const { port } = probe.address();
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

interface RunningRelay {
  address: RelayAddress;
  stop: () => Promise<void>;
}

async function startRelayd(): Promise<RunningRelay> {
  const port = await freeUdpPort();
  const child: ChildProcess = spawn(RELAYD, [], {
    env: { ...process.env, RELAYD_BIND: `127.0.0.1:${port}`, RELAYD_DIFFICULTY: String(DIFFICULTY) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk: string) => {
    stderr += chunk;
  });
  if (child.stdout === null) {
    throw new Error("relayd has no stdout");
  }
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  const first = await lines.next();
  if (first.done || !String(first.value).includes("listening")) {
    child.kill();
    throw new Error(`relayd did not start: ${stderr}`);
  }
  return {
    address: { host: "127.0.0.1", port },
    stop: async () => {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill();
        await once(child, "exit");
      }
    },
  };
}

function tokenFor(seed: Uint8Array, name: string): Uint8Array {
  return relayTokenFor(new HybridIdentity(seed, name).nodeId);
}

test("register, keepalive, forward, deliver and locate through relayd", { skip: SKIP, timeout: 60_000 }, async () => {
  const relay = await startRelayd();
  const alice = new RelayClient(relay.address);
  const bob = new RelayClient(relay.address);
  try {
    await alice.open();
    await bob.open();
    const aliceToken = tokenFor(ALICE_SEED, "alice");
    const bobToken = tokenFor(BOB_SEED, "bob");

    await bob.register(bobToken);
    await alice.register(aliceToken);
    await alice.keepalive(aliceToken);
    await alice.forward(bobToken, encapsulate(PREFIX_DATA, aliceToken, utf8("hello over the relay")));

    const delivered = await bob.delivered();
    const payload = unpad(delivered.ciphertext);
    assert.ok(payload !== null, "the delivered payload is padded as a relay payload");
    assert.equal(payload.prefix, PREFIX_DATA);
    assert.deepEqual(payload.senderToken, aliceToken);
    assert.equal(utf8Decode(payload.body), "hello over the relay");

    const located = await alice.locate(aliceToken, bobToken);
    assert.deepEqual(located.selfAddr, alice.localAddr);
    assert.deepEqual(located.peerAddr, bob.localAddr);
  } finally {
    alice.close();
    bob.close();
    await relay.stop();
  }
});

test("forwarding to an unregistered token is refused with TokenNotFound", { skip: SKIP, timeout: 60_000 }, async () => {
  const relay = await startRelayd();
  const client = new RelayClient(relay.address);
  try {
    await client.open();
    const nobody = Uint8Array.from({ length: 32 }, () => 7);
    await assert.rejects(
      client.forward(nobody, encapsulate(PREFIX_DATA, nobody, utf8("nobody is here"))),
      (error: unknown) => error instanceof RelayRefused && error.code === "TokenNotFound",
    );
  } finally {
    client.close();
    await relay.stop();
  }
});
