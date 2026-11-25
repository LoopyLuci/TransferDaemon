/**
 * The relay path against the reference relay: handshakes, sessions and refusals over relayd.
 *
 * Mirrors `python/tests/test_relay_hub.py`. Build the relay, then point `TRANSFERD_RELAYD` at the executable. Without
 * the variable, or with a missing file, the tests are skipped. Each test starts its own relayd on a free UDP port, at a
 * low proof-of-work difficulty.
 */

import assert from "node:assert/strict";
import { type ChildProcess, spawn as spawnProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import dgram from "node:dgram";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { hexToBytes } from "../src/bytes.js";
import { HandshakeError, OverlayError, RelayRefused } from "../src/errors.js";
import { Frame, PING, VERSION_CURRENT } from "../src/frames.js";
import { GhostKey, Issuer } from "../src/ghostkey.js";
import { HybridIdentity, relayTokenFor } from "../src/identity.js";
import type { Route } from "../src/link.js";
import { type OverlaySession, type SessionEvent, spawn } from "../src/overlay.js";
import { addrText, derivePunchKeys } from "../src/punch.js";
import { EventQueue } from "../src/queue.js";
import type { SocketAddr } from "../src/relay.js";
import { RelayClient, type RelayAddress } from "../src/relay_client.js";
import { RelayHub } from "../src/relay_hub.js";
import { loadVectors } from "./helpers.js";

const RELAYD = process.env.TRANSFERD_RELAYD ?? "";
const skip = RELAYD === "" || !existsSync(RELAYD) ? "set TRANSFERD_RELAYD to the built relayd binary" : false;

const DESK_SEED = Uint8Array.from({ length: 64 }, (_, i) => (i * 5 + 9) & 0xff);
const PHONE_SEED = Uint8Array.from({ length: 64 }, (_, i) => (i * 3 + 17) & 0xff);
const DIFFICULTY = 12;

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

function freeUdpPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = dgram.createSocket("udp4");
    probe.once("error", reject);
    probe.bind(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

interface RunningRelay {
  addr: RelayAddress;
  stop: () => void;
}

/**
 * Starts relayd on a free port, and resolves once it reports that it is listening. `extraEnv` sets its configuration.
 *
 * The relay's per-address rate limit is raised: every node in these tests shares one address, so the default limit
 * (300 datagrams per 30 seconds) would throttle the tests rather than test the overlay. relayd's own tests cover the
 * limit.
 */
async function startRelay(extraEnv: Record<string, string> = {}): Promise<RunningRelay> {
  const port = await freeUdpPort();
  const child: ChildProcess = spawnProcess(RELAYD, [], {
    env: {
      ...process.env,
      RELAYD_BIND: `127.0.0.1:${port}`,
      RELAYD_DIFFICULTY: String(DIFFICULTY),
      RELAYD_RATE_PER_30S: "1000000",
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
  });
  try {
    await within(
      new Promise<void>((resolve, reject) => {
        child.stdout?.on("data", (chunk: Buffer) => {
          if (chunk.toString().includes("listening")) {
            resolve();
          }
        });
        child.once("exit", (code) => reject(new Error(`relayd exited with ${code}: ${stderr}`)));
        child.once("error", reject);
      }),
      15_000,
      "relayd to start listening",
    );
  } catch (error) {
    child.kill();
    throw error;
  }
  return { addr: { host: "127.0.0.1", port }, stop: () => child.kill() };
}

/** Echo one stream to its end, then end it. */
async function echo(session: OverlaySession, stream: number): Promise<void> {
  for (;;) {
    const chunk = await session.recv(stream);
    if (chunk === null) {
      break;
    }
    await session.send(stream, chunk);
  }
  await session.send(stream, new Uint8Array(0), true);
}

/** Answer the streams a peer opens: `echo` is echoed, anything else is refused. Returns once the session is down. */
async function serve(session: OverlaySession, events: EventQueue<SessionEvent>): Promise<void> {
  for (;;) {
    const event = await events.next();
    if (event.kind === "down" || event.kind === "refused") {
      return;
    }
    if (event.kind !== "open_request" || event.stream === undefined || event.service === undefined) {
      continue;
    }
    if (event.service === "echo") {
      await session.authorize(event.stream, event.service, true);
      // The session may end under the echo; that is its end, not an error to report.
      echo(session, event.stream).catch(() => undefined);
    } else {
      await session.authorize(event.stream, event.service, false, "no such service");
    }
  }
}

/** Reads a stream until its end. */
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

test("a session over the relay carries bytes both ways", { skip, timeout: 180_000 }, async () => {
  const relay = await startRelay();
  const desk = new HybridIdentity(DESK_SEED, "desk");
  const phone = new HybridIdentity(PHONE_SEED, "phone");
  const sessions: OverlaySession[] = [];
  const servers: Promise<void>[] = [];
  let markAdopted = (): void => undefined;
  const adopted = new Promise<void>((resolve) => {
    markAdopted = () => resolve();
  });
  const deskHub = new RelayHub(relay.addr, relayTokenFor(desk.nodeId), desk, {
    onAdopt: (link, peerId) => {
      const events = new EventQueue<SessionEvent>();
      const session = spawn({ peerNodeId: peerId, peerName: "phone", identity: desk }, [link], events);
      sessions.push(session);
      servers.push(serve(session, events));
      markAdopted();
    },
  });
  const phoneHub = new RelayHub(relay.addr, relayTokenFor(phone.nodeId), phone);
  let phoneSession: OverlaySession | null = null;
  try {
    await deskHub.start();
    await phoneHub.start();
    const { keys, peerHybridPublicKey } = await within(
      phoneHub.handshake(desk.nodeId, relayTokenFor(desk.nodeId)),
      30_000,
      "the relay handshake",
    );
    assert.deepEqual(peerHybridPublicKey, desk.publicKey, "the relay handshake yields the desk's own key");
    const link = phoneHub.link(relayTokenFor(desk.nodeId), keys);
    phoneSession = spawn(
      { peerNodeId: desk.nodeId, peerName: "desk", identity: phone },
      [link],
      new EventQueue<SessionEvent>(),
    );
    await within(adopted, 30_000, "the desk adopts the link");
    assert.ok(await phoneSession.ready(30_000), "the desk answers our hello over the relay");

    const payload = randomBytes(200 * 1024);
    const stream = await within(phoneSession.open("echo"), 30_000, "opening the echo stream");
    await phoneSession.send(stream, payload, true);
    const echoed = await readAll(phoneSession, stream);
    if (!Buffer.from(echoed).equals(payload)) {
      let firstDifference = Math.min(echoed.length, payload.length);
      for (let i = 0; i < Math.min(echoed.length, payload.length); i++) {
        if (echoed[i] !== payload[i]) {
          firstDifference = i;
          break;
        }
      }
      assert.fail(
        `the echo differs: sent ${payload.length} bytes, received ${echoed.length}, first difference at ${firstDifference}`,
      );
    }
  } finally {
    if (phoneSession !== null) {
      await phoneSession.shutdown();
    }
    for (const session of sessions) {
      await session.shutdown();
    }
    phoneHub.close();
    deskHub.close();
    relay.stop();
  }
});

test("a handshake that reaches another node is refused", { skip, timeout: 120_000 }, async () => {
  const relay = await startRelay();
  const desk = new HybridIdentity(DESK_SEED, "desk");
  const phone = new HybridIdentity(PHONE_SEED, "phone");
  const deskHub = new RelayHub(relay.addr, relayTokenFor(desk.nodeId), desk);
  const phoneHub = new RelayHub(relay.addr, relayTokenFor(phone.nodeId), phone);
  try {
    await deskHub.start();
    await phoneHub.start();
    // The token is the desk's, but the node we say we dialled is the phone: the answer names the desk.
    await assert.rejects(phoneHub.handshake(phone.nodeId, relayTokenFor(desk.nodeId)), HandshakeError);
  } finally {
    phoneHub.close();
    deskHub.close();
    relay.stop();
  }
});

test("a peer the node refuses gets no answer", { skip, timeout: 120_000 }, async () => {
  const relay = await startRelay();
  const desk = new HybridIdentity(DESK_SEED, "desk");
  const phone = new HybridIdentity(PHONE_SEED, "phone");
  let adoptions = 0;
  const deskHub = new RelayHub(relay.addr, relayTokenFor(desk.nodeId), desk, {
    admit: () => false,
    onAdopt: () => {
      adoptions += 1;
    },
  });
  const phoneHub = new RelayHub(relay.addr, relayTokenFor(phone.nodeId), phone, { handshakeTimeoutMs: 2_000 });
  try {
    await deskHub.start();
    await phoneHub.start();
    // A refused flight gets no answer, so the dialler's handshake times out rather than being told why.
    await assert.rejects(
      phoneHub.handshake(desk.nodeId, relayTokenFor(desk.nodeId)),
      (error: unknown) => error instanceof OverlayError && /did not answer/.test(error.message),
    );
    assert.equal(adoptions, 0, "the node never adopts a refused peer's link");
  } finally {
    phoneHub.close();
    deskHub.close();
    relay.stop();
  }
});

/** A candidate's `ip:port` text as an address (a node does this when a peer's candidates arrive). */
function asAddr(text: string): SocketAddr {
  const cut = text.lastIndexOf(":");
  return [text.slice(0, cut).replace(/^\[|\]$/g, ""), Number(text.slice(cut + 1))];
}

/** Waits for the next frame a route delivers, or fails. */
async function nextFrame(route: Route, ms = 5_000): Promise<Frame> {
  const deadline = Date.now() + ms;
  for (;;) {
    const frame = route.tryRecv();
    if (frame !== undefined) {
      return frame;
    }
    if (Date.now() > deadline) {
      throw new Error("no frame arrived over the punched route");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

test("a hole punch between two nodes on one relay opens a route", { skip, timeout: 120_000 }, async () => {
  const relay = await startRelay();
  const desk = new HybridIdentity(DESK_SEED, "desk");
  const phone = new HybridIdentity(PHONE_SEED, "phone");
  const deskHub = new RelayHub(relay.addr, relayTokenFor(desk.nodeId), desk);
  const phoneHub = new RelayHub(relay.addr, relayTokenFor(phone.nodeId), phone);
  try {
    await deskHub.start();
    await phoneHub.start();
    // Each side learns the other's candidates through the relay, as a node does before it punches.
    const deskCandidates = await deskHub.punchCandidates(relayTokenFor(phone.nodeId));
    const phoneCandidates = await phoneHub.punchCandidates(relayTokenFor(desk.nodeId));
    const ownAddr = deskHub.client.localAddr;
    assert.ok(ownAddr !== null, "the desk's socket has an address");
    assert.equal(deskCandidates[0]?.addr, addrText(ownAddr), "the relay sees the desk's socket");

    const keys = derivePunchKeys(11n, randomBytes(32), randomBytes(32));
    const deskRun = deskHub.punchBegin({
      id: 11n,
      initiator: true,
      keys,
      candidates: phoneCandidates.map((c) => asAddr(c.addr)),
      linkId: 21,
    });
    const phoneRun = phoneHub.punchBegin({
      id: 11n,
      initiator: false,
      keys,
      candidates: deskCandidates.map((c) => asAddr(c.addr)),
      linkId: 22,
    });
    const [deskLink, phoneLink] = await within(
      Promise.all([deskRun.finish(), phoneRun.finish()]),
      20_000,
      "the hole punch to open a route",
    );
    deskLink.send(new Frame(VERSION_CURRENT, PING, 0, 1, new TextEncoder().encode("punched hello")));
    assert.equal(Buffer.from((await nextFrame(phoneLink)).body).toString("utf8"), "punched hello");
  } finally {
    phoneHub.close();
    deskHub.close();
    relay.stop();
  }
});

/** A relayd that trusts only the reference issuer and requires a ghost key to register. */
async function startGhostRelay(): Promise<RunningRelay> {
  const issuerFile = join(mkdtempSync(join(tmpdir(), "transferd-ghost-")), "issuer.txt");
  writeFileSync(issuerFile, loadVectors("ghost.json").issuer.public_text, "utf8");
  return startRelay({ RELAYD_GHOST_ISSUERS: issuerFile, RELAYD_REQUIRE_GHOST: "1" });
}

test("a relay that requires a ghost key admits one its issuer vouched for", { skip, timeout: 60_000 }, async () => {
  const v = loadVectors("ghost.json");
  const relay = await startGhostRelay();
  const client = new RelayClient(relay.addr, 10_000);
  try {
    await client.open();
    const token = hexToBytes(v.registration.session_token);
    await assert.rejects(
      client.register(token),
      (error: unknown) => error instanceof RelayRefused && error.code === "GhostRequired",
      "a plain registration is refused",
    );
    const ghost = GhostKey.fromSecret(hexToBytes(v.ghost_secret));
    await client.registerGhost(token, hexToBytes(v.certificate.bincode), ghost);
  } finally {
    client.close();
    relay.stop();
  }
});

test("a relay refuses a certificate from an issuer it does not trust", { skip, timeout: 120_000 }, async () => {
  const v = loadVectors("ghost.json");
  const relay = await startGhostRelay();
  const client = new RelayClient(relay.addr, 10_000);
  try {
    await client.open();
    const other = Issuer.generate("someone else", "supporter", 2048);
    const me = GhostKey.generate();
    const { blinded, state } = me.blindRequest(other.info);
    const certificate = me.finish(other.info, state, other.signBlinded(blinded));
    await assert.rejects(
      client.registerGhost(hexToBytes(v.registration.session_token), certificate.encodeBincode(), me),
      (error: unknown) => error instanceof RelayRefused && error.code === "GhostRejected",
    );
  } finally {
    client.close();
    relay.stop();
  }
});
