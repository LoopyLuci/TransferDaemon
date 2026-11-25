import assert from "node:assert/strict";
import { test } from "node:test";
import { cost, FRAME_OVERHEAD, INITIAL_FRAMES, INITIAL_RTO, MAX_RTO, MIN_FRAMES, MSS, RouteCc } from "../src/cc.js";
import { MAX_FRAME } from "../src/mux.js";

const ms = (n: number): number => n / 1000;

test("the timeout starts at the old fixed value and follows the measured round trip", () => {
  const c = new RouteCc();
  assert.equal(c.rto(), INITIAL_RTO);
  for (let i = 0; i < 40; i += 1) c.onRtt(ms(80));
  const fast = c.rto();
  assert.ok(fast < ms(250), `an 80 ms path times out well under 400 ms: ${fast}`);
  for (let i = 0; i < 40; i += 1) c.onRtt(ms(600));
  assert.ok(c.rto() > ms(600), "a 600 ms path waits longer than its round trip");
});

test("each timeout doubles the wait until a measurement resets it", () => {
  const c = new RouteCc();
  c.onRtt(ms(100));
  const base = c.rto();
  c.backOff();
  assert.ok(Math.abs(c.rto() - base * 2) < 1e-12);
  for (let i = 0; i < 20; i += 1) c.backOff();
  assert.equal(c.rto(), MAX_RTO, "the backoff is capped");
  c.onRtt(ms(100));
  assert.ok(c.rto() < base * 2, "a measurement ends the backoff");
});

test("slow start doubles per round trip, then avoidance adds one frame", () => {
  const c = new RouteCc();
  const start = c.cwnd;
  assert.equal(start, INITIAL_FRAMES * MSS);
  c.setForTest({ inflight: start });
  c.onAcked(start, true);
  assert.equal(c.cwnd, start * 2, "a window acknowledged doubles the window");

  const now = 10;
  c.setForTest({ inflight: c.cwnd });
  c.onLost(MSS, now, now);
  const afterCut = c.cwnd;
  assert.equal(afterCut, Math.floor((start * 2 * 7) / 10), "cut to 0.7 of the window");
  c.setForTest({ inflight: afterCut });
  c.onAcked(afterCut, true);
  assert.equal(c.cwnd, afterCut + MSS, "one frame per window acknowledged");
});

test("losses from one window cut it once", () => {
  const c = new RouteCc();
  const t0 = 10;
  const now = t0 + 0.5;
  c.setForTest({ inflight: 5 * MSS });
  c.onLost(MSS, t0, now);
  const cut = c.cwnd;
  c.onLost(MSS, t0, now + 0.01);
  assert.equal(c.cwnd, cut, "the second loss was sent before the cut");
  c.onLost(MSS, now + 0.02, now + 0.6);
  assert.ok(c.cwnd < cut, "a loss of a frame sent after the cut cuts again");
  for (let i = 0; i < 30; i += 1) {
    c.onLost(MSS, now + 0.7, now + 0.8);
    c.setForTest({ lastCut: null });
  }
  assert.ok(c.cwnd >= MIN_FRAMES * MSS, "never below the floor");
});

test("an idle route does not grow its window", () => {
  const c = new RouteCc();
  const start = c.cwnd;
  c.setForTest({ inflight: MSS });
  c.onAcked(MSS, false);
  assert.equal(c.cwnd, start);
});

test("a route with nothing in flight always takes a frame", () => {
  const c = new RouteCc();
  c.setForTest({ window: MSS / 2 });
  assert.ok(c.hasRoom(MSS));
  c.setForTest({ inflight: 1 });
  assert.ok(!c.hasRoom(MSS));
});

test("pacing spreads a window over the round trip", () => {
  const c = new RouteCc();
  c.onRtt(ms(100));
  const now = 5;
  let waited: [number, number] | null = null;
  for (let i = 0; i < INITIAL_FRAMES; i += 1) {
    const at = c.paceWait(now);
    if (at !== null) {
      waited = [i, at];
      break;
    }
    c.onSent(MSS, MAX_FRAME, false, now);
  }
  assert.ok(waited !== null, "a window is not sent as one burst");
  const [i, at] = waited;
  assert.ok(i >= 1, "a first frame goes at once");
  assert.ok(at - now < ms(100), "and the wait is a fraction of a round trip");
});

test("the wire cost adds the overhead to the payload", () => {
  assert.equal(cost(100), 100 + FRAME_OVERHEAD);
  assert.equal(MSS, MAX_FRAME + FRAME_OVERHEAD);
});
