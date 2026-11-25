import assert from "node:assert/strict";
import { test } from "node:test";
import { CONTROL_WINDOW, ReplayWindow } from "../src/replay.js";

test("a sequence number is accepted once", () => {
  const w = new ReplayWindow();
  assert.equal(w.accept(0), true);
  assert.equal(w.accept(0), false);
  assert.equal(w.highestSeen, 0);
});

test("a gap inside the window fills in once", () => {
  const w = new ReplayWindow();
  assert.equal(w.accept(1), true);
  assert.equal(w.accept(5), true);
  assert.equal(w.accept(4), true, "a gap inside the window fills in");
  assert.equal(w.accept(5), false, "and is then a replay");
  assert.equal(w.accept(3), true);
  assert.equal(w.accept(3), false);
});

test("reordering inside the window is tolerated", () => {
  const w = new ReplayWindow();
  assert.equal(w.accept(10), true);
  assert.equal(w.accept(12), true);
  assert.equal(w.accept(11), true, "11 arrived late but inside the window");
  assert.equal(w.accept(9), true);
  for (const s of [12, 11, 10, 9]) {
    assert.equal(w.accept(s), false);
  }
});

test("the window is 4096 wide, as the spec says", () => {
  assert.equal(CONTROL_WINDOW, 4096);
  const w = new ReplayWindow(CONTROL_WINDOW);
  assert.equal(w.accept(0), true);
  assert.equal(w.accept(2000), true);
  assert.equal(w.accept(1000), true, "1000 is 1000 behind and was never seen");
  assert.equal(w.accept(1000), false);
  assert.equal(w.accept(0), false, "0 is still inside the window and was seen");
  assert.equal(w.accept(10_000), true);
  assert.equal(w.accept(2000), false, "outside the window: refused by age");
  assert.equal(w.accept(5000), false, "5000 is 5000 behind: outside the window");
  assert.equal(w.accept(6000), true, "6000 is 4000 behind: inside, and unseen");
  assert.equal(w.accept(6000), false);
});

test("a long run stays bounded and refuses the old", () => {
  const w = new ReplayWindow(64);
  for (let s = 0; s < 1000; s += 1) {
    assert.equal(w.accept(s), true);
  }
  assert.equal(w.accept(900), false, "more than a window behind the newest");
  assert.equal(w.accept(999), false);
});
