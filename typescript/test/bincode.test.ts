import assert from "node:assert/strict";
import { test } from "node:test";
import { bytesToHex, concatBytes, hexToBytes } from "../src/bytes.js";
import { Reader, Writer } from "../src/bincode.js";
import { DecodeError } from "../src/errors.js";

test("integers are fixed width and little-endian", () => {
  const w = new Writer();
  w.u16(0x0102);
  w.u32(0x03040506);
  w.u64(0x0708090a0b0c0d0en);
  assert.equal(bytesToHex(w.getValue()), "0201" + "06050403" + "0e0d0c0b0a090807");
});

test("a string is a u64 length, then its UTF-8 bytes", () => {
  const w = new Writer();
  w.string("ab");
  assert.equal(bytesToHex(w.getValue()), "0200000000000000" + "6162");
});

test("an option is a tag byte, then the value", () => {
  const w = new Writer();
  w.option<number>(null, (ww, v) => ww.u8(v));
  w.option(5, (ww, v) => ww.u8(v));
  assert.equal(bytesToHex(w.getValue()), "00" + "01" + "05");
});

test("round trip, and trailing bytes are left unread", () => {
  const w = new Writer();
  w.u32(7);
  w.string("hi");
  const r = new Reader(concatBytes(w.getValue(), hexToBytes("ffff")));
  assert.equal(r.u32(), 7);
  assert.equal(r.string(), "hi");
  assert.equal(r.remaining(), 2);
});

test("a length past the end of the body is refused", () => {
  assert.throws(() => new Reader(hexToBytes("ffffffffffffffff00")).bytes(), DecodeError);
});

test("a bool byte other than zero or one is refused", () => {
  assert.throws(() => new Reader(Uint8Array.of(2)).boolean(), DecodeError);
});

test("an option tag other than zero or one is refused", () => {
  assert.throws(() => new Reader(Uint8Array.of(9)).option((r) => r.u8()), DecodeError);
});
