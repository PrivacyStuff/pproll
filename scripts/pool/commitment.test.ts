import assert from "node:assert/strict";
import test from "node:test";
import { be32, limbs } from "./commitment.ts";

test("a field of 1 is the least significant limb", () => {
  const bytes = be32(1n);
  const [blind0, blind1, blind2, blind3] = limbs(bytes);
  assert.equal(blind0, 1n);
  assert.equal(blind1, 0n);
  assert.equal(blind2, 0n);
  assert.equal(blind3, 0n);
  const packed = (((blind3 << 64n) + blind2) << 64n) + (blind1 << 64n) + blind0;
  assert.equal(packed, 1n);
});

test("the high byte is the most significant limb", () => {
  const bytes = Buffer.alloc(32);
  bytes[0] = 1;
  const [blind0, blind1, blind2, blind3] = limbs(bytes);
  assert.equal(blind0, 0n);
  assert.equal(blind3, 1n << 56n);
});
