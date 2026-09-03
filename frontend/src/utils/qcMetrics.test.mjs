import assert from "node:assert/strict";
import test from "node:test";

import { boundedPercent } from "./qcMetrics.js";

test("boundedPercent treats a missing denominator as no data", () => {
  assert.equal(boundedPercent(0, 0), 0);
  assert.equal(boundedPercent(4, undefined), 0);
});

test("boundedPercent returns a finite percentage within display bounds", () => {
  assert.equal(boundedPercent(3, 4), 75);
  assert.equal(boundedPercent(6, 4), 100);
  assert.equal(boundedPercent(-1, 4), 0);
  assert.equal(Number.isFinite(boundedPercent(0, 0)), true);
});
