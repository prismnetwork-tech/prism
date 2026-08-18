import assert from "node:assert/strict";
import test from "node:test";

import { readCanaryConfig } from "./config.mjs";

test("uses capped defaults", () => {
  assert.deepEqual(readCanaryConfig({}), {
    duration: 600,
    maxUsdg: 0.5,
    minVram: 16000,
    node: null,
    image: null,
    capMicros: 500000,
  });
});

test("accepts values at the caps", () => {
  const node = `0x${"ab".repeat(32)}`;
  assert.deepEqual(
    readCanaryConfig({
      CANARY_DURATION: "3600",
      CANARY_MAX_USDG: "5",
      CANARY_MIN_VRAM: "24576",
      CANARY_NODE: node,
    }),
    {
      duration: 3600,
      maxUsdg: 5,
      minVram: 24576,
      node,
      image: null,
      capMicros: 5000000,
    },
  );
});

test("rejects invalid or unsafe values", () => {
  const cases = [
    [{ CANARY_DURATION: "0" }, /positive integer/],
    [{ CANARY_DURATION: "12.5" }, /positive integer/],
    [{ CANARY_DURATION: "3601" }, /capped at 1 hour/],
    [{ CANARY_MAX_USDG: "0" }, /positive number/],
    [{ CANARY_MAX_USDG: "0.0000001" }, /at least 0.000001/],
    [{ CANARY_MAX_USDG: "5.01" }, /capped at 5 USDG/],
    [{ CANARY_MIN_VRAM: "NaN" }, /positive integer/],
    [{ CANARY_NODE: "0x1234" }, /32-byte hex/],
  ];

  for (const [env, expected] of cases) {
    assert.throws(() => readCanaryConfig(env), expected);
  }
});

test("takes a digest-pinned image and refuses a floating tag", () => {
  const image = `registry.example/workspace@sha256:${"a".repeat(64)}`;
  assert.equal(readCanaryConfig({ CANARY_IMAGE: image }).image, image);
  assert.throws(
    () => readCanaryConfig({ CANARY_IMAGE: "registry.example/workspace:latest" }),
    { message: "CANARY_IMAGE must be pinned to a sha256 digest" },
  );
});
