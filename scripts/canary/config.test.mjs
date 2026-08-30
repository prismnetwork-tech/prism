import assert from "node:assert/strict";
import test from "node:test";

import { fundedFailure, readCanaryConfig, reviewQuote, selectManagedOffer } from "./config.mjs";

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

test("binds the reviewed quote to the exact capped request", () => {
  const request = {
    image: `registry.example/workspace@sha256:${"a".repeat(64)}`,
    durationSeconds: 600,
    minVramMib: 45000,
    preferredNodeId: null,
  };
  const quote = {
    quote_id: "01993aa4-5772-7f30-bcb7-7d38f59310e8",
    node_id: `0x${"ab".repeat(32)}`,
    image: request.image,
    duration_seconds: 600,
    min_vram_mib: 45000,
    rate_per_second: "222",
    maximum_escrow: "133200",
    trust_class: "open",
    command: null,
    repro: null,
    expires_at: "2030-01-01T00:10:00Z",
  };

  assert.deepEqual(reviewQuote(quote, request, 500000, Date.parse("2030-01-01T00:00:00Z")), {
    maximumEscrow: 133200n,
    rate: 222n,
    expiresAt: Date.parse("2030-01-01T00:10:00Z"),
  });
  assert.throws(() => reviewQuote({ ...quote, maximum_escrow: "133201" }, request, 500000, 0), /rate/);
  assert.throws(() => reviewQuote({ ...quote, image: "wrong" }, request, 500000, 0), /image/);
  assert.throws(() => reviewQuote(quote, request, 100000, 0), /cap/);
  assert.throws(
    () => reviewQuote({ ...quote, expires_at: "2030-01-01T00:00:30Z" }, request, 500000, Date.parse("2030-01-01T00:00:00Z")),
    /expires/,
  );
});

test("reports only valid funded-failure evidence", () => {
  const fundingHash = `0x${"ab".repeat(32)}`;
  assert.deepEqual(fundedFailure({ body: { funding_hash: fundingHash, lease_id: 42, key_path: "/tmp/key" } }), {
    fundingHash,
    leaseId: 42,
  });
  assert.deepEqual(fundedFailure({ body: { funding_hash: "invalid", lease_id: -1 } }), {
    fundingHash: null,
    leaseId: null,
  });
  assert.deepEqual(fundedFailure(null), { fundingHash: null, leaseId: null });
});

test("selects only live managed Vast capacity", () => {
  const node = (byte) => `0x${byte.repeat(64)}`;
  const offer = (id, managed, rate, vram = 49152) => ({
    node_id: id,
    managed_batch: managed,
    online: true,
    bonded: true,
    public_image_only: true,
    rate_per_second: rate,
    reliability_bps: 9900,
    gpu: { vram_mib: vram },
  });
  const managed = offer(node("b"), true, 222);
  const selected = selectManagedOffer([offer(node("a"), false, 1), managed], { minVramMib: 45000 });
  assert.equal(selected, managed);
  assert.equal(
    selectManagedOffer([managed, offer(node("c"), true, 333)], {
      minVramMib: 45000,
      preferredNodeId: node("c"),
    }).node_id,
    node("c"),
  );
  assert.throws(() => selectManagedOffer([offer(node("d"), true, 100, 24000)], { minVramMib: 45000 }), /managed Vast/);
});
