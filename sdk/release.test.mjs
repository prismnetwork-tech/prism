// endLease releases the lease on the network, which is what stops the meter.
// Before this the call only deleted key material and an interactive lease
// billed for its whole window.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { PrismAgent } from "./prism.mjs";

const KEY = `0x${"11".repeat(32)}`;
const ESCROW = "0x0000000000000000000000000000000000000009";

function agent(status, body) {
  const prism = new PrismAgent({ privateKey: KEY, escrow: ESCROW, rpcUrl: "http://127.0.0.1:1", apiBase: "http://prism.test" });
  prism.session = "session";
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), method: init.method, body: init.body });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  };
  return { prism, calls };
}

const realFetch = globalThis.fetch;
test.afterEach(() => {
  globalThis.fetch = realFetch;
});

test("a release posts to the network and removes the key material", async () => {
  const { prism, calls } = agent(202, { lease_id: 7, state: "active", release: "queued" });
  const keyDir = mkdtempSync(join(tmpdir(), "prism-test-"));
  const out = await prism.endLease({ leaseId: 7, keyDir });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "POST");
  assert.match(calls[0].url, /\/api\/agent\/proxy\/leases\/7\/release$/);
  assert.equal(calls[0].body, undefined);
  assert.deepEqual(out, { lease_id: 7, state: "active", release: "queued" });
  assert.equal(existsSync(keyDir), false);
});

test("a lease already past active reads as already closed", async () => {
  const { prism } = agent(200, { lease_id: 7, state: "finalized", release: "already_closed" });
  const out = await prism.endLease({ leaseId: 7 });
  assert.equal(out.release, "already_closed");
});

test("a refused release never rejects and names the refusal", async () => {
  const { prism } = agent(409, { error: "lease_not_active" });
  const out = await prism.endLease({ leaseId: 7 });
  assert.equal(out.release, "failed");
  assert.match(out.error, /lease_not_active/);
});

test("a handle without a lease id makes no request", async () => {
  const { prism, calls } = agent(202, {});
  const out = await prism.endLease({ keyDir: undefined });
  assert.equal(out.release, "failed");
  assert.equal(calls.length, 0);
});
