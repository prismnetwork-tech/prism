import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { PolicyError, authorised, decisionDigest, decisionFrom, describePolicy, readPolicy } from "./policy.mjs";

const POLICY = JSON.stringify({
  policy_id: "gpu-v1",
  allow: ["fine_tune", "benchmark"],
  require: ["needs_gpu"],
  minimums: { needs_gpu: 0.8 },
});

test("no policy: a decision is optional and an absent one is fine", () => {
  assert.equal(readPolicy(undefined), null);
  assert.equal(readPolicy("  "), null);
  assert.equal(decisionFrom(undefined, null), null);
  assert.deepEqual(describePolicy(null), { spend_policy: "none: leases need no stated reason" });
});

test("reads the policy from JSON or from a file path", () => {
  const inline = readPolicy(POLICY);
  assert.equal(inline.policyId, "gpu-v1");
  assert.deepEqual(inline.allow, ["fine_tune", "benchmark"]);
  const dir = mkdtempSync(join(tmpdir(), "prism-policy-"));
  const path = join(dir, "policy.json");
  writeFileSync(path, POLICY);
  assert.deepEqual(readPolicy(path), inline);
});

test("a malformed policy is an error, never a silent pass", () => {
  assert.throws(() => readPolicy("{not json"), PolicyError);
  assert.throws(() => readPolicy("{}"), /policy_id/);
  assert.throws(() => readPolicy('{"policy_id":"x","minimums":{"a":2}}'), /from 0 to 1/);
  assert.throws(() => readPolicy('{"policy_id":"x","allow":"fine_tune"}'), /list of names/);
  assert.throws(() => readPolicy("/nonexistent/policy.json"), /cannot read/);
});

test("under a policy, a lease with no decision is refused and says what the policy needs", () => {
  const policy = readPolicy(POLICY);
  assert.throws(() => decisionFrom(undefined, policy), (err) => {
    assert.match(err.message, /gpu-v1/);
    assert.match(err.message, /fine_tune, benchmark/);
    assert.match(err.message, /needs_gpu with confidence at least 0.8/);
    assert.match(err.message, /Nothing was quoted or funded/);
    return true;
  });
});

test("a decision that meets the policy passes and carries the policy id", () => {
  const policy = readPolicy(POLICY);
  const d = decisionFrom(
    { action: "fine_tune", source: "rule:test", answers: [{ name: "needs_gpu", value: true, confidence: 0.9 }] },
    policy,
  );
  assert.equal(d.policyId, "gpu-v1");
  authorised(policy, d);
  assert.match(decisionDigest(d), /^0x[0-9a-f]{64}$/);
});

test("a decision under the floor or outside the allowed actions is refused with every reason", () => {
  const policy = readPolicy(POLICY);
  const d = decisionFrom(
    { action: "mine_crypto", source: "model", answers: [{ name: "needs_gpu", value: true, confidence: 0.5 }] },
    policy,
  );
  assert.throws(() => authorised(policy, d), (err) => {
    assert.match(err.message, /mine_crypto/);
    assert.match(err.message, /under the 0.8 floor/);
    return true;
  });
});

test("builds the same decision the SDK would, so the lease reference is the SDK's", async () => {
  const sdk = await import("@prismnetwork/agent-sdk/decision");
  const input = { action: "fine_tune", source: "rule:test", answers: [{ name: "needs_gpu", value: true, confidence: 0.9 }] };
  const ours = decisionFrom(input, null);
  const theirs = sdk.decision({ ...input, answers: [sdk.answer("needs_gpu", true, 0.9)] });
  assert.equal(decisionDigest(ours), sdk.decisionDigest(theirs));
  const quote = "3f2b1a44-9c7e-4d21-8b55-0a1c2d3e4f56";
  assert.equal(sdk.leaseReference(quote, ours), sdk.leaseReference(quote, theirs));
  assert.notEqual(sdk.leaseReference(quote, ours), sdk.leaseReference(quote, null));
});
