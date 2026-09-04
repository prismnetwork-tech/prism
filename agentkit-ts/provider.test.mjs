import assert from "node:assert/strict";
import test from "node:test";
import { PrismActionProvider } from "./provider.mjs";

class FakeAgent {
  constructor() {
    this.released = [];
    this.lastLease = null;
  }

  async balances() {
    return { address: "0x0000000000000000000000000000000000000001", usdg: "1250000", eth: "2000000000000000000" };
  }

  async offers() {
    return [{ gpu: { model: "NVIDIA L40S", vram_mib: 46068 }, rate_per_second: 222, trust_class: "open" }];
  }

  async lease(request) {
    this.lastLease = request;
    return { leaseId: 31, fundingHash: "0xabc" };
  }

  async run(lease, command) {
    return { code: 0, stdout: `${lease.leaseId}:${command}`, stderr: "" };
  }

  endLease(lease) {
    this.released.push(lease.leaseId);
  }
}

function actions(provider) {
  return Object.fromEntries(provider.getActions().map((action) => [action.name, action]));
}

test("every action is exposed with a schema", () => {
  const named = actions(new PrismActionProvider(new FakeAgent()));
  assert.deepEqual(Object.keys(named).sort(), [
    "prism_end_lease",
    "prism_lease_and_run",
    "prism_list_gpus",
    "prism_run",
    "prism_wallet",
  ]);
  for (const action of Object.values(named)) {
    assert.ok(action.schema, `${action.name} has no schema`);
    assert.equal(typeof action.invoke, "function");
  }
});

test("balances and offers read back in units an agent can act on", async () => {
  const named = actions(new PrismActionProvider(new FakeAgent()));
  assert.match(await named.prism_wallet.invoke({}), /1\.250000 USDG/);

  const listed = await named.prism_list_gpus.invoke({});
  assert.match(listed, /NVIDIA L40S/);
  assert.match(listed, /\$0\.80\/hr/);
  assert.match(listed, /open/);
});

test("a lease carries the cap and trust class the caller asked for", async () => {
  const agent = new FakeAgent();
  const named = actions(new PrismActionProvider(agent));
  const schema = named.prism_lease_and_run.schema;
  const args = schema.parse({ command: "nvidia-smi", maxUsdg: 0.25, minTrustClass: "isolated" });

  const output = await named.prism_lease_and_run.invoke(args);
  assert.match(output, /lease 31 funded onchain/);
  assert.equal(agent.lastLease.maxDeposit, 250_000);
  assert.equal(agent.lastLease.minTrustClass, "isolated");
  assert.equal(agent.lastLease.durationSeconds, 600);
});

test("follow-up commands and release only work on a lease this session opened", async () => {
  const agent = new FakeAgent();
  const named = actions(new PrismActionProvider(agent));

  assert.match(await named.prism_run.invoke({ leaseId: 31, command: "echo hi" }), /not open in this session/);
  await named.prism_lease_and_run.invoke(named.prism_lease_and_run.schema.parse({ command: "nvidia-smi" }));

  assert.match(await named.prism_run.invoke({ leaseId: 31, command: "echo hi" }), /31:echo hi/);
  assert.match(await named.prism_end_lease.invoke({ leaseId: 31 }), /^released lease 31/);
  assert.deepEqual(agent.released, [31]);
  assert.match(await named.prism_run.invoke({ leaseId: 31, command: "echo hi" }), /not open in this session/);
});
