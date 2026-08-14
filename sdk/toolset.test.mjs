import assert from "node:assert/strict";
import { test } from "node:test";
import { PrismError } from "./prism.mjs";
import { NO_WALLET, PrismToolset } from "./toolset.mjs";

function fakeAgent(overrides = {}) {
  return {
    leased: [],
    ran: [],
    ended: [],
    async balances() {
      return { address: "0x0000000000000000000000000000000000000001", usdg: "1250000", eth: "2000000000000000000" };
    },
    async offers() {
      return [
        { gpu: { model: "Test GPU", vram_mib: 24576 }, rate_per_second: 25, trust_class: "isolated" },
        { gpu: { model: "Cheap GPU", vram_mib: 49140 }, rate_per_second: 177, trust_class: "open", staker_only: true },
      ];
    },
    async lease(options) {
      this.leased.push(options);
      return {
        leaseId: 7,
        access: { ssh_host: "h", ssh_port: 22, expires_at: new Date(Date.now() + 60_000).toISOString() },
        keyPath: "/tmp/nope/key",
        keyDir: "/tmp/nope",
        fundingHash: "0x01",
      };
    },
    async run(lease, command) {
      this.ran.push(command);
      return { code: 0, stdout: `${lease.leaseId}:${command}`, stderr: "", timedOut: false };
    },
    endLease(lease) {
      this.ended.push(lease.leaseId);
    },
    ...overrides,
  };
}

test("an invalid command never reaches the paid path", async () => {
  const agent = fakeAgent();
  const toolset = new PrismToolset({ agent });
  assert.match(await toolset.leaseAndRun({ command: "" }), /command is required/);
  assert.match(await toolset.leaseAndRun({ command: "   " }), /command is required/);
  assert.match(await toolset.leaseAndRun({ command: "x".repeat(9000) }), /8 KiB/);
  assert.match(await toolset.leaseAndRun({ command: "ok", minTrustClass: "banana" }), /must be one of/);
  assert.equal(agent.leased.length, 0);
});

test("a valid lease funds once, runs, and caps the deposit", async () => {
  const agent = fakeAgent();
  const toolset = new PrismToolset({ agent });
  const out = await toolset.leaseAndRun({ command: "nvidia-smi", maxUsdg: 0.29 });
  assert.match(out, /lease 7 funded onchain \(tx 0x01\), exit 0/);
  assert.equal(agent.leased.length, 1);
  assert.equal(agent.leased[0].maxDeposit, 290_000);
});

test("a lease error becomes a sentence with the amounts in it", async () => {
  const agent = fakeAgent({
    async lease() {
      throw new PrismError(402, "cost_exceeds_max", { required: 500_000, max: 250_000 });
    },
  });
  const toolset = new PrismToolset({ agent });
  const out = await toolset.leaseAndRun({ command: "nvidia-smi" });
  assert.match(out, /0\.500000 USDG/);
  assert.match(out, /0\.250000 USDG/);
});

test("a run failure after funding hands back the lease instead of losing it", async () => {
  let calls = 0;
  const agent = fakeAgent({
    async run(lease, command) {
      calls += 1;
      if (calls === 1) throw new PrismError(400, "ssh_access_unavailable", { mode: "gateway" });
      return { code: 0, stdout: `${lease.leaseId}:${command}`, stderr: "", timedOut: false };
    },
  });
  const toolset = new PrismToolset({ agent });
  const out = await toolset.leaseAndRun({ command: "nvidia-smi" });
  assert.match(out, /Lease 7 is funded \(tx 0x01\)/);
  assert.match(out, /ssh_access_unavailable/);
  assert.match(await toolset.run(7, "echo again"), /7:echo again/);
});

test("without a wallet the money tools refuse and listing uses the public API", async () => {
  const toolset = new PrismToolset({ agent: null });
  assert.equal(await toolset.wallet(), NO_WALLET);
  assert.equal(await toolset.leaseAndRun({ command: "nvidia-smi" }), NO_WALLET);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    json: async () => [{ gpu: { model: "Public GPU", vram_mib: 1 }, rate_per_second: 25, trust_class: "open" }],
  });
  try {
    assert.match(await toolset.listGpus(), /Public GPU/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("listings mark staker-only capacity and empty results name the trust class", async () => {
  const agent = fakeAgent();
  const toolset = new PrismToolset({ agent });
  const rows = await toolset.listGpus();
  assert.match(rows, /Cheap GPU .* stakers only/);
  assert.match(rows, /0\.09 USDG\/hr/);
  const empty = new PrismToolset({ agent: fakeAgent({ async offers() { return []; } }) });
  assert.match(await empty.listGpus("attested"), /trust class 'attested'/);
});

test("lease ids coerce from strings and unknown ids read as such", async () => {
  const agent = fakeAgent();
  const toolset = new PrismToolset({ agent });
  await toolset.leaseAndRun({ command: "nvidia-smi" });
  assert.match(await toolset.run("7", "echo hi"), /7:echo hi/);
  assert.match(await toolset.run("seven", "echo hi"), /positive integer/);
  assert.match(toolset.endLease(99), /No active lease 99/);
  assert.match(toolset.endLease("7"), /released lease 7/);
  assert.deepEqual(agent.ended, [7]);
});

test("an expired lease is swept before the next lease call", async () => {
  let nextId = 0;
  const agent = fakeAgent({
    async lease(options) {
      this.leased.push(options);
      nextId += 1;
      const expiry = nextId === 1 ? Date.now() - 1_000 : Date.now() + 60_000;
      return {
        leaseId: nextId,
        access: { ssh_host: "h", ssh_port: 22, expires_at: new Date(expiry).toISOString() },
        keyPath: "/tmp/nope/key",
        keyDir: "/tmp/nope",
        fundingHash: `0x0${nextId}`,
      };
    },
  });
  const toolset = new PrismToolset({ agent });
  await toolset.leaseAndRun({ command: "nvidia-smi" });
  await toolset.leaseAndRun({ command: "nvidia-smi" });
  assert.deepEqual(agent.ended, [1]);
});
