import assert from "node:assert/strict";
import { test } from "node:test";
import { createGateway } from "./gateway.mjs";
import { verifyItem } from "./receipt.mjs";

const MODEL = "llama3.2:3b";
const tx = (byte) => `0x${byte.repeat(32)}`;
const pay = (byte = "ab") => Buffer.from(JSON.stringify({ txHash: tx(byte), signature: "0xsig" })).toString("base64");

function fakeDeps(overrides = {}) {
  const calls = { leases: 0, generations: [], ended: [], closed: 0 };
  let clock = 1_000_000;
  const deps = {
    calls,
    clock: () => clock,
    agent: {
      async lease() {
        calls.leases += 1;
        return {
          leaseId: 1000 + calls.leases,
          keyPath: "/tmp/nope",
          access: { ssh_host: "h", ssh_port: 22, expires_at: new Date(clock + 1_800_000).toISOString() },
        };
      },
      async run() {
        return { code: 0, stdout: "", stderr: "" };
      },
      endLease(lease) {
        calls.ended.push(lease.leaseId);
      },
    },
    spawnTunnel: async () => ({ close: () => (calls.closed += 1) }),
    fetchOllama: async (slot, path, init) => {
      if (path === "/api/tags") return { ok: true, json: async () => ({ models: [] }) };
      const body = JSON.parse(init.body);
      calls.generations.push({ slot, prompt: body.prompt });
      return {
        ok: true,
        json: async () => ({
          response: `answer to ${body.prompt}`,
          prompt_eval_count: 5,
          eval_count: 7,
          total_duration: 2e9,
        }),
      };
    },
    verify: async () => ({ ok: true, payer: "0x0000000000000000000000000000000000000001" }),
    log: () => {},
  };
  Object.assign(deps, overrides);
  return deps;
}

const build = (deps, extra = {}) =>
  createGateway({
    agent: deps.agent,
    models: [MODEL],
    pricing: { [MODEL]: { base: 5000, per_token: 10 } },
    payTo: "0x0000000000000000000000000000000000000002",
    image: "img@sha256:" + "0".repeat(64),
    verify: deps.verify,
    spawnTunnel: deps.spawnTunnel,
    fetchOllama: deps.fetchOllama,
    log: deps.log,
    now: deps.clock,
    ...extra,
  });

const prompts = (n) => Array.from({ length: n }, (_, i) => `prompt ${i}`);
const unit = (cap = 1024) => 5000 + 10 * cap;

test("an unpaid batch is quoted per prompt and leases nothing", async () => {
  const deps = fakeDeps();
  const gateway = build(deps);
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(4) }, undefined);
  assert.equal(out.status, 402);
  assert.equal(out.body.quote.price_micros, String(unit() * 4));
  assert.equal(out.body.quote.count, 4);
  assert.match(out.body.resource.url, /\/v1\/batch$/);
  assert.equal(deps.calls.leases, 0);
});

test("the quote follows the requested output cap, and that is what the payment must match", async () => {
  const deps = fakeDeps();
  const verified = [];
  deps.verify = async (_tx, _sig, micros) => {
    verified.push(micros);
    return { ok: true, payer: "0x0000000000000000000000000000000000000001" };
  };
  const gateway = build(deps);
  const quoted = await gateway.handleBatch({ model: MODEL, prompts: prompts(3), options: { num_predict: 100 } }, undefined);
  assert.equal(quoted.body.quote.price_micros, String(unit(100) * 3));

  await gateway.handleBatch({ model: MODEL, prompts: prompts(3), options: { num_predict: 100 } }, pay());
  assert.deepEqual(verified, [BigInt(unit(100) * 3)]);
});

test("every prompt in a paid batch comes back, in order, with its own answer", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { poolMax: 3, itemsPerBox: 2 });
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(6) }, pay());
  assert.equal(out.status, 200);
  assert.equal(out.body.count, 6);
  for (let i = 0; i < 6; i += 1) {
    assert.equal(out.body.items[i].index, i);
    assert.equal(out.body.items[i].response, `answer to prompt ${i}`);
  }
  assert.equal(out.body.usage.completion_tokens, 42);
  assert.equal(deps.calls.generations.length, 6);
});

test("a batch that needs more than one box spreads across the pool", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { poolMax: 3, itemsPerBox: 2 });
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(6) }, pay());
  assert.equal(out.status, 200);
  assert.equal(deps.calls.leases, 3);
  const slots = new Set(deps.calls.generations.map((g) => g.slot));
  assert.equal(slots.size, 3, "every warm box should have taken work");
  assert.equal(new Set(out.body.receipt.lease_ids).size, 3);
});

test("a batch small enough for one box never funds a second lease", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { poolMax: 4, itemsPerBox: 25 });
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(5) }, pay());
  assert.equal(out.status, 200);
  assert.equal(deps.calls.leases, 1);
  assert.deepEqual(out.body.receipt.lease_ids, [1001]);
});

test("the pool never grows past what the operator allows", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { poolMax: 2, itemsPerBox: 1 });
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(10) }, pay());
  assert.equal(out.status, 200);
  assert.equal(deps.calls.leases, 2);
  assert.equal(gateway.models().pool.max, 2);
});

test("each item proves its own place in the batch without the other prompts", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { poolMax: 2, itemsPerBox: 2 });
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(5) }, pay());
  const { receipt, items } = out.body;
  assert.equal(receipt.count, 5);
  assert.equal(receipt.algorithm, "rfc6962-sha256");
  assert.equal(receipt.paid_micros, String(unit() * 5));
  assert.equal(receipt.payer, "0x0000000000000000000000000000000000000001");
  for (const item of items) {
    assert.ok(verifyItem(item.commitment, item.merkle_proof, receipt.merkle_root), `item ${item.index}`);
    assert.ok(receipt.lease_ids.includes(item.lease_id));
  }
});

test("the receipt commits to the prompts and answers, so neither can be swapped afterwards", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { poolMax: 2, itemsPerBox: 2 });
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(4) }, pay());
  const { receipt, items } = out.body;
  const forged = { ...items[2].commitment, response: items[0].commitment.response };
  assert.equal(verifyItem(forged, items[2].merkle_proof, receipt.merkle_root), false);
});

test("a prompt that fails once is retried on whatever box is free next", async () => {
  const deps = fakeDeps();
  let failed = false;
  const inner = deps.fetchOllama;
  deps.fetchOllama = async (slot, path, init) => {
    if (path !== "/api/tags" && !failed) {
      failed = true;
      return { ok: false, status: 500 };
    }
    return inner(slot, path, init);
  };
  const gateway = build(deps, { poolMax: 2, itemsPerBox: 2 });
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(4) }, pay());
  assert.equal(out.status, 200);
  assert.equal(out.body.count, 4);
  assert.ok(out.body.items.every((item) => item.response.startsWith("answer to ")));
});

test("a batch that cannot finish charges nothing and leaves the payment usable", async () => {
  const deps = fakeDeps({
    fetchOllama: async (_slot, path) => {
      if (path === "/api/tags") return { ok: true, json: async () => ({ models: [] }) };
      return { ok: false, status: 500 };
    },
  });
  const gateway = build(deps, { poolMax: 2, itemsPerBox: 2 });
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(4) }, pay());
  assert.equal(out.status, 503);
  assert.equal(out.body.error, "batch_unavailable");
  assert.match(out.body.retry, /nothing was charged/);
  assert.equal(gateway.stats().batches, 0);

  const recovered = build(fakeDeps(), { poolMax: 2, itemsPerBox: 2 });
  assert.equal((await recovered.handleBatch({ model: MODEL, prompts: prompts(4) }, pay())).status, 200);
});

test("a batch is refused before payment when the request cannot be served", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { poolMax: 2, maxBatchItems: 4 });
  const refused = async (body) => (await gateway.handleBatch(body, pay())).status;
  assert.equal(await refused({ model: "nope", prompts: prompts(2) }), 400);
  assert.equal(await refused({ model: MODEL, prompts: [] }), 400);
  assert.equal(await refused({ model: MODEL, prompts: prompts(5) }), 400);
  assert.equal(await refused({ model: MODEL, prompts: ["ok", "  "] }), 400);
  assert.equal(await refused({ model: MODEL, prompts: ["ok", "x".repeat(40_000)] }), 413);
  assert.equal(deps.calls.leases, 0);
});

test("a replayed batch payment hands back the batch it already bought", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { poolMax: 2, itemsPerBox: 2 });
  const first = await gateway.handleBatch({ model: MODEL, prompts: prompts(3) }, pay());
  assert.equal(first.status, 200);
  const replay = await gateway.handleBatch({ model: MODEL, prompts: prompts(3) }, pay());
  assert.equal(replay.status, 200);
  assert.equal(replay.body.replayed, true);
  assert.equal(replay.body.receipt.merkle_root, first.body.receipt.merkle_root);
  assert.equal(deps.calls.generations.length, 3, "a replay must not run the prompts again");
});

test("stats and the pool view report what the batch actually used", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { poolMax: 2, itemsPerBox: 2 });
  await gateway.handleBatch({ model: MODEL, prompts: prompts(4) }, pay());
  const stats = gateway.stats();
  assert.equal(stats.batches, 1);
  assert.equal(stats.batch_items, 4);
  assert.equal(stats.generations, 4);
  assert.equal(stats.revenue_micros, String(unit() * 4));
  assert.equal(stats.pool.warm, 2);
  assert.equal(stats.pool.in_flight, 0);
  assert.equal(stats.pool.lease_ids.length, 2);
});

test("a cold gateway answers a batch with when to come back, and charges nothing", async () => {
  const deps = fakeDeps();
  deps.agent.lease = () => new Promise(() => {});
  const gateway = build(deps, { poolMax: 2, readyWaitMs: 30, retryAfterMs: 90_000 });
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(4) }, pay());
  assert.equal(out.status, 503);
  assert.equal(out.body.error, "warming_up");
  assert.equal(out.headers["retry-after"], "90");
});

test("renewal replaces every box that was busy, not just the first", async () => {
  const deps = fakeDeps();
  let clock = 1_000_000;
  deps.clock = () => clock;
  const gateway = build(deps, { poolMax: 2, itemsPerBox: 2, idleMs: 3_600_000 });
  await gateway.handleBatch({ model: MODEL, prompts: prompts(4) }, pay());
  assert.equal(deps.calls.leases, 2);

  clock += 1_740_000;
  await gateway.maintain();
  assert.equal(deps.calls.ended.length, 2, "both expiring leases are handed back");
  assert.equal(deps.calls.leases, 4, "and both are replaced");
  assert.equal(gateway.stats().pool.warm, 2);
});

test("a lease that expires unused is dropped rather than renewed", async () => {
  const deps = fakeDeps();
  let clock = 1_000_000;
  deps.clock = () => clock;
  const gateway = build(deps, { poolMax: 2, itemsPerBox: 2, idleMs: 1000 });
  await gateway.handleBatch({ model: MODEL, prompts: prompts(4) }, pay());
  clock += 1_750_000;
  await gateway.maintain();
  assert.equal(deps.calls.leases, 2, "nothing is released and nothing new is funded");
  assert.equal(gateway.stats().pool.warm, 0);
});

test("the whole batch survives the wire, and the receipt still verifies on the other side", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { poolMax: 2, itemsPerBox: 2 });
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(5) }, pay());
  // A BigInt anywhere in the body would throw here rather than at a caller.
  const wire = JSON.parse(JSON.stringify(out.body));
  assert.equal(wire.receipt.paid_micros, String(unit() * 5));
  for (const item of wire.items) {
    assert.ok(verifyItem(item.commitment, item.merkle_proof, wire.receipt.merkle_root));
  }
});

test("warming the pool ahead of the work is what makes a batch use all of it", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { poolMax: 3, itemsPerBox: 25 });
  await gateway.ensureWarm(3);
  assert.equal(deps.calls.leases, 3);
  assert.equal(gateway.stats().pool.warm, 3);

  // Small enough that the growth gate would never have leased a second box.
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(6) }, pay());
  assert.equal(out.status, 200);
  assert.equal(deps.calls.leases, 3, "an already-warm pool is used, not grown");
  assert.equal(new Set(deps.calls.generations.map((g) => g.slot)).size, 3);
  assert.equal(new Set(out.body.receipt.lease_ids).size, 3);
});

test("a chain fault is logged with the reason, not just its code", async () => {
  const deps = fakeDeps();
  const lines = [];
  deps.log = (line) => lines.push(line);
  deps.agent.lease = async () => {
    const err = new Error("prism 502: chain_error");
    err.body = { cause: "Nonce provided for the transaction is lower than the current nonce of the account." };
    throw err;
  };
  const gateway = build(deps, { poolMax: 2 });
  const out = await gateway.handleBatch({ model: MODEL, prompts: prompts(2) }, pay());
  assert.equal(out.status, 503);
  assert.match(lines.join("\n"), /chain_error: Nonce provided/);
});
