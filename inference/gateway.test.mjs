import assert from "node:assert/strict";
import { test } from "node:test";
import { createGateway, priceFor } from "./gateway.mjs";

const TX = `0x${"ab".repeat(32)}`;
const payment = Buffer.from(JSON.stringify({ txHash: TX, signature: "0xsig" })).toString("base64");

function fakeDeps(overrides = {}) {
  const calls = { leases: 0, pulls: [], generations: [], ended: [], tunnels: 0, closed: 0 };
  let clock = 1_000_000;
  const deps = {
    calls,
    clock: () => clock,
    tick: (ms) => {
      clock += ms;
    },
    agent: {
      async lease() {
        calls.leases += 1;
        return {
          leaseId: calls.leases,
          keyPath: "/tmp/nope",
          access: { ssh_host: "h", ssh_port: 22, expires_at: new Date(clock + 1_800_000).toISOString() },
        };
      },
      async run(_lease, command) {
        calls.pulls.push(command);
        return { code: 0, stdout: "", stderr: "" };
      },
      endLease(lease) {
        calls.ended.push(lease.leaseId);
      },
    },
    spawnTunnel: async () => {
      calls.tunnels += 1;
      return { close: () => (calls.closed += 1) };
    },
    fetchOllama: async (path, init) => {
      if (path === "/api/tags") return { ok: true, json: async () => ({ models: [] }) };
      calls.generations.push(JSON.parse(init.body));
      return {
        ok: true,
        json: async () => ({ response: "hello", prompt_eval_count: 5, eval_count: 7, total_duration: 2e9 }),
      };
    },
    verify: async () => ({ ok: true, payer: "0x0000000000000000000000000000000000000001" }),
    log: () => {},
  };
  Object.assign(deps, overrides);
  return deps;
}

function build(deps, extra = {}) {
  return createGateway({
    agent: deps.agent,
    models: ["llama3.2:3b"],
    payTo: "0x0000000000000000000000000000000000000002",
    image: "img@sha256:" + "0".repeat(64),
    verify: deps.verify,
    spawnTunnel: deps.spawnTunnel,
    fetchOllama: deps.fetchOllama,
    log: deps.log,
    now: deps.clock,
    ...extra,
  });
}

test("a paid request warms the box once and serves through it", async () => {
  const deps = fakeDeps();
  const gateway = build(deps);
  const first = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(first.status, 200);
  assert.equal(first.body.response, "hello");
  assert.equal(first.body.usage.completion_tokens, 7);
  assert.equal(deps.calls.leases, 1);
  assert.match(deps.calls.pulls[0], /ollama pull llama3\.2:3b/);

  const second = await gateway.handleInference(
    { model: "llama3.2:3b", prompt: "again" },
    Buffer.from(JSON.stringify({ txHash: `0x${"cd".repeat(32)}`, signature: "0xsig" })).toString("base64"),
  );
  assert.equal(second.status, 200);
  assert.equal(deps.calls.leases, 1);
});

test("no payment answers 402 with a request-specific quote", async () => {
  const deps = fakeDeps();
  const gateway = build(deps);
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, undefined);
  assert.equal(out.status, 402);
  assert.equal(out.body.accepts[0].network, "eip155:4663");
  assert.equal(out.body.quote.output_cap, 1024);
  assert.equal(deps.calls.leases, 0);
});

test("prices scale with the model and the requested output cap", async () => {
  const pricing = {
    "llama3.2:3b": { base: 5000, per_token: 10 },
    "llama3.1:8b": { base: 10000, per_token: 25 },
  };
  const deps = fakeDeps();
  const verified = [];
  deps.verify = async (_tx, _sig, micros) => {
    verified.push(micros);
    return { ok: true, payer: "0x0000000000000000000000000000000000000001" };
  };
  const gateway = createGateway({
    agent: deps.agent,
    models: ["llama3.2:3b", "llama3.1:8b"],
    pricing,
    payTo: "0x0000000000000000000000000000000000000002",
    image: "img@sha256:" + "0".repeat(64),
    verify: deps.verify,
    spawnTunnel: deps.spawnTunnel,
    fetchOllama: deps.fetchOllama,
    log: deps.log,
    now: deps.clock,
  });

  const listing = gateway.models();
  assert.equal(listing.pricing["llama3.2:3b"].full_cap_micros, String(5000 + 10 * 1024));
  assert.equal(listing.price_micros, String(10000 + 25 * 1024));

  const quoted = await gateway.handleInference(
    { model: "llama3.1:8b", prompt: "hi", options: { num_predict: 100 } },
    undefined,
  );
  assert.equal(quoted.body.quote.price_micros, String(10000 + 25 * 100));

  await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi", options: { num_predict: 100 } }, payment);
  assert.deepEqual(verified, [BigInt(5000 + 10 * 100)]);
  assert.equal(priceFor(pricing, "llama3.2:3b", 0).cap, 1024);
});

test("stats count served generations and revenue", async () => {
  const deps = fakeDeps();
  const gateway = build(deps);
  await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  const stats = gateway.stats();
  assert.equal(stats.generations, 1);
  assert.equal(stats.tokens_out, 7);
  assert.equal(stats.revenue_micros, "10000");
  assert.equal(stats.leases_warmed, 1);
});

test("validation runs before payment and before any lease", async () => {
  const deps = fakeDeps();
  const gateway = build(deps);
  assert.equal((await gateway.handleInference({ model: "nope", prompt: "hi" }, payment)).status, 400);
  assert.equal((await gateway.handleInference({ model: "llama3.2:3b", prompt: "" }, payment)).status, 400);
  const big = { model: "llama3.2:3b", prompt: "x".repeat(40_000) };
  assert.equal((await gateway.handleInference(big, payment)).status, 413);
  assert.equal(deps.calls.leases, 0);
});

test("a replayed tx hash answers with the result it already bought", async () => {
  const deps = fakeDeps();
  const gateway = build(deps);
  assert.equal((await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment)).status, 200);
  const replay = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(replay.status, 200);
  assert.equal(replay.body.replayed, true);
  assert.equal(replay.body.response, "hello");
  assert.equal(deps.calls.generations.length, 1);
});

test("a failed generation does not consume the payment", async () => {
  const deps = fakeDeps({
    fetchOllama: async (path) => {
      if (path === "/api/tags") return { ok: true, json: async () => ({}) };
      return { ok: false, status: 500 };
    },
  });
  const gateway = build(deps);
  const first = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(first.status, 503);
  assert.match(first.body.retry, /not consumed/);

  // The same tx works on retry once the backend recovers.
  deps.fetchOllama = fakeDeps().fetchOllama;
  const retryGateway = build(deps);
  const retry = await retryGateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(retry.status, 200);
});

test("a failed warmup releases the lease and cools down instead of chain-leasing", async () => {
  const deps = fakeDeps();
  deps.agent.run = async () => ({ code: 1, stdout: "", stderr: "no space left" });
  const gateway = build(deps);
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(out.status, 503);
  assert.deepEqual(deps.calls.ended, [1]);

  // Retries inside the cooldown window must not fund another lease.
  const retry = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(retry.status, 503);
  assert.match(retry.body.detail, /cooling down/);
  assert.equal(deps.calls.leases, 1);

  // After the window, and with the fault fixed, warmup runs again.
  deps.agent.run = fakeDeps().agent.run;
  deps.tick(300_000);
  const ok = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(ok.status, 200);
  assert.equal(deps.calls.leases, 2);
});

test("a failed match resets to cold and cools down", async () => {
  const deps = fakeDeps();
  deps.agent.lease = async () => {
    deps.calls.leases += 1;
    throw new Error("prism 409: capacity_reserved");
  };
  const gateway = build(deps);
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(out.status, 503);
  assert.equal(gateway.state().phase, "cold");
  const retry = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.match(retry.body.detail, /cooling down/);
  assert.equal(deps.calls.leases, 1);
});

test("num_predict is capped", async () => {
  const deps = fakeDeps();
  const gateway = build(deps);
  await gateway.handleInference(
    { model: "llama3.2:3b", prompt: "hi", options: { num_predict: 999999 } },
    payment,
  );
  assert.equal(deps.calls.generations[0].options.num_predict, 1024);
});

test("maintain drains an idle box at renewal time and renews a busy one", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { idleMs: 300_000 });
  await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(gateway.state().phase, "warm");

  // Idle past the threshold as the lease nears expiry: let it lapse.
  deps.tick(1_750_000);
  await gateway.maintain();
  assert.equal(gateway.state().phase, "cold");
  assert.deepEqual(deps.calls.ended, [1]);

  // Warm again, stay busy, and cross into the renewal window: a fresh lease
  // replaces the old one.
  await gateway.handleInference(
    { model: "llama3.2:3b", prompt: "hi" },
    Buffer.from(JSON.stringify({ txHash: `0x${"ef".repeat(32)}`, signature: "0xsig" })).toString("base64"),
  );
  deps.tick(1_700_000);
  await gateway.handleInference(
    { model: "llama3.2:3b", prompt: "hi" },
    Buffer.from(JSON.stringify({ txHash: `0x${"12".repeat(32)}`, signature: "0xsig" })).toString("base64"),
  );
  await gateway.maintain();
  assert.equal(gateway.state().phase, "warm");
  assert.equal(deps.calls.leases, 3);
});

// The Base rail. `exact` stands in for the verifier so these pin the gateway's
// own ordering and bookkeeping rather than re-testing EIP-3009, which
// x402/exact-evm.test.mjs already covers.
const BASE_PAY_TO = "0xe67a61f8e2aC4057aa22e64306107E7120078447";
const PAYER = "0x1111111111111111111111111111111111111111";
const NONCE = `0x${"ab".repeat(32)}`;

function authorization(overrides = {}) {
  return Buffer.from(JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: "eip155:8453" },
    payload: {
      signature: "0xsig",
      authorization: { from: PAYER, to: BASE_PAY_TO, value: "10000", validAfter: "1", validBefore: "2", nonce: NONCE },
      ...overrides,
    },
  })).toString("base64");
}

function fakeExact({ isValid = true, settles = true } = {}) {
  const calls = { verified: 0, settled: 0, requirements: [] };
  return {
    calls,
    verify: async (_payload, requirements) => {
      calls.verified += 1;
      calls.requirements.push(requirements);
      return isValid ? { isValid: true, payer: PAYER } : { isValid: false, invalidReason: "insufficient_funds", payer: PAYER };
    },
    settle: async () => {
      calls.settled += 1;
      return settles
        ? { success: true, payer: PAYER, transaction: "0xdeadbeef", network: "eip155:8453" }
        : { success: false, errorReason: "invalid_transaction_state", payer: PAYER, transaction: "", network: "eip155:8453" };
    },
  };
}

test("both rails are offered when Base is configured, Robinhood alone when it is not", async () => {
  const deps = fakeDeps();
  const dual = build(deps, { basePayTo: BASE_PAY_TO, exact: fakeExact() });
  // v1 names Base by its ecosystem name and v2 by CAIP-2; both mean chain 8453.
  const v1 = (await dual.handleInference({ model: "llama3.2:3b", prompt: "hi" }, undefined, 1)).body.accepts;
  assert.deepEqual(v1.map((a) => a.network), ["base", "eip155:4663"]);
  assert.equal(v1[0].maxAmountRequired, "10000");

  const offered = (await dual.handleInference({ model: "llama3.2:3b", prompt: "hi" }, undefined, 2)).body.accepts;
  assert.deepEqual(offered.map((a) => a.network), ["eip155:8453", "eip155:4663"]);
  assert.equal(offered[0].amount, "10000");
  assert.equal(offered[0].payTo, BASE_PAY_TO);
  assert.equal(offered[0].extra.assetTransferMethod, "eip3009");
  // The domain the signer must use has to travel with the requirement.
  assert.equal(offered[0].extra.name, "USD Coin");

  const single = build(fakeDeps());
  const only = (await single.handleInference({ model: "llama3.2:3b", prompt: "hi" }, undefined, 2)).body.accepts;
  assert.deepEqual(only.map((a) => a.network), ["eip155:4663"]);
});

test("a Base authorization is settled only after a generation exists", async () => {
  const deps = fakeDeps();
  const exact = fakeExact();
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact });
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(out.status, 200);
  assert.equal(out.body.response, "hello");
  assert.equal(exact.calls.verified, 1);
  assert.equal(exact.calls.settled, 1);
  assert.equal(deps.calls.generations.length, 1);
  // v2 reports the settlement in a header.
  const receipt = JSON.parse(Buffer.from(out.headers["PAYMENT-RESPONSE"], "base64").toString());
  assert.equal(receipt.transaction, "0xdeadbeef");
});

test("a failed generation never broadcasts, so the payer keeps their money", async () => {
  const exact = fakeExact();
  const deps = fakeDeps({
    fetchOllama: async (path) => {
      if (path === "/api/tags") return { ok: true, json: async () => ({ models: [] }) };
      return { ok: false, status: 500 };
    },
  });
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact });
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(out.status, 503);
  assert.equal(exact.calls.verified, 1);
  assert.equal(exact.calls.settled, 0, "nothing may be broadcast when there is no generation to pay for");

  // And the authorization is free to use again.
  const retry = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.notEqual(retry.body.error, "payment_reused");
});

test("a settlement that fails after serving is counted rather than hidden", async () => {
  const deps = fakeDeps();
  const exact = fakeExact({ settles: false });
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact });
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(out.status, 200, "the work was done, so the caller still gets it");
  assert.equal(gateway.stats().unsettled, 1);
  assert.equal(gateway.stats().revenue_micros, "0", "an unsettled payment is not revenue");
});

test("an authorization is verified against our own requirement, not the client's copy", async () => {
  const deps = fakeDeps();
  const exact = fakeExact();
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact });
  await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  const used = exact.calls.requirements[0];
  assert.equal(used.payTo, BASE_PAY_TO);
  assert.equal(used.asset, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
  assert.equal(used.network, "eip155:8453");
});

test("the same authorization cannot be spent twice", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact: fakeExact() });
  const first = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(first.status, 200);
  const second = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(second.status, 200);
  assert.equal(second.body.replayed, true, "a replay returns what it paid for");
  assert.equal(deps.calls.generations.length, 1, "and does not generate again");
});

test("a Base payment is refused when no Base rail is configured", async () => {
  const gateway = build(fakeDeps());
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(out.status, 402);
  assert.equal(out.body.error, "invalid_scheme");
});

test("a refused authorization frees its key for a corrected retry", async () => {
  const deps = fakeDeps();
  const exact = fakeExact({ isValid: false });
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact });
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(out.status, 402);
  assert.equal(out.body.error, "insufficient_funds");
  assert.equal(deps.calls.generations.length, 0);

  const funded = build(deps, { basePayTo: BASE_PAY_TO, exact: fakeExact() });
  const retry = await funded.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(retry.status, 200);
});

test("the legacy tx-hash scheme keeps working alongside the new one", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact: fakeExact() });
  const legacy = Buffer.from(JSON.stringify({ txHash: `0x${"ef".repeat(32)}`, signature: "0xsig" })).toString("base64");
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, legacy);
  assert.equal(out.status, 200);
  assert.equal(out.body.response, "hello");
});

test("a v2 refusal carries the terms in the header, not only the body", async () => {
  const gateway = build(fakeDeps(), { basePayTo: BASE_PAY_TO, exact: fakeExact({ isValid: false }) });
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(out.status, 402);
  const decoded = JSON.parse(Buffer.from(out.headers["PAYMENT-REQUIRED"], "base64").toString());
  assert.equal(decoded.x402Version, 2);
  assert.equal(decoded.accepts[0].network, "eip155:8453");
  assert.equal(decoded.error, "insufficient_funds");
});

test("an unpaid v1 request gets no protocol headers, which is where v1 puts nothing", async () => {
  const gateway = build(fakeDeps(), { basePayTo: BASE_PAY_TO, exact: fakeExact() });
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, undefined, 1);
  assert.equal(out.status, 402);
  assert.deepEqual(out.headers, {});
  assert.equal(out.body.accepts[0].network, "base");
});
