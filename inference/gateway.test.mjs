import assert from "node:assert/strict";
import { test } from "node:test";
import { recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { boundMessage, hashRequest } from "@prismnetwork/x402/codec";
import { createGateway, DEFAULT_PRICING, priceFor, SERVED_TTL_MS } from "./gateway.mjs";

// What a lease costs and what it produces. The rate is the network's, read off
// /v1/offers and confirmed by settled receipts (900s billed 199,800 micros).
// The throughputs are end-to-end tokens per second measured under ollama on a
// 273 GB/s workstation, which is slower than any card the network offers, so
// they are the pessimistic case for cost.
const LEASE_MICROS_PER_SECOND = 222;
const WARM_WINDOW_SECONDS = 1800;
const FLOOR_TOKENS_PER_SECOND = { "llama3.2:3b": 88.7, "llama3.1:8b": 43.4 };

// What an uncapped request costs, which is what the tests below pay.
const fullCap = (m) => String(DEFAULT_PRICING[m].base + DEFAULT_PRICING[m].perToken * 1024);

const TX = `0x${"ab".repeat(32)}`;
const payment = Buffer.from(JSON.stringify({ txHash: TX, signature: "0xsig" })).toString("base64");
const payer = privateKeyToAccount(`0x${"33".repeat(32)}`);

function fakeDeps(overrides = {}) {
  const calls = { leases: 0, pulls: [], generations: [], ended: [], tunnels: 0, closed: 0, slots: [] };
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
    spawnTunnel: async (_lease, slot) => {
      calls.tunnels += 1;
      calls.slots.push(slot);
      return { close: () => (calls.closed += 1) };
    },
    fetchOllama: async (slot, path, init) => {
      if (path === "/api/tags") return { ok: true, json: async () => ({ models: [] }) };
      calls.generations.push({ slot, ...JSON.parse(init.body) });
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

test("an unconfigured gateway quotes the shipped card, not a flat fee", () => {
  const deps = fakeDeps();
  const gateway = build(deps, { models: ["llama3.2:3b", "llama3.1:8b"] });
  const listing = gateway.models();
  assert.equal(listing.pricing["llama3.2:3b"].base_micros, 3000);
  assert.equal(listing.pricing["llama3.2:3b"].per_token_micros, 3);
  assert.equal(listing.pricing["llama3.2:3b"].full_cap_micros, String(3000 + 3 * 1024));
  assert.equal(listing.pricing["llama3.1:8b"].full_cap_micros, String(6000 + 6 * 1024));
  assert.equal(listing.price_micros, String(6000 + 6 * 1024));
});

test("a model with no measured card is priced as the largest one that was measured", () => {
  const listing = build(fakeDeps(), { models: ["qwen2.5:32b"] }).models();
  assert.deepEqual(
    { base: listing.pricing["qwen2.5:32b"].base_micros, perToken: listing.pricing["qwen2.5:32b"].per_token_micros },
    DEFAULT_PRICING["llama3.1:8b"],
  );
});

test("a configured base moves the card without erasing its per-token rates", () => {
  const listing = build(fakeDeps(), { models: ["llama3.2:3b"], priceMicros: 9_000n }).models();
  assert.equal(listing.pricing["llama3.2:3b"].base_micros, 9000);
  assert.equal(listing.pricing["llama3.2:3b"].per_token_micros, 3, "the measured rate survives a base override");

  const explicit = build(fakeDeps(), {
    models: ["llama3.2:3b"],
    priceMicros: 9_000n,
    pricing: { "llama3.2:3b": { base: 1, per_token: 2 } },
  }).models();
  assert.equal(explicit.pricing["llama3.2:3b"].base_micros, 1);
  assert.equal(explicit.pricing["llama3.2:3b"].per_token_micros, 2);
});

// The two assertions that keep the card honest. Both are about money, not
// shape, and both fail if someone trims a rate without redoing the arithmetic.
test("every per-token rate is above the lease seconds a token burns", () => {
  for (const [model, tokensPerSecond] of Object.entries(FLOOR_TOKENS_PER_SECOND)) {
    const marginal = LEASE_MICROS_PER_SECOND / tokensPerSecond;
    assert.ok(
      DEFAULT_PRICING[model].perToken > marginal,
      `${model} sells tokens at ${DEFAULT_PRICING[model].perToken} micros and burns ${marginal.toFixed(2)}`,
    );
  }
});

test("the base recovers a warm window inside the traffic one window can serve", () => {
  const window = LEASE_MICROS_PER_SECOND * WARM_WINDOW_SECONDS;
  for (const [model, { base, perToken }] of Object.entries(DEFAULT_PRICING)) {
    const calls = window / (base + perToken * 256);
    // A window holds far more than this, so break-even is a traffic level the
    // GPU can actually serve rather than an arithmetic one.
    assert.ok(calls < 150, `${model} needs ${Math.ceil(calls)} calls of 256 tokens to pay for its lease`);
  }
});

test("stats count served generations and revenue", async () => {
  const deps = fakeDeps();
  const gateway = build(deps);
  await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  const stats = gateway.stats();
  assert.equal(stats.generations, 1);
  assert.equal(stats.tokens_out, 7);
  assert.equal(stats.revenue_micros, fullCap("llama3.2:3b"));
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

test("a bought answer stops being collectable once its window closes", async () => {
  const deps = fakeDeps();
  const gateway = build(deps);
  assert.equal((await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment)).status, 200);
  deps.tick(SERVED_TTL_MS + 1);
  // The payment stays spent. What expires is the copy of the answer, so the
  // refusal is a refusal rather than a second generation on one payment.
  const late = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(late.status, 402);
  assert.equal(late.body.error, "payment_reused");
  assert.equal(deps.calls.generations.length, 1);
});

test("a failed generation does not consume the payment", async () => {
  const deps = fakeDeps({
    fetchOllama: async (_slot, path) => {
      if (path === "/api/tags") return { ok: true, json: async () => ({}) };
      return { ok: false, status: 500 };
    },
  });
  const gateway = build(deps);
  const first = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(first.status, 503);
  assert.match(first.body.retry, /nothing was charged/);

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
  // A GPU was leased and could not be used, which is this pool being down
  // rather than busy, and the status has to say so or the outage is invisible.
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(out.status, 503);
  assert.match(out.body.detail, /no space left/);
  assert.deepEqual(deps.calls.ended, [1]);

  // Retries inside the cooldown window must not fund another lease, and are
  // still answered with the fault that is holding the pool down.
  const retry = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(retry.status, 503);
  assert.match(retry.body.detail, /cooling down after model pull exit 1/);
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
  assert.equal(out.status, 429);
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
      authorization: {
        from: PAYER,
        to: BASE_PAY_TO,
        value: fullCap("llama3.2:3b"),
        validAfter: "1",
        validBefore: "2",
        nonce: NONCE,
      },
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
  assert.equal(v1[0].maxAmountRequired, fullCap("llama3.2:3b"));

  const offered = (await dual.handleInference({ model: "llama3.2:3b", prompt: "hi" }, undefined, 2)).body.accepts;
  assert.deepEqual(offered.map((a) => a.network), ["eip155:8453", "eip155:4663"]);
  assert.equal(offered[0].amount, fullCap("llama3.2:3b"));
  assert.equal(offered[0].payTo, BASE_PAY_TO);
  assert.equal(offered[0].extra.assetTransferMethod, "eip3009");
  // The domain the signer must use has to travel with the requirement.
  assert.equal(offered[0].extra.name, "USD Coin");

  const single = build(fakeDeps());
  const only = (await single.handleInference({ model: "llama3.2:3b", prompt: "hi" }, undefined, 2)).body.accepts;
  assert.deepEqual(only.map((a) => a.network), ["eip155:4663"]);
});

test("the Robinhood offer carries the EIP-712 domain a signer needs", async () => {
  const only = (
    await build(fakeDeps()).handleInference({ model: "llama3.2:3b", prompt: "hi" }, undefined, 2)
  ).body.accepts;
  const rh = only.find((a) => a.network === "eip155:4663");

  // A client that cannot see the domain either signs against a guess or, if it
  // is careful, refuses the offer. Both leave the rail unpayable, and the
  // symptom is a signature the token rejects rather than an error naming this.
  assert.equal(rh.extra.name, "Global Dollar");
  assert.equal(rh.extra.version, "1");
  assert.equal(rh.extra.assetTransferMethod, "eip3009");
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
    fetchOllama: async (_slot, path) => {
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

test("a settlement that broadcasts but cannot be read is neither revenue nor loss", async () => {
  const exact = fakeExact();
  exact.settle = async () => ({
    success: false,
    settled: null,
    errorReason: "settlement_unconfirmed",
    payer: PAYER,
    transaction: "0xbroadcast",
    network: "eip155:8453",
  });
  const gateway = build(fakeDeps(), { basePayTo: BASE_PAY_TO, exact });
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(out.status, 200);
  const s = gateway.stats();
  assert.equal(s.unconfirmed, 1);
  assert.equal(s.unsettled, 0, "an unread receipt is not a known loss");
  assert.equal(s.revenue_micros, "0", "nor is it known revenue");
});

test("a settle that throws still hands over the work already paid for", async () => {
  const exact = fakeExact();
  exact.settle = async () => {
    throw new Error("rpc exploded");
  };
  const gateway = build(fakeDeps(), { basePayTo: BASE_PAY_TO, exact });
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(out.status, 200, "the money may have moved and the generation exists");
  assert.equal(out.body.response, "hello");
  assert.equal(gateway.stats().unconfirmed, 1);
});

test("a payment quoted under v1 is accepted when it echoes the v1 network name", async () => {
  const deps = fakeDeps();
  const exact = fakeExact();
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact });
  // What a client that read the v1 402 sends back: the chain named, not CAIP-2.
  const v1Echo = Buffer.from(JSON.stringify({
    x402Version: 1,
    scheme: "exact",
    network: "base",
    payload: {
      signature: "0xsig",
      authorization: { from: PAYER, to: BASE_PAY_TO, value: "10000", validAfter: "1", validBefore: "2", nonce: NONCE },
    },
  })).toString("base64");
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, v1Echo, 1);
  assert.equal(out.status, 200);
  // And it is still checked against our own CAIP-2 requirement.
  assert.equal(exact.calls.requirements[0].network, "eip155:8453");
});

test("a cold box answers immediately with when to retry instead of holding the caller", async () => {
  let release;
  const deps = fakeDeps({
    agent: {
      ...fakeDeps().agent,
      // A lease that never lands, which is what a cold start looks like for the
      // minutes it takes to source a GPU and pull models.
      lease: () => new Promise((r) => { release = r; }),
    },
  });
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact: fakeExact(), readyWaitMs: 30, retryAfterMs: 300_000 });
  const started = Date.now();
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.ok(Date.now() - started < 2_000, "the caller must not wait on a GPU");
  assert.equal(out.status, 429);
  assert.equal(out.body.error, "warming_up");
  assert.equal(out.body.retry_after_seconds, 300);
  assert.equal(out.headers["retry-after"], "300");
  release?.({ leaseId: 1, access: {} });
});

test("a queue is not a fault: no GPU to run on answers 429, a GPU that fails answers 5xx", async () => {
  const cold = fakeDeps();
  cold.agent.lease = () => new Promise(() => {});
  const queued = await build(cold, { readyWaitMs: 30, retryAfterMs: 300_000 })
    .handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(queued.status, 429);
  assert.equal(queued.headers["retry-after"], "300");
  assert.equal(queued.body.state, "warming");
  // The fields a client reads off a cold answer are the fields it always read.
  assert.deepEqual(Object.keys(queued.body), ["error", "detail", "state", "retry_after_seconds", "retry"]);

  // A lease that never lands leaves the pool cooling down, which is still the
  // pool being unable to take work rather than anything having gone wrong here.
  const refused = fakeDeps();
  refused.agent.lease = async () => {
    refused.calls.leases += 1;
    throw new Error("prism 409: capacity_reserved");
  };
  const cooling = build(refused, { coldRetryAfterMs: 600_000 });
  await cooling.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  const out = await cooling.handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(out.status, 429);
  assert.equal(out.body.error, "inference_unavailable");
  assert.equal(out.body.retry_after_seconds, 600);

  const broken = fakeDeps({
    fetchOllama: async (_slot, path) =>
      path === "/api/tags" ? { ok: true, json: async () => ({ models: [] }) } : { ok: false, status: 500 },
  });
  const failed = await build(broken).handleInference({ model: "llama3.2:3b", prompt: "hi" }, payment);
  assert.equal(failed.status, 503, "a box that took the work and could not do it is a fault");
  assert.equal(failed.body.error, "inference_unavailable");
});

test("nothing is charged while warming, so the same authorization still works", async () => {
  let release;
  const base = fakeDeps();
  const deps = fakeDeps({ agent: { ...base.agent, lease: () => new Promise((r) => { release = r; }) } });
  const exact = fakeExact();
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact, readyWaitMs: 30 });
  const first = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(first.status, 429);
  assert.equal(exact.calls.settled, 0, "a warming box must not take money");

  // Same authorization again once the box is up: not a replay, because the
  // first attempt never consumed it.
  const warm = build(fakeDeps(), { basePayTo: BASE_PAY_TO, exact: fakeExact() });
  const second = await warm.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(second.status, 200);
  release?.({ leaseId: 1, access: {} });
});

test("a warm box still serves without waiting", async () => {
  const gateway = build(fakeDeps(), { basePayTo: BASE_PAY_TO, exact: fakeExact(), readyWaitMs: 30 });
  await gateway.ensureWarm();
  const out = await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(out.status, 200);
  assert.equal(out.body.response, "hello");
});

test("an unpaid request never leases a GPU, so nobody can spend our money for free", async () => {
  const deps = fakeDeps();
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact: fakeExact() });
  await gateway.handleInference({ model: "llama3.2:3b", prompt: "hi" }, undefined, 2);
  // And neither does one whose payment does not verify.
  await gateway.handleInference(
    { model: "llama3.2:3b", prompt: "hi" },
    authorization(),
    2,
  ).catch(() => {});
  const refused = build(deps, { basePayTo: BASE_PAY_TO, exact: fakeExact({ isValid: false }) });
  await refused.handleInference({ model: "llama3.2:3b", prompt: "hi" }, authorization(), 2);
  assert.equal(deps.calls.leases, 1, "only the one verified payment leased anything");
});

test("an unpaid probe is told the price, not that its body is wrong", async () => {
  const gateway = build(fakeDeps(), { basePayTo: BASE_PAY_TO, exact: fakeExact() });
  // What a discovery crawler sends: nothing.
  for (const body of [{}, undefined, { model: "nope" }, { model: "llama3.2:3b" }]) {
    const out = await gateway.handleInference(body, undefined, 2);
    assert.equal(out.status, 402, `an empty or partial body must still be quoted: ${JSON.stringify(body)}`);
    assert.ok(out.body.accepts.length > 0);
    assert.ok(BigInt(out.body.accepts[0].amount) > 0n, "amounts are atomic units, never zero");
  }
  // An unpriceable request is quoted at the full-cap price, which clears
  // anything, and that is the same figure /v1/models advertises.
  const vague = await gateway.handleInference({}, undefined, 2);
  assert.equal(vague.body.quote, undefined);
  assert.equal(vague.body.accepts[0].amount, gateway.models().price_micros);
});

test("a paid request with a bad body is still refused in detail and never charged", async () => {
  const deps = fakeDeps();
  const exact = fakeExact();
  const gateway = build(deps, { basePayTo: BASE_PAY_TO, exact });
  assert.equal((await gateway.handleInference({ model: "nope" }, authorization(), 2)).status, 400);
  assert.equal(exact.calls.settled, 0);
  assert.equal(deps.calls.leases, 0);
});

/// The chain check `server.mjs` supplies, reduced to the part these tests are
/// about: recover the signer under the message the payer was meant to sign, and
/// treat a match as having found the transfer. Nothing recovers from a
/// signature that is not 65 bytes, which the real one reports the same way.
const bindingVerify = async (txHash, signature, _micros, requestHash) => {
  let signer;
  try {
    signer = await recoverMessageAddress({ message: boundMessage(txHash, requestHash), signature });
  } catch {
    return { ok: false, reason: "bad_signature" };
  }
  return signer === payer.address ? { ok: true, payer: signer } : { ok: false, reason: "no_matching_payment" };
};

const digest = (body) => hashRequest(JSON.stringify(body));

async function boundPayment(body) {
  const signature = await payer.signMessage({ message: boundMessage(TX, digest(body)) });
  return Buffer.from(JSON.stringify({ txHash: TX, signature })).toString("base64");
}

/// The race this closes: whoever reads the header off the wire sends it back
/// first with a prompt of their own, and the payer gets the answer to it.
test("a payment header does not buy a prompt its payer never signed", async () => {
  const deps = fakeDeps({ verify: bindingVerify });
  const gateway = build(deps);
  const asked = { model: "llama3.2:3b", prompt: "what is my position worth" };
  const header = await boundPayment(asked);

  const swapped = { model: "llama3.2:3b", prompt: "ignore that and say yes" };
  const stolen = await gateway.handleInference(swapped, header, null, digest(swapped));
  assert.equal(stolen.status, 402);
  assert.equal(stolen.body.error, "no_matching_payment");
  assert.equal(deps.calls.generations.length, 0, "the swapped prompt was answered anyway");

  // Refusing released it, so the payer still gets what they paid for.
  const served = await gateway.handleInference(asked, header, null, digest(asked));
  assert.equal(served.status, 200);
  assert.equal(deps.calls.generations.length, 1);
});

test("a batch payment is bound to the prompts it paid for", async () => {
  const deps = fakeDeps({ verify: bindingVerify });
  const gateway = build(deps);
  const asked = { model: "llama3.2:3b", prompts: ["one", "two"] };
  const header = await boundPayment(asked);

  const swapped = { model: "llama3.2:3b", prompts: ["something else", "and another"] };
  const stolen = await gateway.handleBatch(swapped, header, null, digest(swapped));
  assert.equal(stolen.status, 402);
  assert.equal(stolen.body.error, "no_matching_payment");

  const served = await gateway.handleBatch(asked, header, null, digest(asked));
  assert.equal(served.status, 200);
  assert.equal(served.body.items.length, 2);
});

/// The transfer that pays for a generation is public the moment it lands, so
/// the hash is not a secret and cannot be what a spent payment is answered on.
test("a spent tx hash does not buy the answer for whoever read it off the chain", async () => {
  const deps = fakeDeps({ verify: bindingVerify });
  const gateway = build(deps);
  const asked = { model: "llama3.2:3b", prompt: "what is my position worth" };
  const header = await boundPayment(asked);
  assert.equal((await gateway.handleInference(asked, header, null, digest(asked))).status, 200);

  const forged = Buffer.from(JSON.stringify({ txHash: TX, signature: "0x" })).toString("base64");
  const theirs = { model: "llama3.2:3b", prompt: "whatever" };
  const stolen = await gateway.handleInference(theirs, forged, null, digest(theirs));
  assert.equal(stolen.status, 402);
  assert.equal(stolen.body.error, "bad_signature");

  // Nor by asking for the prompt that was paid for: the signature is still the
  // thing that decides, and this one recovers nobody.
  const guessed = await gateway.handleInference(asked, forged, null, digest(asked));
  assert.equal(guessed.status, 402);
  assert.equal(guessed.body.error, "bad_signature");

  // The payer's own retry is what the cache is for, and it still works.
  const again = await gateway.handleInference(asked, header, null, digest(asked));
  assert.equal(again.status, 200);
  assert.equal(again.body.replayed, true);
  assert.equal(deps.calls.generations.length, 1);
});

/// A payment buys one request. Signing a second one over the same transfer is
/// something only the payer can do, and it is still not something that hands
/// back the first request's answer.
test("a spent payment answers the request it bought and no other", async () => {
  const deps = fakeDeps({ verify: bindingVerify });
  const gateway = build(deps);
  const asked = { model: "llama3.2:3b", prompts: ["one", "two"] };
  assert.equal((await gateway.handleBatch(asked, await boundPayment(asked), null, digest(asked))).status, 200);

  const other = { model: "llama3.2:3b", prompts: ["three", "four"] };
  const resigned = await gateway.handleBatch(other, await boundPayment(other), null, digest(other));
  assert.equal(resigned.status, 402);
  assert.equal(resigned.body.error, "payment_reused");
  assert.equal(deps.calls.generations.length, 2, "the second request must not be served from the first");
});
