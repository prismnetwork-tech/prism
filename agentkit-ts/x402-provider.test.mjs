import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { PrismX402ActionProvider, DEFAULT_API_BASE } from "./x402-provider.mjs";

const wallet = {
  toSigner: () => ({ address: "0x1111111111111111111111111111111111111111" }),
  readContract: async () => 0n,
};

const actions = (provider = new PrismX402ActionProvider()) =>
  Object.fromEntries(provider.getActions(wallet).map((a) => [a.name, a]));

function reply(status, body, settlement) {
  return {
    status,
    ok: status >= 200 && status < 300,
    text: async () => JSON.stringify(body),
    headers: {
      get: (name) =>
        name === "payment-response" && settlement
          ? Buffer.from(JSON.stringify(settlement)).toString("base64")
          : null,
    },
  };
}

describe("PrismX402ActionProvider", () => {
  const realFetch = globalThis.fetch;
  const stub = (impl) => {
    globalThis.fetch = impl;
  };
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  test("exposes the five actions", () => {
    assert.deepEqual(Object.keys(actions()), [
      "prism_get_models",
      "prism_run_inference",
      "prism_run_batch",
      "prism_run_gpu_command",
      "prism_get_gpu_job",
    ]);
  });

  test("supports EVM wallets only", () => {
    const provider = new PrismX402ActionProvider();
    assert.equal(provider.supportsNetwork({ protocolFamily: "evm" }), true);
    assert.equal(provider.supportsNetwork({ protocolFamily: "svm" }), false);
  });

  test("get_models reads the free endpoint", async () => {
    const models = { models: ["llama3.2:3b"], state: "warm" };
    stub(async (url) => {
      assert.equal(url, `${DEFAULT_API_BASE}/inference/v1/models`);
      return { ok: true, json: async () => models };
    });
    assert.deepEqual(JSON.parse(await actions().prism_get_models.invoke({})), models);
  });

  test("get_gpu_job polls with the bearer token", async () => {
    stub(async (url, init) => {
      assert.equal(url, `${DEFAULT_API_BASE}/x402/jobs/abc`);
      assert.equal(init.headers.authorization, "Bearer t0k");
      return reply(200, { status: "succeeded", stdout: "H100" });
    });
    const out = JSON.parse(
      await actions().prism_get_gpu_job.invoke({ jobId: "abc", token: "t0k" }),
    );
    assert.equal(out.status, "succeeded");
  });

  test("get_gpu_job reports an unknown job", async () => {
    stub(async () => reply(404, { error: "job_not_found" }));
    const out = await actions().prism_get_gpu_job.invoke({ jobId: "nope", token: "t0k" });
    assert.match(out, /answered 404/);
  });

  test("inference sends prompt, model and token cap", async () => {
    const settlement = { success: true, transaction: "0xabc" };
    let sent;
    // wrapFetchWithPayment hands fetch a single Request, not (url, init).
    stub(async (request) => {
      sent = { url: request.url, body: await request.json() };
      return reply(200, { model: "llama3.2:3b", response: "hi" }, settlement);
    });
    const out = JSON.parse(
      await actions().prism_run_inference.invoke({
        prompt: "say hi",
        model: "llama3.2:3b",
        maxTokens: 16,
      }),
    );
    assert.equal(sent.url, `${DEFAULT_API_BASE}/inference/v1/inference`);
    assert.deepEqual(sent.body, {
      prompt: "say hi",
      model: "llama3.2:3b",
      options: { num_predict: 16 },
    });
    assert.deepEqual(out.settlement, settlement);
  });

  test("inference omits model and options when not given", async () => {
    let sent;
    stub(async (request) => {
      sent = await request.json();
      return reply(200, { response: "hi" });
    });
    await actions().prism_run_inference.invoke({ prompt: "hi" });
    assert.deepEqual(sent, { prompt: "hi" });
  });

  test("a cold pool reports unbilled, not an error", async () => {
    stub(async () => reply(503, { error: "warming_up", detail: "leasing", retry_after_seconds: 300 }));
    const out = JSON.parse(await actions().prism_run_inference.invoke({ prompt: "hi" }));
    assert.deepEqual(out, { charged: false, retryAfterSeconds: 300, detail: "leasing" });
  });

  test("a non-JSON gateway page does not become a parse error", async () => {
    stub(async () => ({
      status: 502,
      ok: false,
      text: async () => "<html>bad gateway</html>",
      headers: { get: () => null },
    }));
    const out = await actions().prism_run_inference.invoke({ prompt: "hi" });
    assert.match(out, /bad gateway/);
  });

  test("batch sends every prompt in one call", async () => {
    let sent;
    stub(async (request) => {
      sent = { url: request.url, body: await request.json() };
      return reply(200, { count: 2, items: [] });
    });
    await actions().prism_run_batch.invoke({ prompts: ["a", "b"], maxTokens: 8 });
    assert.equal(sent.url, `${DEFAULT_API_BASE}/inference/v1/batch`);
    assert.deepEqual(sent.body, { prompts: ["a", "b"], options: { num_predict: 8 } });
  });

  test("gpu command queues and returns the job handle", async () => {
    const job = { job_id: "abc", status: "queued", token: "t0k" };
    stub(async (request) => {
      assert.equal(request.url, `${DEFAULT_API_BASE}/x402/run`);
      return reply(202, job);
    });
    const out = JSON.parse(await actions().prism_run_gpu_command.invoke({ command: "nvidia-smi" }));
    assert.equal(out.job_id, "abc");
  });

  test("the spend cap drops options priced above the ceiling", () => {
    const provider = new PrismX402ActionProvider({ maxPaymentUsdc: 0.01 });
    const policy = provider._spendCapForTest();
    assert.deepEqual(
      policy(2, [{ amount: "6096" }, { amount: "20000" }]).map((o) => o.amount),
      ["6096"],
    );
  });

  test("the cap defaults to 1 USDC and rejects unreadable amounts", () => {
    const policy = new PrismX402ActionProvider()._spendCapForTest();
    assert.deepEqual(
      policy(2, [{ amount: "999999" }, { amount: "1000001" }, { amount: "nope" }]).map(
        (o) => o.amount,
      ),
      ["999999"],
    );
  });

  test("a custom apiBase loses its trailing slash", async () => {
    let url;
    stub(async (u) => {
      url = u;
      return { ok: true, json: async () => ({}) };
    });
    const provider = new PrismX402ActionProvider({ apiBase: "https://example.test/" });
    await actions(provider).prism_get_models.invoke({});
    assert.equal(url, "https://example.test/inference/v1/models");
  });
});
