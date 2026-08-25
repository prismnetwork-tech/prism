import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createGateway,
  DEFAULT_CONFIDENTIAL_PRICING,
  MAX_CONFIDENTIAL_BODY_BYTES,
  MAX_PREDICT_TOKENS,
  priceFor,
} from "./gateway.mjs";

const MODEL = "phala/gemma-4-26b-a4b-uncensored";
const PAY_TO = "0x0000000000000000000000000000000000000002";
const PAYER = "0x0000000000000000000000000000000000000001";

const paymentFor = (hex) =>
  Buffer.from(JSON.stringify({ txHash: `0x${hex.repeat(32)}`, signature: "0xsig" })).toString("base64");
const PAYMENT = paymentFor("ab");

// Deliberately not what JSON.stringify would produce: odd spacing, a float that
// round-trips to a different literal, and keys out of order. If any of it
// survives the relay, the request bytes were never re-serialized.
const REQUEST = `{ "model":"${MODEL}" ,\n  "max_tokens": 64, "temperature": 1.0,\n  "messages":[{"role":"user","content":"hi"}] }`;
const RESPONSE =
  '{\n  "id": "chatcmpl-1",\n  "choices": [ { "index": 0, "message": { "role": "assistant", "content": "ok" } } ],\n' +
  '  "usage": { "prompt_tokens": 11, "completion_tokens": 4, "cost": 0.00012 }\n}\n';
// The upstream adds `cost` only when its control plane priced the route, so a
// response without one is a shape the relay has to handle.
const RESPONSE_NO_COST = RESPONSE.replace(', "cost": 0.00012', "");

// What the gateway must assume a REQUEST costs when the upstream stays silent:
// the shipped card over the 64-token cap the body asks for.
const CARD = DEFAULT_CONFIDENTIAL_PRICING[MODEL];
const MODELLED_USD = (CARD.base + CARD.perToken * 64) / 1e6;

function fakeUpstream(reply) {
  const calls = [];
  const answer =
    reply ??
    (() => new Response(Buffer.from(RESPONSE), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-receipt-id": "rcpt_1",
        "x-aci-version": "aci/1",
        "x-aci-keyset-digest": "sha256:abc",
      },
    }));
  return {
    calls,
    fetch: async (url, init = {}) => {
      calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ?? null });
      return answer(url, init);
    },
  };
}

function build({ upstream: replies, confidential, ...extra } = {}) {
  const upstream = fakeUpstream(replies);
  let clock = Date.parse("2026-08-25T09:00:00Z");
  const gateway = createGateway({
    agent: { lease: async () => ({}), run: async () => ({ code: 0 }), endLease() {} },
    models: ["llama3.2:3b"],
    payTo: PAY_TO,
    image: `img@sha256:${"0".repeat(64)}`,
    verify: async () => ({ ok: true, payer: PAYER }),
    spawnTunnel: async () => ({ close() {} }),
    fetchOllama: async () => ({ ok: true, json: async () => ({}) }),
    fetchUpstream: upstream.fetch,
    log: () => {},
    now: () => clock,
    confidential: confidential === null ? null : { key: "upstream-key", models: { [MODEL]: {} }, ...confidential },
    ...extra,
  });
  return { gateway, upstream, tick: (ms) => (clock += ms) };
}

const paid = (gateway, body = REQUEST, headers = {}, payment = PAYMENT) =>
  gateway.handleConfidential(Buffer.from(body), headers, payment, 2);

// What the upstream catalog charges, read off tee.redpill.ai/v1/models. A
// request is bounded by the body cap and by max_tokens, so these two figures
// are the whole of what one call can cost us.
const CATALOG_USD_PER_TOKEN = {
  [MODEL]: { prompt: 0.00000015, completion: 0.0000007 },
  "phala/qwen3.6-35b-a3b-uncensored": { prompt: 0.0000003, completion: 0.0000015 },
};
// Four bytes to a token is pessimistic for prose, which makes the input side of
// the estimate an upper bound rather than a guess.
const BYTES_PER_TOKEN = 4;

test("every confidential rate clears five times what the upstream charges at the caps", () => {
  for (const [model, card] of Object.entries(DEFAULT_CONFIDENTIAL_PRICING)) {
    const catalog = CATALOG_USD_PER_TOKEN[model];
    const worstUsd =
      (MAX_CONFIDENTIAL_BODY_BYTES / BYTES_PER_TOKEN) * catalog.prompt + MAX_PREDICT_TOKENS * catalog.completion;
    const charged = card.base + card.perToken * MAX_PREDICT_TOKENS;
    assert.ok(
      charged >= worstUsd * 1e6 * 5,
      `${model} charges ${charged} micros against a worst upstream cost of ${Math.ceil(worstUsd * 1e6)}`,
    );
  }
});

test("a confidential price is the base plus the per-token rate over the cap asked for", () => {
  const card = DEFAULT_CONFIDENTIAL_PRICING[MODEL];
  assert.equal(priceFor(DEFAULT_CONFIDENTIAL_PRICING, MODEL, 64).micros, BigInt(card.base + card.perToken * 64));
  assert.equal(priceFor(DEFAULT_CONFIDENTIAL_PRICING, MODEL, null).cap, MAX_PREDICT_TOKENS);

  const { gateway } = build({ confidential: { models: { [MODEL]: { base_micros: 4_000, per_token_micros: 7 } } } });
  const listed = gateway.models().confidential;
  assert.equal(listed.models[MODEL].base_micros, 4_000);
  assert.equal(listed.models[MODEL].per_token_micros, 7);
  assert.equal(listed.models[MODEL].full_cap_micros, String(4_000 + 7 * MAX_PREDICT_TOKENS));
  assert.equal(listed.price_micros, String(4_000 + 7 * MAX_PREDICT_TOKENS));
});

test("an unpaid confidential request is quoted on its own max_tokens", async () => {
  const { gateway } = build();
  const card = DEFAULT_CONFIDENTIAL_PRICING[MODEL];
  const out = await gateway.handleConfidential(Buffer.from(REQUEST), {}, undefined, 2);
  assert.equal(out.status, 402);
  assert.equal(out.body.quote.price_micros, String(card.base + card.perToken * 64));
  assert.equal(out.body.quote.output_cap, 64);
  assert.match(out.body.resource.url, /\/v1\/chat\/completions$/);

  // A discovery probe carries nothing and still gets a payable price.
  const probe = await gateway.handleConfidential(null, {}, undefined, 2);
  assert.equal(probe.status, 402);
  assert.equal(probe.body.accepts[0].amount, gateway.models().confidential.price_micros);
});

test("/v1/models advertises the class as facts a caller can act on", () => {
  const { gateway } = build();
  const listed = gateway.models().confidential;
  assert.equal(listed.endpoint, "/inference/v1/chat/completions");
  assert.equal(listed.attestation, "/inference/v1/attestation");
  assert.deepEqual(
    { ...listed.models[MODEL], base_micros: 0, per_token_micros: 0, full_cap_micros: "0" },
    {
      base_micros: 0,
      per_token_micros: 0,
      full_cap_micros: "0",
      confidential: true,
      tee: "intel-tdx + nvidia",
      provider: "phala",
      e2ee: true,
      attestation: "/inference/v1/attestation",
    },
  );
  // An operator who configured no upstream key gets no advertisement at all.
  assert.equal(build({ confidential: null }).gateway.models().confidential, undefined);
});

test("the request bytes reach the upstream exactly as they arrived", async () => {
  const { gateway, upstream } = build();
  const out = await paid(gateway);
  assert.equal(out.status, 200);

  const call = upstream.calls[0];
  assert.equal(call.url, "https://tee.redpill.ai/v1/chat/completions");
  assert.equal(call.method, "POST");
  assert.equal(call.body.toString("utf8"), REQUEST, "the relay must not reshape a body it is paid to forward");
  assert.equal(call.headers.authorization, "Bearer upstream-key");
});

test("the response bytes reach the caller exactly as the enclave returned them", async () => {
  const { gateway } = build();
  const out = await paid(gateway);
  // Byte equality, not JSON equality: the receipt is signed over these bytes.
  assert.equal(out.bytes.toString("utf8"), RESPONSE);
  assert.equal(out.body, undefined);
});

test("the encryption headers travel up and the receipt headers travel down", async () => {
  const { gateway, upstream } = build();
  const sent = {
    "X-E2EE-Version": "2",
    "x-client-pub-key": "aa".repeat(32),
    "x-model-pub-key": "bb".repeat(32),
    "x-e2ee-nonce": "cc".repeat(32),
    "x-e2ee-timestamp": "1787000000",
    // A caller's own bearer is not ours to pass on, and neither is anything
    // else it happened to set.
    authorization: "Bearer someone-elses-token",
    cookie: "session=1",
  };
  const out = await paid(gateway, REQUEST, sent);
  const forwarded = upstream.calls[0].headers;
  assert.equal(forwarded["x-e2ee-version"], "2");
  assert.equal(forwarded["x-client-pub-key"], "aa".repeat(32));
  assert.equal(forwarded["x-model-pub-key"], "bb".repeat(32));
  assert.equal(forwarded["x-e2ee-nonce"], "cc".repeat(32));
  assert.equal(forwarded["x-e2ee-timestamp"], "1787000000");
  assert.equal(forwarded.authorization, "Bearer upstream-key");
  assert.equal(forwarded.cookie, undefined);
  assert.equal(forwarded["x-signing-algo"], undefined);

  assert.equal(out.headers["x-receipt-id"], "rcpt_1");
  assert.equal(out.headers["x-aci-version"], "aci/1");
  assert.equal(out.headers["x-aci-keyset-digest"], "sha256:abc");
});

test("the applied-encryption headers come back when the enclave sets them", async () => {
  const { gateway } = build({
    upstream: () => new Response(Buffer.from(RESPONSE), {
      status: 200,
      headers: { "x-e2ee-applied": "true", "x-e2ee-version": "2", "x-e2ee-algo": "x25519" },
    }),
  });
  const out = await paid(gateway);
  assert.equal(out.headers["x-e2ee-applied"], "true");
  assert.equal(out.headers["x-e2ee-version"], "2");
  assert.equal(out.headers["x-e2ee-algo"], "x25519");
});

test("only allowlisted models are relayed, and an unknown one costs no upstream call", async () => {
  const { gateway, upstream } = build();
  const body = JSON.stringify({ model: "gpt-4", max_tokens: 16, messages: [{ role: "user", content: "hi" }] });
  const out = await paid(gateway, body);
  assert.equal(out.status, 400);
  assert.equal(out.body.error, "unknown_model");
  assert.deepEqual(out.body.models, [MODEL]);
  assert.equal(upstream.calls.length, 0);
});

test("a request the gateway cannot bound is refused before anything is charged", async () => {
  const { gateway, upstream } = build();
  const cases = [
    [{ model: MODEL, messages: [{ role: "user", content: "hi" }] }, "max_tokens_required"],
    [{ model: MODEL, max_tokens: 9999, messages: [{ role: "user", content: "hi" }] }, "max_tokens_required"],
    [{ model: MODEL, max_tokens: 16 }, "messages_required"],
    [{ model: MODEL, max_tokens: 16, messages: [{ role: "user", content: "hi" }], stream: true }, "stream_unsupported"],
    [{ model: MODEL, max_tokens: 16, messages: [{ role: "user", content: "hi" }], n: 4 }, "n_unsupported"],
  ];
  for (const [body, error] of cases) {
    const out = await paid(gateway, JSON.stringify(body));
    assert.equal(out.status, 400, error);
    assert.equal(out.body.error, error);
  }
  const oversized = await paid(gateway, "x".repeat(MAX_CONFIDENTIAL_BODY_BYTES + 1));
  assert.equal(oversized.status, 413);
  assert.equal(upstream.calls.length, 0);
});

test("an upstream that refuses to serve keeps the payment usable", async () => {
  let quota = false;
  const { gateway, upstream } = build({
    upstream: () =>
      quota
        ? new Response(Buffer.from(RESPONSE), { status: 200, headers: { "x-receipt-id": "rcpt_2" } })
        : new Response(Buffer.from('{"error":"insufficient credit"}'), { status: 403 }),
  });
  const refused = await paid(gateway);
  assert.equal(refused.status, 503);
  assert.equal(refused.body.error, "upstream_unavailable");
  assert.match(refused.body.retry, /not consumed/);
  // Whatever upstream said about our account is upstream's business.
  assert.equal(refused.body.detail, undefined);

  quota = true;
  const retry = await paid(gateway);
  assert.equal(retry.status, 200, "the same payment header must still work");
  assert.equal(upstream.calls.length, 2);
});

test("a request the upstream rejects is quoted back so the caller can fix it", async () => {
  const { gateway } = build({
    upstream: () => new Response(Buffer.from('{"error":{"message":"e2ee headers incomplete"}}'), { status: 400 }),
  });
  const out = await paid(gateway);
  assert.equal(out.status, 400);
  assert.equal(out.body.error, "upstream_rejected");
  assert.equal(out.body.upstream_status, 400);
  assert.match(out.body.detail, /e2ee headers incomplete/);

  const again = await paid(gateway);
  assert.notEqual(again.body.error, "payment_reused", "nothing was served, so nothing was spent");
});

test("an upstream that never answers releases the payment", async () => {
  const { gateway } = build({
    upstream: () => {
      throw new Error("connect ETIMEDOUT");
    },
  });
  const out = await paid(gateway);
  assert.equal(out.status, 503);
  assert.equal(out.body.error, "upstream_unavailable");
  assert.match(out.body.detail, /ETIMEDOUT/);
});

test("a replayed payment returns the bytes it already bought", async () => {
  const { gateway, upstream } = build();
  const first = await paid(gateway);
  const replay = await paid(gateway);
  assert.equal(replay.status, 200);
  assert.equal(replay.bytes.toString("utf8"), first.bytes.toString("utf8"));
  assert.equal(replay.headers["x-prism-replayed"], "true");
  assert.equal(replay.headers["x-receipt-id"], "rcpt_1");
  assert.equal(upstream.calls.length, 1, "and does not buy it again");
});

test("the daily spend cap stops the relay before it takes another payment", async () => {
  const { gateway, upstream, tick } = build({
    confidential: { dailyUsd: MODELLED_USD * 2.5 },
    upstream: () => new Response(Buffer.from(RESPONSE_NO_COST), { status: 200 }),
  });
  assert.equal((await paid(gateway, REQUEST, {}, paymentFor("11"))).status, 200);
  assert.equal((await paid(gateway, REQUEST, {}, paymentFor("22"))).status, 200);

  const capped = await paid(gateway, REQUEST, {}, paymentFor("33"));
  assert.equal(capped.status, 503);
  assert.equal(capped.body.error, "spend_cap_reached");
  assert.equal(upstream.calls.length, 2, "a capped request never reaches the upstream");

  const stats = gateway.stats();
  assert.equal(stats.confidential_generations, 2);
  assert.equal(stats.confidential_spend_today_usd, Number((MODELLED_USD * 2).toFixed(6)));
  assert.equal(stats.confidential_daily_cap_usd, MODELLED_USD * 2.5);

  // The cap is a day's worth, not a lifetime's.
  tick(24 * 60 * 60 * 1000);
  assert.equal((await paid(gateway, REQUEST, {}, paymentFor("44"))).status, 200);
});

test("an upstream that reports no cost is charged what the request was modelled at", async () => {
  const lines = [];
  const { gateway } = build({
    upstream: () => new Response(Buffer.from(RESPONSE_NO_COST), { status: 200 }),
    log: (line) => lines.push(line),
  });
  await paid(gateway, REQUEST, {}, paymentFor("11"));
  await paid(gateway, REQUEST, {}, paymentFor("22"));

  const stats = gateway.stats();
  // Never zero: a cap that only counts what the upstream volunteers is a cap
  // the upstream can switch off.
  assert.equal(stats.confidential_spend_today_usd, Number((MODELLED_USD * 2).toFixed(6)));
  assert.equal(stats.confidential_cost_usd, Number((MODELLED_USD * 2).toFixed(6)));
  assert.equal(lines.filter((line) => line.includes("no usage.cost")).length, 1, "said once, not once a call");
  assert.match(lines[lines.length - 1], /cost=~0\.010320/);
});

test("what the upstream says it charged replaces what the request was modelled at", async () => {
  const { gateway } = build();
  await paid(gateway);
  assert.equal(gateway.stats().confidential_spend_today_usd, 0.00012);
});

test("a request the upstream does not serve gives its reservation back", async () => {
  const { gateway } = build({
    upstream: () => new Response(Buffer.from('{"error":"insufficient credit"}'), { status: 403 }),
  });
  assert.equal((await paid(gateway)).status, 503);
  assert.equal(gateway.stats().confidential_spend_today_usd, 0);

  const dead = build({
    upstream: () => {
      throw new Error("connect ETIMEDOUT");
    },
  });
  assert.equal((await paid(dead.gateway)).status, 503);
  assert.equal(dead.gateway.stats().confidential_spend_today_usd, 0);
});

test("two requests racing for the last of the cap cannot both take it", async () => {
  let release;
  const upstreamAnswered = new Promise((resolve) => {
    release = resolve;
  });
  // Room for one modelled request and no more.
  const { gateway, upstream } = build({
    confidential: { dailyUsd: MODELLED_USD * 1.5 },
    upstream: async () => {
      await upstreamAnswered;
      return new Response(Buffer.from(RESPONSE), { status: 200 });
    },
  });

  const first = paid(gateway, REQUEST, {}, paymentFor("11"));
  const second = paid(gateway, REQUEST, {}, paymentFor("22"));
  release();
  const [a, b] = await Promise.all([first, second]);

  assert.equal(a.status, 200);
  assert.equal(b.status, 503);
  assert.equal(b.body.error, "spend_cap_reached");
  assert.equal(upstream.calls.length, 1, "the loser of the race never reaches the upstream");
});

test("usage is counted, revenue is booked, and the content is not logged", async () => {
  const lines = [];
  const { gateway } = build({ log: (line) => lines.push(line) });
  await paid(gateway);
  const stats = gateway.stats();
  assert.equal(stats.confidential_tokens_in, 11);
  assert.equal(stats.confidential_tokens_out, 4);
  assert.equal(stats.confidential_cost_usd, 0.00012);
  const card = DEFAULT_CONFIDENTIAL_PRICING[MODEL];
  assert.equal(stats.revenue_micros, String(card.base + card.perToken * 64));
  assert.equal(lines.length, 1);
  assert.match(lines[0], /confidential phala\/gemma-4-26b-a4b-uncensored in=11 out=4 cost=0.00012 receipt=rcpt_1/);
  assert.doesNotMatch(lines[0], /hi|assistant/);
});

test("a nonce that is not 64 lowercase hex is refused before it reaches the upstream", async () => {
  const { gateway, upstream } = build();
  for (const nonce of [undefined, null, "", "ab", "AB".repeat(32), `${"ab".repeat(32)}f`, "zz".repeat(32)]) {
    const out = await gateway.attestation(nonce);
    assert.equal(out.status, 400, `nonce ${nonce}`);
    assert.equal(out.body.error, "invalid_nonce");
  }
  assert.equal(upstream.calls.length, 0);

  const nonce = "ab".repeat(32);
  const ok = await gateway.attestation(nonce);
  assert.equal(ok.status, 200);
  assert.equal(upstream.calls[0].url, `https://tee.redpill.ai/v1/aci/attestation?nonce=${nonce}`);
  assert.equal(upstream.calls[0].headers.authorization, undefined, "attestation is public and needs no key");
});

test("a receipt is fetched under the gateway's own bearer, which is what makes it reachable", async () => {
  const { gateway, upstream } = build();
  const out = await gateway.receipt("rcpt_1");
  assert.equal(out.status, 200);
  assert.equal(out.bytes.toString("utf8"), RESPONSE);
  assert.equal(upstream.calls[0].url, "https://tee.redpill.ai/v1/aci/receipts/rcpt_1");
  assert.equal(upstream.calls[0].headers.authorization, "Bearer upstream-key");

  for (const id of ["", "../attestation", "a/b", "x".repeat(200)]) {
    assert.equal((await gateway.receipt(id)).body.error, "invalid_receipt_id", `id ${id}`);
  }
  assert.equal(upstream.calls.length, 1);
});

test("sessions are listed and fetched by their own id", async () => {
  const { gateway, upstream } = build();
  assert.equal((await gateway.sessions()).status, 200);
  assert.equal(upstream.calls[0].url, "https://tee.redpill.ai/v1/aci/sessions");

  await gateway.sessions({ model: MODEL });
  assert.equal(upstream.calls[1].url, `https://tee.redpill.ai/v1/aci/sessions?model=${encodeURIComponent(MODEL)}`);
  assert.equal((await gateway.sessions({ model: "gpt-4" })).body.error, "unknown_model");

  const id = "cd".repeat(32);
  await gateway.session(id);
  assert.equal(upstream.calls[2].url, `https://tee.redpill.ai/v1/aci/sessions/${id}`);
  assert.equal((await gateway.session("nope")).body.error, "invalid_session_id");
});

test("gpu evidence comes from the host that publishes it, not the confidential one", async () => {
  const { gateway, upstream } = build();
  const out = await gateway.gpuEvidence(MODEL);
  assert.equal(out.status, 200);
  assert.equal(
    upstream.calls[0].url,
    `https://api.redpill.ai/v1/attestation/report?model=${encodeURIComponent(MODEL)}`,
  );
  assert.equal(upstream.calls[0].headers.authorization, undefined);
  assert.equal((await gateway.gpuEvidence("gpt-4")).body.error, "unknown_model");
});

test("the free relay is rate limited rather than left open as a proxy", async () => {
  const { gateway, tick } = build({ relayPerMinute: 3 });
  const nonce = "ab".repeat(32);
  for (let i = 0; i < 3; i += 1) assert.equal((await gateway.attestation(nonce)).status, 200);
  const limited = await gateway.attestation(nonce);
  assert.equal(limited.status, 429);
  assert.equal(limited.headers["retry-after"], "60");

  tick(61_000);
  assert.equal((await gateway.attestation(nonce)).status, 200);
});

test("without an upstream key the whole class answers 404 rather than half-working", async () => {
  const { gateway, upstream } = build({ confidential: null });
  assert.equal((await gateway.handleConfidential(Buffer.from(REQUEST), {}, PAYMENT, 2)).status, 404);
  assert.equal((await gateway.attestation("ab".repeat(32))).status, 404);
  assert.equal((await gateway.receipt("rcpt_1")).status, 404);
  assert.equal((await gateway.sessions({ model: MODEL })).status, 404);
  assert.equal((await gateway.session("cd".repeat(32))).status, 404);
  assert.equal((await gateway.gpuEvidence(MODEL)).status, 404);
  assert.equal(gateway.confidential(), null);
  assert.equal(upstream.calls.length, 0);
});

test("a confidential model with no card of its own is priced as the dearest one that has", () => {
  const { gateway } = build({ confidential: { models: { "phala/something-new": {} } } });
  const listed = gateway.models().confidential.models["phala/something-new"];
  const dearest = Object.values(DEFAULT_CONFIDENTIAL_PRICING).reduce((a, b) =>
    a.base + a.perToken * MAX_PREDICT_TOKENS >= b.base + b.perToken * MAX_PREDICT_TOKENS ? a : b,
  );
  assert.equal(listed.base_micros, dearest.base);
  assert.equal(listed.per_token_micros, dearest.perToken);
});

test("a misconfigured class fails at boot rather than at the first paid request", () => {
  assert.throws(() => build({ confidential: { key: null } }), /upstream API key/);
  assert.throws(() => build({ confidential: { models: {} } }), /at least one model/);
  assert.throws(() => build({ confidential: { dailyUsd: 0 } }), /positive number of dollars/);
  assert.throws(
    () => build({ confidential: { models: { [MODEL]: { base_micros: -1 } } } }),
    /non-negative numbers/,
  );
});
