import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createGateway,
  GPU_EVIDENCE_TTL_MS,
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

// The exact scheme: signed, verified before the work and broadcast after it,
// which is the only shape where a settlement can hold a response open.
const AUTHORIZATION = Buffer.from(JSON.stringify({
  x402Version: 2,
  accepted: { scheme: "exact", network: "eip155:4663" },
  payload: {
    signature: "0xsig",
    authorization: { from: PAYER, to: PAY_TO, value: "1", validAfter: "1", validBefore: "2", nonce: `0x${"cd".repeat(32)}` },
  },
})).toString("base64");

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

// The same answer as frames. Usage rides the last one before the terminator,
// which is where a caller that asked for it gets it.
const FRAMES = [
  'data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{"role":"assistant"}}]}\n\n',
  'data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"ok"}}]}\n\n',
  'data: {"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":4,"cost":0.00012}}\n\n',
  "data: [DONE]\n\n",
];
const STREAM_REQUEST = REQUEST.replace('"max_tokens": 64', '"stream": true, "max_tokens": 64');

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

// One frame per chunk, each enqueued only when the reader asks for the next, so
// a relay that collected the answer and wrote it once would fail rather than
// pass by accident. `fail` is the enclave dropping the connection mid-answer.
function sseResponse(frames = FRAMES, { fail = null, headers = {} } = {}) {
  let sent = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (sent < frames.length) return void controller.enqueue(Buffer.from(frames[sent++]));
      if (fail) return void controller.error(new Error(fail));
      controller.close();
    },
  });
  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/event-stream", "x-receipt-id": "rcpt_1", ...headers },
  });
}

async function collect(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return chunks;
}

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

test("a streamed answer reaches the caller frame by frame", async () => {
  const { gateway, upstream } = build({ upstream: () => sseResponse() });
  const out = await paid(gateway, STREAM_REQUEST);
  assert.equal(out.status, 200);
  assert.equal(out.headers["content-type"], "text/event-stream");
  assert.equal(out.bytes, undefined, "a stream is not a body the caller waits behind");
  assert.equal(upstream.calls[0].headers.accept, "text/event-stream");
  assert.equal(upstream.calls[0].body.toString("utf8"), STREAM_REQUEST);

  const chunks = await collect(out.stream);
  // More than one chunk is the whole point: what a caller is timed on is the
  // first token, not the last.
  assert.equal(chunks.length, FRAMES.length);
  // And byte equality over the concatenation, framing included, because that is
  // what the receipt hash covers.
  assert.equal(Buffer.concat(chunks).toString("utf8"), FRAMES.join(""));
});

test("a request that asks for no stream is answered whole, as it always was", async () => {
  const { gateway, upstream } = build();
  const out = await paid(gateway);
  assert.equal(out.stream, undefined);
  assert.equal(out.bytes.toString("utf8"), RESPONSE);
  assert.equal(out.headers["content-type"], "application/json");
  assert.equal(upstream.calls[0].headers.accept, "application/json");

  // An enclave that answers a stream request whole is relayed whole. Asking is
  // not being given.
  const ignored = build();
  const buffered = await paid(ignored.gateway, STREAM_REQUEST);
  assert.equal(buffered.stream, undefined);
  assert.equal(buffered.bytes.toString("utf8"), RESPONSE);
});

test("a stream the enclave never starts is refused with a status the caller can act on", async () => {
  const dead = build({
    upstream: () => {
      throw new Error("connect ETIMEDOUT");
    },
  });
  const gone = await paid(dead.gateway, STREAM_REQUEST);
  assert.equal(gone.status, 503);
  assert.equal(gone.stream, undefined);
  assert.equal(gone.body.error, "upstream_unavailable");
  assert.equal(dead.gateway.stats().confidential_spend_today_usd, 0);

  const busy = build({ upstream: () => new Response(Buffer.from('{"error":"slow down"}'), { status: 429 }) });
  const limited = await paid(busy.gateway, STREAM_REQUEST);
  assert.equal(limited.status, 503);
  assert.equal(limited.body.upstream_status, 429);
  assert.equal(limited.stream, undefined);

  const strict = build({ upstream: () => new Response(Buffer.from('{"error":"stream unsupported"}'), { status: 400 }) });
  const rejected = await paid(strict.gateway, STREAM_REQUEST);
  assert.equal(rejected.status, 400);
  assert.equal(rejected.body.error, "upstream_rejected");
  assert.match(rejected.body.detail, /stream unsupported/);
});

test("a stream that stops short says so and takes no payment", async () => {
  let broken = true;
  const { gateway, upstream } = build({
    upstream: () => (broken ? sseResponse(FRAMES.slice(0, 2), { fail: "socket hang up" }) : sseResponse()),
  });
  const out = await paid(gateway, STREAM_REQUEST);
  // The status went out with the first frame, so the truncation is told in the
  // only place left: the body.
  assert.equal(out.status, 200);
  const body = Buffer.concat(await collect(out.stream)).toString("utf8");
  assert.ok(body.startsWith(FRAMES[0] + FRAMES[1]), "the frames that did arrive are the frames they were");
  assert.match(body, /^data: /m);
  assert.match(body, /stream_truncated/);
  assert.match(body, /payment was not consumed/);

  const stats = gateway.stats();
  assert.equal(stats.confidential_generations, 0);
  assert.equal(stats.confidential_spend_today_usd, 0);
  assert.equal(stats.revenue_micros, "0");

  broken = false;
  const retry = await paid(gateway, STREAM_REQUEST);
  assert.equal(retry.status, 200, "the same payment header must still work");
  assert.equal(Buffer.concat(await collect(retry.stream)).toString("utf8"), FRAMES.join(""));
  assert.equal(upstream.calls.length, 2);
});

test("a stream that carried its terminator is the whole answer, whatever the socket did next", async () => {
  // Every frame arrives, [DONE] included, and then the connection resets. A
  // reset after the terminator is a routine way for an SSE stream to end and
  // says nothing about the answer, which is complete and already signed for.
  const { gateway, upstream } = build({ upstream: () => sseResponse(FRAMES, { fail: "terminated" }) });
  const out = await paid(gateway, STREAM_REQUEST);
  const body = Buffer.concat(await collect(out.stream)).toString("utf8");
  // Not one byte more than the enclave sent: an error frame appended here would
  // be invisible to every client that stops reading at [DONE], and a response
  // hash the receipt does not match for every client that does not.
  assert.equal(body, FRAMES.join(""));

  const stats = gateway.stats();
  assert.equal(stats.confidential_generations, 1, "a served generation is a served generation");
  assert.equal(stats.revenue_micros, String(CARD.base + CARD.perToken * 64));
  assert.equal(stats.confidential_cost_usd, 0.00012);

  // And it was paid for, so the header that bought it collects the bytes again
  // rather than buying a second generation with the same money.
  const replay = await paid(gateway, STREAM_REQUEST);
  assert.equal(replay.headers["x-prism-replayed"], "true");
  assert.equal(replay.bytes.toString("utf8"), body);
  assert.equal(upstream.calls.length, 1);
});

test("the caller is let go at the last frame, not at the settlement behind it", async () => {
  // A broadcast that never comes back, which is the far end of what the route
  // quotes 60 seconds for.
  const exact = {
    verify: async () => ({ isValid: true, payer: PAYER }),
    settle: () => new Promise(() => {}),
  };
  const { gateway } = build({ upstream: () => sseResponse(), exact });
  const out = await paid(gateway, STREAM_REQUEST, {}, AUTHORIZATION);
  const body = await Promise.race([
    collect(out.stream).then((chunks) => Buffer.concat(chunks).toString("utf8")),
    new Promise((r) => setTimeout(() => r("the response is still open"), 250)),
  ]);
  assert.equal(body, FRAMES.join(""));

  // The generation is booked and the payment is spent by the time the caller is
  // let go; only the revenue waits on the chain, because only the chain knows.
  const stats = gateway.stats();
  assert.equal(stats.confidential_generations, 1);
  assert.equal(stats.revenue_micros, "0");
  const replay = await paid(gateway, STREAM_REQUEST, {}, AUTHORIZATION);
  assert.equal(replay.headers["x-prism-replayed"], "true");
  assert.equal(replay.bytes.toString("utf8"), FRAMES.join(""));
});

test("a streamed request is accounted from the frame that carries its usage", async () => {
  const lines = [];
  const { gateway } = build({ upstream: () => sseResponse(), log: (line) => lines.push(line) });
  await collect((await paid(gateway, STREAM_REQUEST)).stream);

  const stats = gateway.stats();
  assert.equal(stats.confidential_generations, 1);
  assert.equal(stats.confidential_tokens_in, 11);
  assert.equal(stats.confidential_tokens_out, 4);
  assert.equal(stats.confidential_cost_usd, 0.00012);
  const card = DEFAULT_CONFIDENTIAL_PRICING[MODEL];
  assert.equal(stats.revenue_micros, String(card.base + card.perToken * 64));
  assert.equal(lines.length, 1);
  assert.match(lines[0], /confidential phala\/gemma-4-26b-a4b-uncensored stream in=11 out=4 cost=0.00012 receipt=rcpt_1/);
  assert.doesNotMatch(lines[0], /hi|content/);

  // A caller who did not ask the enclave for usage is charged the modelled
  // price, the same figure an upstream that reports no cost is charged at.
  const quiet = build({ upstream: () => sseResponse([FRAMES[0], FRAMES[1], FRAMES[3]]) });
  await collect((await paid(quiet.gateway, STREAM_REQUEST)).stream);
  assert.equal(quiet.gateway.stats().confidential_spend_today_usd, Number(MODELLED_USD.toFixed(6)));
  assert.equal(quiet.gateway.stats().confidential_tokens_out, 0);
});

test("a streamed answer carries the encryption headers and replays whole", async () => {
  const { gateway, upstream } = build({
    upstream: () =>
      sseResponse(FRAMES, {
        headers: { "x-e2ee-applied": "true", "x-e2ee-version": "2", "x-e2ee-algo": "x25519" },
      }),
  });
  const out = await paid(gateway, STREAM_REQUEST, {
    "X-E2EE-Version": "2",
    "x-client-pub-key": "aa".repeat(32),
    "x-model-pub-key": "bb".repeat(32),
    "x-e2ee-nonce": "cc".repeat(32),
    "x-e2ee-timestamp": "1787000000",
    authorization: "Bearer someone-elses-token",
  });
  const forwarded = upstream.calls[0].headers;
  assert.equal(forwarded["x-e2ee-version"], "2");
  assert.equal(forwarded["x-client-pub-key"], "aa".repeat(32));
  assert.equal(forwarded.authorization, "Bearer upstream-key");
  assert.equal(out.headers["x-e2ee-applied"], "true");
  assert.equal(out.headers["x-e2ee-algo"], "x25519");

  const served = Buffer.concat(await collect(out.stream)).toString("utf8");
  // A client that lost the connection gets back the bytes it bought, which is
  // what keeps the receipt hash reachable after a reconnect.
  const replay = await paid(gateway, STREAM_REQUEST);
  assert.equal(replay.headers["x-prism-replayed"], "true");
  assert.equal(replay.bytes.toString("utf8"), served);
  assert.equal(upstream.calls.length, 1, "and does not buy it again");
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

/// The relay hands the upstream's bytes back untouched, which for a caller who
/// turned e2ee off is the answer in the clear. A payment is public once it has
/// settled, so a spent one must produce nothing for a request it never bought.
test("a spent payment does not relay its bytes to a request it never bought", async () => {
  const { gateway, upstream } = build();
  assert.equal((await paid(gateway)).status, 200);

  const other = REQUEST.replace('"content":"hi"', '"content":"repeat what you were just asked"');
  const stolen = await paid(gateway, other);
  assert.equal(stolen.status, 402);
  assert.equal(stolen.body.error, "payment_reused");
  assert.equal(stolen.bytes, undefined, "the earlier answer was handed to a request that did not pay for it");
  assert.equal(upstream.calls.length, 1);
});

test("the daily spend cap stops the relay before it takes another payment", async () => {
  const { gateway, upstream, tick } = build({
    confidential: { dailyUsd: MODELLED_USD * 2.5 },
    upstream: () => new Response(Buffer.from(RESPONSE_NO_COST), { status: 200 }),
  });
  assert.equal((await paid(gateway, REQUEST, {}, paymentFor("11"))).status, 200);
  assert.equal((await paid(gateway, REQUEST, {}, paymentFor("22"))).status, 200);

  // A budget the operator set is an allowance running out, not the relay
  // breaking, and it says when the allowance comes back.
  const capped = await paid(gateway, REQUEST, {}, paymentFor("33"));
  assert.equal(capped.status, 429);
  assert.equal(capped.body.error, "spend_cap_reached");
  assert.equal(capped.headers["retry-after"], "3600");
  assert.equal(capped.body.retry_after_seconds, 3600);
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
  assert.equal(b.status, 429);
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

test("gpu evidence asks again until the named instance answers", async () => {
  // The model runs on several instances and the upstream picks one per request,
  // so naming the instance we need is only useful if the relay asks more than
  // once. Everything below RTMR3 matches between siblings, which is exactly why
  // the wrong one cannot be waved through.
  const served = `sha256:${"a".repeat(64)}`;
  const answers = [`sha256:${"b".repeat(64)}`, `sha256:${"c".repeat(64)}`, served];
  let asked = 0;
  const { gateway, upstream } = build({
    upstream: (url) => {
      const digest = answers[Math.min(asked++, answers.length - 1)];
      return new Response(JSON.stringify({ workload_keyset_digest: digest }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  // The relay hands the upstream's bytes back untouched, so the instance it
  // reached is read out of those rather than off a parsed body.
  const digestOf = (relayed) => JSON.parse(Buffer.from(relayed.bytes).toString("utf8")).workload_keyset_digest;

  const found = await gateway.gpuEvidence(MODEL, served);
  assert.equal(digestOf(found), served);
  assert.equal(asked, 3);
  assert.ok(upstream.calls.every((c) => c.url.includes("/attestation/report")));

  asked = 0;
  const blind = await gateway.gpuEvidence(MODEL);
  assert.equal(asked, 1, "a caller that names no instance must not make the relay loop");
  assert.equal(digestOf(blind), answers[0]);
});

test("gpu evidence refuses a key set digest that is not one", async () => {
  const { gateway, upstream } = build();
  const out = await gateway.gpuEvidence(MODEL, "not-a-digest");
  assert.equal(out.status, 400);
  assert.equal(out.body.error, "invalid_keyset_digest");
  assert.equal(upstream.calls.length, 0, "a malformed digest must not reach the upstream");
});

test("evidence seen once is held, so a later caller does not depend on the rotation", async () => {
  // The upstream offers a different set of instances from one minute to the
  // next, so retrying inside a bad window cannot help. What previous requests
  // saw is what carries a caller through it.
  const wanted = `sha256:${"a".repeat(64)}`;
  const other = `sha256:${"b".repeat(64)}`;
  let offering = wanted;
  let asked = 0;
  const { gateway } = build({
    upstream: () => {
      asked += 1;
      return new Response(JSON.stringify({ workload_keyset_digest: offering }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const digestOf = (r) => JSON.parse(Buffer.from(r.bytes).toString("utf8")).workload_keyset_digest;

  assert.equal(digestOf(await gateway.gpuEvidence(MODEL, wanted)), wanted);
  const afterFirst = asked;

  // The rotation moves on. Without the cache this is the burst that costs a
  // paid generation: every attempt reaches the wrong instance.
  offering = other;
  const held = await gateway.gpuEvidence(MODEL, wanted);
  assert.equal(digestOf(held), wanted);
  assert.equal(asked, afterFirst, "a held answer must not go back to the upstream");

  // An instance never seen still has to be looked for, and the looking is what
  // fills the cache for next time.
  const missing = await gateway.gpuEvidence(MODEL, `sha256:${"c".repeat(64)}`);
  assert.ok(asked > afterFirst);
  assert.equal(digestOf(missing), other);
  assert.equal(digestOf(await gateway.gpuEvidence(MODEL, other)), other);
});

test("held evidence is dropped once it is too old to stand in for a fresh fetch", async () => {
  const wanted = `sha256:${"d".repeat(64)}`;
  let asked = 0;
  const { gateway, tick } = build({
    upstream: () => {
      asked += 1;
      return new Response(JSON.stringify({ workload_keyset_digest: wanted }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  await gateway.gpuEvidence(MODEL, wanted);
  assert.equal(asked, 1);
  await gateway.gpuEvidence(MODEL, wanted);
  assert.equal(asked, 1, "still fresh");

  tick(GPU_EVIDENCE_TTL_MS + 1);
  await gateway.gpuEvidence(MODEL, wanted);
  assert.equal(asked, 2, "past its life it is fetched again");
});
