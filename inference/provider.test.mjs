import assert from "node:assert/strict";
import { test } from "node:test";
import { createGateway, DEFAULT_CONFIDENTIAL_PRICING, MAX_PREDICT_TOKENS } from "./gateway.mjs";
import { providerModels } from "./provider.mjs";

const GEMMA = "phala/gemma-4-26b-a4b-uncensored";
const QWEN = "phala/qwen3.6-35b-a3b-uncensored";

// The block `/v1/models` publishes, which is the only input the catalogue has.
const confidential = (models = [GEMMA]) => ({
  max_tokens: MAX_PREDICT_TOKENS,
  max_body_bytes: 32 * 1024,
  models: Object.fromEntries(
    models.map((m) => {
      const card = DEFAULT_CONFIDENTIAL_PRICING[m];
      return [m, {
        base_micros: card.base,
        per_token_micros: card.perToken,
        full_cap_micros: String(card.base + card.perToken * MAX_PREDICT_TOKENS),
      }];
    }),
  ),
});

const catalogue = (over = {}) => providerModels({ confidential: confidential(), dailyUsd: 2, ...over });
const only = (over) => catalogue(over).data[0];

const PAYMENT = Buffer.from(
  JSON.stringify({ txHash: `0x${"ab".repeat(32)}`, signature: "0xsig" }),
).toString("base64");

// A live gateway, so a document checked against it is checked against the route
// it describes rather than against a fixture that agrees with nothing.
const build = (models = [GEMMA]) =>
  createGateway({
    agent: { lease: async () => ({}), run: async () => ({ code: 0 }), endLease() {} },
    models: ["llama3.2:3b", "llama3.1:8b"],
    payTo: "0x0000000000000000000000000000000000000002",
    image: `img@sha256:${"0".repeat(64)}`,
    verify: async () => ({ ok: true }),
    spawnTunnel: async () => ({ close() {} }),
    fetchOllama: async () => ({ ok: true, json: async () => ({}) }),
    log: () => {},
    confidential: { key: "upstream-key", models: Object.fromEntries(models.map((m) => [m, {}])) },
  });

// The closed vocabularies the catalogue schema declares. Anything outside them
// is rejected on submission, so an extra key here is a listing that never goes
// live rather than a field nobody reads.
const ROOT_KEYS = new Set([
  "schema_version", "id", "hugging_face_id", "name", "created", "quantization", "tokenizer",
  "description", "input_modalities", "output_modalities", "pricing", "capacity",
  "passthrough_parameters", "deprecation_date", "is_ready", "is_free", "discount_to_user",
  "openrouter", "datacenters", "deployment_region", "compliance",
]);
const REQUIRED_ROOT = ["schema_version", "id", "name", "input_modalities", "output_modalities"];
const COST_USD = /^\d+(\.\d+)?$/;

test("the document validates against the shape a provider monitor accepts", () => {
  for (const doc of catalogue({ confidential: confidential([GEMMA, QWEN]) }).data) {
    for (const key of Object.keys(doc)) assert.ok(ROOT_KEYS.has(key), `${key} is not a document field`);
    for (const key of REQUIRED_ROOT) assert.ok(doc[key] != null, `${key} is required`);
    assert.equal(doc.schema_version, "2.4");
    assert.ok(doc.input_modalities.length >= 1 && doc.output_modalities.length >= 1);

    for (const out of doc.output_modalities) {
      assert.equal(out.type, "text");
      assert.ok(out.supported_parameters, "an output modality declares its parameters or it is invalid");
    }
    for (const entry of [...doc.pricing, ...doc.output_modalities.flatMap((o) => o.pricing ?? [])]) {
      assert.match(entry.cost_usd, COST_USD, "prices are decimal strings, never numbers");
      assert.deepEqual(Object.keys(entry).sort(), ["cost_usd", "type", "unit"]);
    }
    for (const entry of doc.capacity) {
      assert.ok(Number.isInteger(entry.value) && entry.value >= 1);
      assert.ok(["minute", "hour", "day"].includes(entry.per));
    }
  }
});

test("prices are per one unit, so a per-token rate is the price of one token", () => {
  const doc = only();
  const card = DEFAULT_CONFIDENTIAL_PRICING[GEMMA];

  // 5 micros a token is $0.000005 a token. Quoting the per-million figure here
  // reads as $5 a token and prices the model a million times over.
  assert.equal(card.perToken, 5);
  assert.deepEqual(doc.output_modalities[0].pricing, [
    { type: "completion", unit: "token", cost_usd: "0.000005" },
  ]);
  assert.equal(card.base, 10_000);
  assert.deepEqual(doc.pricing, [{ type: "request", unit: "request", cost_usd: "0.010000" }]);

  // Both together are what the 402 quotes at the cap: 10000 + 5 x 1024.
  const full = Number(doc.pricing[0].cost_usd) +
    Number(doc.output_modalities[0].pricing[0].cost_usd) * MAX_PREDICT_TOKENS;
  assert.equal(full.toFixed(6), "0.015120");
});

test("prompt tokens carry no price, because nothing bills them", () => {
  const input = only().input_modalities[0];
  assert.equal(input.type, "text");
  assert.equal(input.pricing, undefined, "an unbilled SKU is left out, not declared at zero");
  assert.deepEqual(input.supported_inputs, { max_prompt_length: { value: 32_768, unit: "byte" } });
});

test("the output cap is declared as both a limit and a parameter", () => {
  const out = only().output_modalities[0];
  assert.deepEqual(out.max_length, { value: 1024, unit: "token" });
  assert.deepEqual(out.supported_parameters.max_tokens, {
    type: "integer", min: 1, max: 1024, unit: "token", required: true,
  });
  assert.equal(out.streaming, true, "the relay serves server-sent events");
});

test("max_tokens is declared required, because the route refuses a request without one", async () => {
  const gateway = build();
  const doc = providerModels({
    confidential: gateway.confidential(),
    dailyUsd: gateway.stats().confidential_daily_cap_usd,
  }).data[0];
  assert.equal(doc.output_modalities[0].supported_parameters.max_tokens.required, true);

  // The route the document describes, driven the way an OpenAI client would
  // build the call. A parameter the catalogue leaves optional here is a listing
  // that 400s every default-shaped request it attracts.
  const body = Buffer.from(JSON.stringify({ model: GEMMA, messages: [{ role: "user", content: "hi" }] }));
  const out = await gateway.handleConfidential(body, {}, PAYMENT, 2);
  assert.equal(out.status, 400);
  assert.equal(out.body.error, "max_tokens_required");
});

test("capacity is the day's budget counted in the most expensive request allowed", () => {
  // $2 a day against a full-cap gemma request of $0.015120.
  assert.deepEqual(only().capacity, [{ type: "request", unit: "request", per: "day", value: 132 }]);
  assert.equal(only({ dailyUsd: 1 }).capacity[0].value, 66);

  // A cap below one full-cap call is a misconfiguration, and a declared limit
  // cannot be zero, so it floors at one rather than emitting an invalid entry.
  assert.equal(only({ dailyUsd: 0.001 }).capacity[0].value, 1);
});

test("one budget across two models is not two budgets", () => {
  // Qwen is twice gemma's price and both draw on the same $2. Counting gemma
  // against its own cheaper cap would declare 132 gemma requests a day next to
  // 66 qwen ones, and serving either declared figure would leave the other
  // unservable long before the day was out.
  const docs = catalogue({ confidential: confidential([GEMMA, QWEN]) }).data;
  const full = { [GEMMA]: 0.015120, [QWEN]: 0.030240 };
  for (const doc of docs) {
    assert.equal(doc.capacity[0].value, 66, `${doc.id} declares the shared budget's floor`);
    assert.ok(doc.capacity[0].value * full[doc.id] <= 2, `${doc.id} declares more than the budget funds`);
  }
});

test("zero data retention is declared, and it is declared false", () => {
  // A served answer is held against the payment that bought it so a dropped
  // connection can collect it. Claiming zero retention over a buffer that
  // exists is the kind of claim a compliance filter is built to catch.
  assert.deepEqual(only().compliance, { zdr: false });
});

test("nothing is invented where the upstream publishes nothing", () => {
  const doc = only();
  assert.equal(doc.datacenters, undefined, "no attested location means no country code");
  assert.equal(doc.deployment_region, undefined);
  assert.equal(doc.quantization, undefined);
  assert.equal(doc.hugging_face_id, undefined);
  // The id is the upstream's, and so is the half of the name that follows it.
  assert.equal(doc.id, GEMMA);
  assert.equal(doc.name, "Phala: gemma-4-26b-a4b-uncensored");
});

test("an unconfigured confidential class lists nothing rather than erroring", () => {
  assert.deepEqual(providerModels({ confidential: null, dailyUsd: 2 }), { data: [] });
  assert.deepEqual(providerModels(), { data: [] });
});

test("the open tier never reaches the catalogue", () => {
  const gateway = build();
  const stats = gateway.stats();
  const ids = providerModels({
    confidential: gateway.confidential(),
    dailyUsd: stats.confidential_daily_cap_usd,
  }).data.map((d) => d.id);

  assert.deepEqual(ids, [GEMMA]);
  for (const open of gateway.models().models) assert.ok(!ids.includes(open), `${open} leases per request`);
});
