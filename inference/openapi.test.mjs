import assert from "node:assert/strict";
import test from "node:test";
import { openApiDocument } from "./openapi.mjs";

const doc = () => openApiDocument({
  models: ["llama3.2:3b", "llama3.1:8b"],
  pricing: {
    "llama3.2:3b": { base_micros: 3000, per_token_micros: 3, full_cap_micros: "6072" },
    "llama3.1:8b": { base_micros: 6000, per_token_micros: 6, full_cap_micros: "12144" },
  },
  jobPriceMicros: 30000,
  contactEmail: "contact@prismnetwork.tech",
  siteUrl: "https://api.prismnetwork.tech",
});

test("it carries every field the scanners require", () => {
  const d = doc();
  assert.equal(d.openapi, "3.1.0");
  for (const field of ["title", "version", "x-guidance"]) {
    assert.ok(d.info[field], `info.${field} is required`);
  }
  assert.ok(d.info.contact.email, "contact email lets us prove we own the origin");
  assert.ok(Object.keys(d.paths).length >= 2);
});

test("every paid operation declares a price, a protocol and a 402", () => {
  const d = doc();
  const paid = Object.values(d.paths).flatMap((p) => Object.values(p)).filter((op) => op["x-payment-info"]);
  assert.equal(paid.length, 3, "single inference, batch inference, and the job runner");
  for (const op of paid) {
    const info = op["x-payment-info"];
    assert.equal(info.price.currency, "USD");
    assert.ok(["fixed", "dynamic"].includes(info.price.mode));
    assert.deepEqual(info.protocols, [{ x402: {} }]);
    assert.ok(op.responses["402"], "a paid operation must document its 402");
  }
});

test("prices are decimal USD here, not the atomic units the 402 carries", () => {
  const d = doc();
  // 30000 micros is three cents. Publishing "30000" would read as $30,000 and
  // is one of the listed registration failures.
  assert.equal(d.paths["/x402/run"].post["x-payment-info"].price.amount, "0.030000");
  const dyn = d.paths["/inference/v1/inference"].post["x-payment-info"].price;
  assert.equal(dyn.min, "0.003000");
  assert.equal(dyn.max, "0.012144");
});

test("every operation has an input and an output schema, or it is not invocable", () => {
  const d = doc();
  for (const [path, item] of Object.entries(d.paths)) {
    for (const [method, op] of Object.entries(item)) {
      const ok = Object.values(op.responses).some((r) => r.content?.["application/json"]?.schema);
      assert.ok(ok, `${method} ${path} needs an output schema`);
      if (method === "post") {
        assert.ok(op.requestBody?.content?.["application/json"]?.schema, `${method} ${path} needs an input schema`);
      }
    }
  }
});

test("the free route is marked free, not merely left unpaid", () => {
  const models = doc().paths["/inference/v1/models"].get;
  assert.equal(models["x-payment-info"], undefined);
  assert.equal(models.responses["402"], undefined);
  // Silence is not enough: an absent security list means "unknown", and the
  // scanners probe it for a payment challenge and fail the origin when a free
  // route answers 200.
  assert.deepEqual(models.security, []);
});

test("paid routes do not claim to be free", () => {
  for (const [path, item] of Object.entries(doc().paths)) {
    for (const op of Object.values(item)) {
      if (!op["x-payment-info"]) continue;
      assert.equal(op.security, undefined, `${path} is paid and must not be marked free`);
    }
  }
});

test("the guidance names both products so an agent can choose", () => {
  const g = doc().info["x-guidance"];
  assert.ok(g.includes("/inference/v1/inference"));
  assert.ok(g.includes("/x402/run"));
  assert.ok(g.includes("no gas"), "the thing that makes paying us easy belongs in the guidance");
});
