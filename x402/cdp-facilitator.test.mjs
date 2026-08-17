import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";

import { createCdpFacilitator, routeByNetwork } from "./cdp-facilitator.mjs";

const SECRET = randomBytes(64).toString("base64");
const KEY_ID = "00000000-0000-4000-8000-000000000000";

const payload = {
  accepted: { scheme: "exact", network: "eip155:8453" },
  payload: {
    signature: "0xsig",
    authorization: { from: "0xF1", to: "0xF2", value: "35600", validAfter: "0", validBefore: "99", nonce: "0xab" },
  },
};

const requirements = {
  scheme: "exact",
  network: "eip155:8453",
  amount: "35600",
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  payTo: "0xC0",
  maxTimeoutSeconds: 60,
};

function withFetch(handler, run) {
  const original = globalThis.fetch;
  globalThis.fetch = handler;
  return run().finally(() => {
    globalThis.fetch = original;
  });
}

const respond = (body, init = {}) =>
  new Response(JSON.stringify(body), { status: init.status ?? 200, headers: { "Content-Type": "application/json" } });

test("the chain is renamed to the spelling CDP understands", async () => {
  let sent;
  await withFetch(async (_url, init) => {
    sent = JSON.parse(init.body);
    return respond({ isValid: true, payer: "0xF1" });
  }, async () => {
    const f = createCdpFacilitator({ keyId: KEY_ID, keySecret: SECRET });
    await f.verify(payload, requirements);
  });

  assert.equal(sent.x402Version, 1);
  assert.equal(sent.paymentPayload.network, "base");
  assert.equal(sent.paymentRequirements.network, "base");
  // v1 names the ceiling maxAmountRequired; sending `amount` fails their schema.
  assert.equal(sent.paymentRequirements.maxAmountRequired, "35600");
  assert.equal(sent.paymentRequirements.amount, undefined);
});

test("the request is signed for exactly the path it is sent to", async () => {
  const seen = [];
  await withFetch(async (url, init) => {
    seen.push({ url, auth: init.headers.Authorization });
    return respond({ isValid: true });
  }, async () => {
    const f = createCdpFacilitator({ keyId: KEY_ID, keySecret: SECRET });
    await f.verify(payload, requirements);
  });

  const [{ url, auth }] = seen;
  assert.match(url, /\/platform\/v2\/x402\/verify$/);
  const claims = JSON.parse(Buffer.from(auth.split(".")[1], "base64url").toString());
  assert.deepEqual(claims.uris, ["POST api.cdp.coinbase.com/platform/v2/x402/verify"]);
  assert.equal(claims.sub, KEY_ID);
});

test("a refusal keeps the reason CDP gave", async () => {
  const verdict = await withFetch(
    async () => respond({ isValid: false, invalidReason: "insufficient_funds" }),
    async () => {
      const f = createCdpFacilitator({ keyId: KEY_ID, keySecret: SECRET });
      return f.verify(payload, requirements);
    },
  );
  assert.equal(verdict.isValid, false);
  assert.equal(verdict.invalidReason, "insufficient_funds");
});

test("an upstream failure after settle is unknown, not a refusal", async () => {
  const result = await withFetch(
    async () => new Response("upstream exploded", { status: 502 }),
    async () => {
      const f = createCdpFacilitator({ keyId: KEY_ID, keySecret: SECRET });
      return f.settle(payload, requirements);
    },
  );
  // The transfer may have happened. Reporting false here refunds a real payment.
  assert.equal(result.settled, null);
  assert.equal(result.success, false);
  assert.equal(result.errorReason, "settlement_unconfirmed");
});

test("a rejected settle is a definite no", async () => {
  const result = await withFetch(
    async () => respond({ success: false, errorReason: "invalid_signature" }),
    async () => {
      const f = createCdpFacilitator({ keyId: KEY_ID, keySecret: SECRET });
      return f.settle(payload, requirements);
    },
  );
  assert.equal(result.settled, false);
  assert.equal(result.errorReason, "invalid_signature");
});

test("only the networks it claims are routed to it", async () => {
  const calls = [];
  const primary = {
    handles: (n) => n === "eip155:8453",
    verify: async () => (calls.push("cdp"), { isValid: true }),
    settle: async () => (calls.push("cdp"), { success: true }),
  };
  const fallback = {
    verify: async () => (calls.push("local"), { isValid: true }),
    settle: async () => (calls.push("local"), { success: true }),
    supported: async () => ({ kinds: [] }),
  };
  const routed = routeByNetwork(primary, fallback);

  await routed.verify(payload, { network: "eip155:8453" });
  await routed.verify(payload, { network: "eip155:4663" });
  assert.deepEqual(calls, ["cdp", "local"]);
});

test("a malformed secret is refused at construction", () => {
  assert.throws(() => createCdpFacilitator({ keyId: KEY_ID, keySecret: "c2hvcnQ=" }), /expected 64/);
  assert.throws(() => createCdpFacilitator({ keyId: KEY_ID }), /key id and a secret/);
});

test("a 4xx carrying a verdict is the verdict, not an outage", async () => {
  const verdict = await withFetch(
    async () =>
      new Response(
        JSON.stringify({ isValid: false, invalidReason: "invalid_exact_evm_payload_signature", payer: "0xF1" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      ),
    async () => {
      const f = createCdpFacilitator({ keyId: KEY_ID, keySecret: SECRET });
      return f.verify(payload, requirements);
    },
  );
  assert.equal(verdict.isValid, false);
  assert.equal(verdict.invalidReason, "invalid_exact_evm_payload_signature");
});
