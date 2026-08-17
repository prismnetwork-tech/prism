import assert from "node:assert/strict";
import test from "node:test";
import { createBudget, createFacilitator } from "./facilitator.mjs";

const PAYER = "0x53c8B114baF2C4ef4700D20dCc8937a68d133A26";
const REQUIREMENTS = { scheme: "exact", network: "eip155:8453", amount: "1000", asset: "0xasset", payTo: "0xpay" };
const PAYLOAD = { x402Version: 2, payload: { signature: "0xsig", authorization: { from: PAYER } } };

function fakeExact({ isValid = true, settlement } = {}) {
  const calls = { verified: 0, settled: 0 };
  return {
    calls,
    verify: async () => {
      calls.verified += 1;
      return isValid ? { isValid: true, payer: PAYER } : { isValid: false, invalidReason: "insufficient_funds", payer: PAYER };
    },
    settle: async () => {
      calls.settled += 1;
      return settlement ?? { success: true, settled: true, payer: PAYER, transaction: "0xtx", network: "eip155:8453" };
    },
    supported: () => ({ kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:8453" }] }),
  };
}

const body = { paymentPayload: PAYLOAD, paymentRequirements: REQUIREMENTS };

function build(exact, budgetOptions = {}) {
  return createFacilitator({ exact, budget: createBudget({ ...budgetOptions }) });
}

test("supported reports what the verifier handles, with the budget alongside", async () => {
  const f = build(fakeExact(), { dailySettlements: 5 });
  const out = await f.handle("GET", "/supported", null);
  assert.equal(out.status, 200);
  assert.equal(out.body.kinds[0].network, "eip155:8453");
  assert.equal(out.body.daily_limit, 5);
});

test("verify is read-only and never settles", async () => {
  const exact = fakeExact();
  const out = await build(exact).handle("POST", "/verify", body);
  assert.equal(out.status, 200);
  assert.equal(out.body.isValid, true);
  assert.equal(exact.calls.settled, 0);
});

test("settle verifies first, so a doomed payment spends none of the budget", async () => {
  const exact = fakeExact({ isValid: false });
  const f = build(exact, { dailySettlements: 1 });
  const out = await f.handle("POST", "/settle", body);
  assert.equal(out.body.success, false);
  assert.equal(out.body.errorReason, "insufficient_funds");
  assert.equal(exact.calls.settled, 0, "nothing may be broadcast for a payment that cannot work");
  // The budget is untouched, so a good payment still goes through after it.
  const good = await build(fakeExact(), { dailySettlements: 1 }).handle("POST", "/settle", body);
  assert.equal(good.body.success, true);
});

test("the daily budget fails closed rather than draining the wallet", async () => {
  const f = build(fakeExact(), { dailySettlements: 2 });
  assert.equal((await f.handle("POST", "/settle", body)).status, 200);
  assert.equal((await f.handle("POST", "/settle", body)).status, 200);
  const third = await f.handle("POST", "/settle", body);
  assert.equal(third.status, 429);
  assert.equal(third.body.errorReason, "daily_budget_exhausted");
});

test("one payer cannot consume the whole allowance", async () => {
  const f = build(fakeExact(), { dailySettlements: 100, perPayerPerHour: 2 });
  await f.handle("POST", "/settle", body);
  await f.handle("POST", "/settle", body);
  const third = await f.handle("POST", "/settle", body);
  assert.equal(third.status, 429);
  assert.equal(third.body.errorReason, "payer_rate_limited");
});

test("a failed broadcast returns the allowance, an unreadable one does not", async () => {
  const failed = build(fakeExact({
    settlement: { success: false, settled: false, errorReason: "invalid_transaction_state", payer: PAYER, transaction: "", network: "eip155:8453" },
  }), { dailySettlements: 1 });
  await failed.handle("POST", "/settle", body);
  // Nothing was broadcast, so the slot is free again.
  assert.equal((await failed.handle("POST", "/settle", body)).status, 200);

  const unread = build(fakeExact({
    settlement: { success: false, settled: null, errorReason: "settlement_unconfirmed", payer: PAYER, transaction: "0xtx", network: "eip155:8453" },
  }), { dailySettlements: 1 });
  await unread.handle("POST", "/settle", body);
  // That one did cost gas, so it counts.
  assert.equal((await unread.handle("POST", "/settle", body)).status, 429);
});

test("a malformed request is refused before the verifier sees it", async () => {
  const exact = fakeExact();
  const f = build(exact);
  assert.equal((await f.handle("POST", "/verify", null)).status, 400);
  assert.equal((await f.handle("POST", "/settle", { paymentPayload: PAYLOAD })).body.errorReason, "invalid_payment_requirements");
  assert.equal(exact.calls.verified, 0);
});

test("routes that are not the facilitator's are left alone", async () => {
  const f = build(fakeExact());
  assert.equal(await f.handle("POST", "/run", body), null);
  assert.equal(await f.handle("GET", "/healthz", null), null);
});

test("the budget window rolls, so yesterday's traffic does not block today", async () => {
  let clock = 1_000_000;
  const budget = createBudget({ dailySettlements: 1, now: () => clock });
  assert.equal(budget.take(PAYER).ok, true);
  assert.equal(budget.take(PAYER).ok, false);
  clock += 86_400_001;
  assert.equal(budget.take(PAYER).ok, true);
});
