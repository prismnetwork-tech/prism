// The facilitator half of x402: verify and settle on someone else's behalf.
//
// The free public facilitators are testnet-only. Coinbase's settles Base
// mainnet but wants an API key and does not know Robinhood Chain, which is
// where our leases settle, so we run our own. This is the same verifier Prism
// uses for its own endpoints, exposed at the routes the spec defines.
//
// Settling for a stranger means broadcasting a transaction and paying its gas,
// which is the whole cost of the service and the whole abuse surface. Verify is
// read-only and free; settle is metered against a budget that fails closed.

const MAX_BODY_BYTES = 32 * 1024;

/**
 * A gas budget with a rolling daily window. Settling costs real ETH, so an open
 * endpoint without one is an invitation to drain the wallet; refusing politely
 * once the day's allowance is gone beats an empty wallet and a silent outage.
 */
export function createBudget({ dailySettlements = 2_000, perPayerPerHour = 60, now = () => Date.now() }) {
  let dayStarted = now();
  let spentToday = 0;
  const perPayer = new Map();

  function roll() {
    if (now() - dayStarted >= 86_400_000) {
      dayStarted = now();
      spentToday = 0;
      perPayer.clear();
    }
  }

  return {
    /// Checked before broadcasting, never after: a refusal must cost nothing.
    take(payer) {
      roll();
      if (spentToday >= dailySettlements) return { ok: false, reason: "daily_budget_exhausted" };
      const key = String(payer ?? "").toLowerCase();
      const seen = perPayer.get(key) ?? [];
      const hourAgo = now() - 3_600_000;
      const recent = seen.filter((t) => t > hourAgo);
      if (recent.length >= perPayerPerHour) return { ok: false, reason: "payer_rate_limited" };
      recent.push(now());
      perPayer.set(key, recent);
      spentToday += 1;
      return { ok: true };
    },
    /// Handing back an unused allowance keeps a failed broadcast from counting
    /// against a caller who got nothing for it.
    refund(payer) {
      spentToday = Math.max(0, spentToday - 1);
      const key = String(payer ?? "").toLowerCase();
      const seen = perPayer.get(key);
      if (seen?.length) seen.pop();
    },
    state() {
      roll();
      return { settlements_today: spentToday, daily_limit: dailySettlements, per_payer_hourly_limit: perPayerPerHour };
    },
  };
}

/**
 * Routes for the facilitator interface. Returns null when the request is not
 * one of ours, so a server can mount this alongside its own endpoints.
 */
export function createFacilitator({ exact, budget, log = () => {} }) {
  async function handle(method, path, body) {
    if (method === "GET" && path === "/supported") {
      return { status: 200, body: { ...exact.supported(), ...budget.state() } };
    }

    if (method === "POST" && path === "/verify") {
      const parsed = read(body);
      if (!parsed.ok) return { status: 400, body: { isValid: false, invalidReason: parsed.reason } };
      const verdict = await exact.verify(parsed.paymentPayload, parsed.paymentRequirements);
      return { status: 200, body: verdict };
    }

    if (method === "POST" && path === "/settle") {
      const parsed = read(body);
      if (!parsed.ok) {
        return { status: 400, body: { success: false, errorReason: parsed.reason, transaction: "", network: "" } };
      }
      // Verify first and separately, so a payment that was never going to work
      // is refused without spending any of the budget on it.
      const verdict = await exact.verify(parsed.paymentPayload, parsed.paymentRequirements);
      if (!verdict.isValid) {
        return {
          status: 200,
          body: {
            success: false,
            errorReason: verdict.invalidReason,
            payer: verdict.payer ?? "",
            transaction: "",
            network: parsed.paymentRequirements?.network ?? "",
          },
        };
      }
      const allowed = budget.take(verdict.payer);
      if (!allowed.ok) {
        return {
          status: 429,
          body: {
            success: false,
            errorReason: allowed.reason,
            payer: verdict.payer,
            transaction: "",
            network: parsed.paymentRequirements?.network ?? "",
          },
        };
      }
      const settlement = await exact.settle(parsed.paymentPayload, parsed.paymentRequirements);
      // `settled === null` means it was broadcast and could not be read, which
      // did cost gas, so only an outright failure returns the allowance.
      if (settlement.settled === false) budget.refund(verdict.payer);
      log(`settle ${settlement.success ? "ok" : settlement.errorReason} payer=${verdict.payer} tx=${settlement.transaction || "none"}`);
      return { status: 200, body: settlement };
    }

    return null;
  }

  return { handle };
}

function read(body) {
  if (!body || typeof body !== "object") return { ok: false, reason: "invalid_payload" };
  const { paymentPayload, paymentRequirements } = body;
  if (!paymentPayload || typeof paymentPayload !== "object") return { ok: false, reason: "invalid_payload" };
  if (!paymentRequirements || typeof paymentRequirements !== "object") {
    return { ok: false, reason: "invalid_payment_requirements" };
  }
  return { ok: true, paymentPayload, paymentRequirements };
}

export { MAX_BODY_BYTES };
