import { strict as assert } from "node:assert";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  BudgetError,
  SpendLedger,
  callCeiling,
  defaultLedgerPath,
  readBudget,
  recordSpend,
  spentInWindow,
  stripUnexpanded,
  usdg,
} from "./budget.mjs";

const MICROS = 1_000_000;

async function ledger(overrides = {}) {
  const dir = await mkdtemp(join(tmpdir(), "prism-budget-"));
  return new SpendLedger({
    ledgerPath: join(dir, "spend.json"),
    dailyMicros: 5 * MICROS,
    maxPerCallMicros: 1 * MICROS,
    lockWaitMs: 100,
    ...overrides,
  });
}

test("a missing budget is a small one, not an unlimited one", () => {
  const budget = readBudget({ HOME: "/nowhere" });
  assert.equal(budget.maxPerCallMicros, 1 * MICROS);
  assert.equal(budget.dailyMicros, 5 * MICROS);
  assert.equal(budget.ledgerPath, "/nowhere/.prism/spend.json");
});

test("PRISM_LEDGER_PATH wins over the home-directory default", () => {
  assert.equal(defaultLedgerPath({ HOME: "/h", PRISM_LEDGER_PATH: "/tmp/x.json" }), "/tmp/x.json");
});

test("a per-call cap above the daily budget is refused as a configuration error", () => {
  assert.throws(
    () => readBudget({ HOME: "/h", PRISM_MAX_USDG: "10", PRISM_DAILY_BUDGET_USDG: "5" }),
    (err) => err instanceof BudgetError && /cannot exceed/.test(err.message),
  );
});

test("a negative or unparseable budget is refused rather than coerced", () => {
  assert.throws(() => readBudget({ HOME: "/h", PRISM_DAILY_BUDGET_USDG: "-1" }), BudgetError);
  assert.throws(() => readBudget({ HOME: "/h", PRISM_MAX_USDG: "plenty" }), BudgetError);
});

test("an explicit zero removes the daily ceiling", () => {
  const budget = readBudget({ HOME: "/h", PRISM_DAILY_BUDGET_USDG: "0", PRISM_MAX_USDG: "2" });
  assert.equal(budget.dailyMicros, 0);
  assert.equal(budget.maxPerCallMicros, 2 * MICROS);
});

test("a commit is refused past the per-call cap and charges nothing", async () => {
  const book = await ledger();
  assert.throws(
    () => book.commit({ tool: "prism_lease", micros: 2 * MICROS }),
    (err) => err instanceof BudgetError && /per-call cap/.test(err.message),
  );
  assert.equal(book.remaining(), 5 * MICROS);
});

test("commits accumulate and the day's ceiling holds", async () => {
  const book = await ledger();
  for (let i = 0; i < 5; i += 1) book.commit({ tool: "prism_lease", micros: 1 * MICROS });
  assert.equal(book.remaining(), 0);
  assert.throws(
    () => book.commit({ tool: "prism_lease", micros: 1 }),
    (err) => err instanceof BudgetError && /daily cap/.test(err.message) && /5\.000000 USDG already spent/.test(err.message),
  );
});

test("the ceiling survives a restart, because a ledger that forgets is not a ceiling", async () => {
  const book = await ledger();
  for (let i = 0; i < 4; i += 1) book.commit({ tool: "prism_lease", micros: 1 * MICROS });
  const reopened = new SpendLedger({
    ledgerPath: book.path,
    dailyMicros: book.dailyMicros,
    maxPerCallMicros: book.maxPerCallMicros,
  });
  assert.equal(reopened.remaining(), 1 * MICROS);
});

test("spend older than a day falls out of the window", async () => {
  const book = await ledger();
  const now = Date.now();
  book.commit({ tool: "prism_lease", micros: 1 * MICROS, now: now - 25 * 3_600_000 });
  book.commit({ tool: "prism_lease", micros: 1 * MICROS, now });
  assert.equal(book.remaining(now), 4 * MICROS);
});

test("revert removes an attempt that provably cost nothing", async () => {
  const book = await ledger();
  const id = book.commit({ tool: "prism_infer", micros: 1 * MICROS });
  assert.equal(book.revert(id), true);
  assert.equal(book.remaining(), 5 * MICROS);
  assert.equal(book.revert(id), false, "reverting twice must not credit the wallet twice");
  assert.equal(book.revert(null), false);
});

test("settle replaces the reservation with what was actually charged", async () => {
  const book = await ledger();
  const id = book.commit({ tool: "prism_lease", micros: 1 * MICROS });
  assert.equal(book.settle(id, { micros: 222_000, reference: "0xabc" }), true);
  assert.equal(book.remaining(), 5 * MICROS - 222_000);
  const status = book.status();
  assert.equal(status.charges_last_24h[0].reference, "0xabc");
  assert.equal(status.charges_last_24h[0].amount, "0.222000 USDG");
  assert.equal(book.settle("nope", { micros: 1 }), false);
});

test("an unlimited budget still records what it spent", async () => {
  const book = await ledger({ dailyMicros: 0, maxPerCallMicros: 100 * MICROS });
  book.commit({ tool: "prism_lease", micros: 50 * MICROS });
  assert.equal(book.remaining(), null);
  const status = book.status();
  assert.match(status.daily_budget, /unlimited/);
  assert.equal(status.spent_last_24h, "50.000000 USDG");
});

test("a corrupt ledger refuses spending instead of reading as a fresh day", async () => {
  const book = await ledger();
  await writeFile(book.path, "{not json");
  assert.throws(
    () => book.commit({ tool: "prism_lease", micros: 1 }),
    (err) => err instanceof BudgetError && /unreadable/.test(err.message),
  );
});

test("the ledger file is written for this user only", async () => {
  const book = await ledger();
  book.commit({ tool: "prism_lease", micros: 1 });
  const { mode } = await import("node:fs").then((fs) => fs.promises.stat(book.path));
  assert.equal(mode & 0o777, 0o600);
  const parsed = JSON.parse(await readFile(book.path, "utf8"));
  assert.equal(parsed.version, 1);
});

test("a held lock blocks a second writer rather than losing its entry", async () => {
  const book = await ledger();
  const { writeFileSync, unlinkSync } = await import("node:fs");
  writeFileSync(`${book.path}.lock`, "");
  try {
    assert.throws(
      () => book.commit({ tool: "prism_lease", micros: 1 }),
      (err) => err instanceof BudgetError && /locked/.test(err.message),
    );
  } finally {
    unlinkSync(`${book.path}.lock`);
  }
  assert.ok(book.commit({ tool: "prism_lease", micros: 1 }));
});

test("a stale lock is broken rather than wedging the wallet forever", async () => {
  const book = await ledger();
  const { writeFileSync, utimesSync } = await import("node:fs");
  const lock = `${book.path}.lock`;
  writeFileSync(lock, "");
  const old = new Date(Date.now() - 60_000);
  utimesSync(lock, old, old);
  assert.ok(book.commit({ tool: "prism_lease", micros: 1 }));
});

test("spentInWindow and usdg render honestly", () => {
  const now = Date.now();
  assert.equal(spentInWindow([{ at: now, micros: 3 }, { at: now - 2 * 86_400_000, micros: 9 }], now), 3);
  assert.equal(usdg(222), "0.000222 USDG");
});

test("an unexpanded template reads as absent, not as a broken value", () => {
  const env = {
    PRISM_AGENT_KEY: "${user_config.agent_key}",
    PRISM_MAX_USDG: " ${user_config.max_usdg} ",
    PRISM_DAILY_BUDGET_USDG: "12",
    OTHER_VAR: "${keep.me}",
  };
  stripUnexpanded(env);
  assert.equal(env.PRISM_AGENT_KEY, undefined);
  assert.equal(env.PRISM_MAX_USDG, undefined);
  assert.equal(env.PRISM_DAILY_BUDGET_USDG, "12");
  assert.equal(env.OTHER_VAR, "${keep.me}", "only Prism's own variables are ours to clear");
  const budget = readBudget({ ...env, HOME: "/h" });
  assert.equal(budget.maxPerCallMicros, 1 * MICROS);
  assert.equal(budget.dailyMicros, 12 * MICROS);
});

test("a ledger that cannot be written does not become the caller's error", async () => {
  const book = await ledger();
  const id = book.commit({ tool: "prism_lease", micros: 1 });
  const { writeFileSync } = await import("node:fs");
  writeFileSync(`${book.path}.lock`, "");
  try {
    assert.throws(() => book.settle(id, { reference: "0xabc" }), BudgetError);
  } finally {
    await import("node:fs").then((fs) => fs.unlinkSync(`${book.path}.lock`));
  }
  assert.equal(book.settle(id, { reference: "0xabc" }), true, "it settles once the lock clears");
});

test("a call cannot raise the operator's per-call ceiling", () => {
  assert.equal(callCeiling(1000, 1 * MICROS), 1 * MICROS, "a bigger max_usdg is clamped, not honoured");
  assert.equal(callCeiling(0.25, 1 * MICROS), 250_000, "a smaller one still lowers the call");
  assert.equal(callCeiling(undefined, 1 * MICROS), 1 * MICROS, "an omitted one takes the operator's cap");
  assert.equal(callCeiling(null, 2 * MICROS), 2 * MICROS);
});

test("a max_usdg that is not a positive number is refused rather than coerced", () => {
  for (const bad of ["1", 0, -1, Number.NaN, Number.POSITIVE_INFINITY, {}]) {
    assert.throws(() => callCeiling(bad, 1 * MICROS), BudgetError, `${JSON.stringify(bad)} must not pass`);
  }
});

test("the clamped ceiling is what the day is charged, whatever the call asked for", async () => {
  const book = await ledger();
  for (let i = 0; i < 5; i += 1) book.commit({ tool: "prism_lease", micros: callCeiling(1000, book.maxPerCallMicros) });
  assert.equal(book.remaining(), 0, "five clamped leases spend the day, not five thousand USDG");
});

test("a per-call refusal names the ceiling that stopped it", async () => {
  const book = await ledger({ maxPerCallMicros: 2 * MICROS });
  assert.throws(
    () => book.commit({ tool: "prism_lease", micros: 3 * MICROS }),
    (err) => /2\.000000 USDG per-call cap/.test(err.message) && /PRISM_MAX_USDG/.test(err.message),
  );
});

test("a daily refusal names the ceiling, what is spent, and that nothing was charged", async () => {
  const book = await ledger({ maxPerCallMicros: 2 * MICROS });
  for (let i = 0; i < 2; i += 1) book.commit({ tool: "prism_lease", micros: 2 * MICROS });
  assert.throws(
    () => book.commit({ tool: "prism_infer", micros: 2 * MICROS }),
    (err) =>
      /5\.000000 USDG/.test(err.message) &&
      /4\.000000 USDG already spent/.test(err.message) &&
      /Nothing was charged/.test(err.message) &&
      /PRISM_DAILY_BUDGET_USDG/.test(err.message),
  );
  assert.equal(book.remaining(), 1 * MICROS, "the refused amount is not held against the day");
});

test("one transaction settling twice is booked once", async () => {
  const book = await ledger();
  const first = book.commit({ tool: "prism_infer", micros: 1 * MICROS });
  book.settle(first, { micros: 10_000, reference: "0xpaid" });
  // A payment the endpoint never consumed is redeemed by the next attempt, so
  // the retry reserves again and settles onto the transaction already on file.
  const retry = book.commit({ tool: "prism_infer", micros: 1 * MICROS });
  assert.equal(book.settle(retry, { micros: 10_000, reference: "0xpaid" }), true);
  assert.equal(book.remaining(), 5 * MICROS - 10_000);
  assert.equal(book.status().charges_last_24h.length, 1);
});

// The failure the ledger has to survive: viem broadcasts the transaction, then
// waiting for the receipt times out or the rpc rate-limits. The SDK reports
// that as `chain_error`, and the money is on chain either way.
class ChainError extends Error {
  constructor(body) {
    super("prism 502: chain_error");
    this.status = 502;
    this.code = "chain_error";
    this.body = body;
  }
}

test("a funded lease whose receipt never came back still spends the day", async () => {
  const book = await ledger();
  for (let i = 0; i < 4; i += 1) {
    await assert.rejects(
      recordSpend(book, "prism_lease", 1 * MICROS, async () => {
        throw new ChainError({ cause: "timed out while waiting for transaction receipt" });
      }),
      (err) => err.code === "chain_error",
    );
  }
  assert.equal(book.remaining(), 1 * MICROS, "four funded escrows left the day's ceiling untouched");
  assert.equal(book.status().charges_last_24h.length, 4);
});

test("a broadcast the SDK could name is booked against the transaction that proves it", async () => {
  const book = await ledger();
  await assert.rejects(
    recordSpend(book, "prism_infer", 1 * MICROS, async () => {
      throw new ChainError({ payment_tx: "0xbroadcast" });
    }),
    (err) => err.code === "chain_error",
  );
  assert.deepEqual(
    book.status().charges_last_24h.map((charge) => charge.reference),
    ["0xbroadcast"],
  );
});

test("a refusal that never reached the chain gives the reservation back", async () => {
  const book = await ledger();
  await assert.rejects(
    recordSpend(book, "prism_lease", 1 * MICROS, async () => {
      throw Object.assign(new Error("prism 400: image_must_be_digest_pinned"), {
        status: 400,
        code: "image_must_be_digest_pinned",
        body: { hint: "use ollama@sha256:... or DEFAULT_IMAGE" },
      });
    }),
    (err) => err.code === "image_must_be_digest_pinned",
  );
  assert.equal(book.remaining(), 5 * MICROS);
  assert.deepEqual(book.status().charges_last_24h, []);
});

test("what was served is what is charged, not what was reserved", async () => {
  const book = await ledger();
  const value = await recordSpend(book, "prism_infer", 1 * MICROS, async () => ({
    value: { response: "hello" },
    settledMicros: 12_000,
    reference: "0xserved",
  }));
  assert.deepEqual(value, { response: "hello" });
  assert.equal(book.remaining(), 5 * MICROS - 12_000);
});
