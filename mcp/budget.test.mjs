import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, lstatSync, readFileSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { test } from "node:test";

import {
  BudgetError,
  MAX_AT_MS,
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
const MODULE = new URL("./budget.mjs", import.meta.url).href;

// A second process that takes the lock and sits inside it, so the ones that
// matter here are real and not two callbacks pretending.
const HOLDER = `
import { writeFileSync } from "node:fs";
import { withLock } from ${JSON.stringify(MODULE)};
const [path, mark, hold] = process.argv.slice(1);
withLock(path, () => {
  writeFileSync(mark, "in");
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Number(hold));
}, 4000);
`;

function holder(path, mark, holdMs) {
  return spawn(process.execPath, ["--input-type=module", "-e", HOLDER, path, mark, String(holdMs)], {
    stdio: "inherit",
  });
}

// A writer that has read the ledger and not written it yet, which is the window
// a lock broken as stale takes the file out from under.
const SLOW_WRITER = `
import { writeFileSync } from "node:fs";
import { withLock, writeState } from ${JSON.stringify(MODULE)};
const [path, mark, before, after] = process.argv.slice(1);
const pause = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Number(ms));
withLock(path, () => {
  writeFileSync(mark, "read");
  pause(before);
  writeState(path, { entries: [{ id: "slow", at: Date.now(), tool: "prism_slow", micros: 250_000 }] }, Date.now());
  writeFileSync(\`\${mark}.written\`, "written");
  pause(after);
}, 4000);
`;

// The other half: a process that finds the lock too old to believe, breaks it,
// and records a charge of its own inside it.
const BREAKER = `
import { utimesSync } from "node:fs";
import { SpendLedger } from ${JSON.stringify(MODULE)};
const [path] = process.argv.slice(1);
const stale = new Date(Date.now() - 20_000);
utimesSync(\`\${path}.lock\`, stale, stale);
new SpendLedger({ ledgerPath: path, dailyMicros: 5_000_000, maxPerCallMicros: 1_000_000, lockWaitMs: 4000 })
  .commit({ tool: "prism_breaker", micros: 100_000 });
`;

function script(source, ...args) {
  const child = spawn(process.execPath, ["--input-type=module", "-e", source, ...args], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  let said = "";
  child.stderr.on("data", (chunk) => {
    said += chunk;
  });
  child.said = () => said;
  return child;
}

const exited = (child) => new Promise((resolve) => child.on("exit", resolve));

async function awaitFile(path, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const body = readFileSync(path, "latin1");
      if (body) return body;
    } catch {
      /* not there yet */
    }
    await sleep(20);
  }
  throw new Error(`${path} never appeared`);
}

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
  constructor(body, broadcast = null) {
    super("prism 502: chain_error");
    this.status = 502;
    this.code = "chain_error";
    this.body = body;
    this.broadcast = broadcast;
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
      throw new ChainError({ payment_tx: "0xbroadcast" }, "0xbroadcast");
    }),
    (err) => err.code === "chain_error",
  );
  assert.deepEqual(
    book.status().charges_last_24h.map((charge) => charge.reference),
    ["0xbroadcast"],
  );
});

test("a hash the control plane supplied is not proof that money moved", async () => {
  const book = await ledger();
  // The shape prism.mjs raises when the control plane refuses before the wallet
  // has signed anything: `body` is the far side's own JSON.
  const refused = () =>
    recordSpend(book, "prism_lease_and_run", 500_000, async () => {
      throw Object.assign(new Error("prism 503: no_capacity"), {
        status: 503,
        code: "no_capacity",
        body: { error: "no_capacity", funding_hash: "0xSERVERCHOSEN" },
      });
    });
  for (let i = 0; i < 6; i += 1) await assert.rejects(refused(), (err) => err.code === "no_capacity");
  assert.equal(book.remaining(), 5 * MICROS);
  assert.deepEqual(book.status().charges_last_24h, []);
});

test("one reference cannot swallow the charges of other tools", async () => {
  const book = await ledger();
  for (const tool of ["prism_lease", "prism_infer", "prism_batch_run"]) {
    book.settle(book.commit({ tool, micros: 400_000 }), { micros: 400_000, reference: "0xSAME" });
  }
  assert.equal(book.status().charges_last_24h.length, 3);
  assert.equal(book.remaining(), 5 * MICROS - 1_200_000);
});

test("a charge the day no longer counts is not folded into", async () => {
  const book = await ledger();
  const now = Date.now();
  const yesterday = book.commit({ tool: "prism_infer", micros: 400_000, now: now - 86_400_000 - 1000 });
  book.settle(yesterday, { micros: 400_000, reference: "0xpaid" });
  book.settle(book.commit({ tool: "prism_infer", micros: 400_000, now }), { micros: 400_000, reference: "0xpaid" });
  assert.equal(JSON.parse(await readFile(book.path, "utf8")).entries.length, 2, "yesterday's charge is still on file");
  assert.equal(book.status().charges_last_24h.length, 1);
  assert.equal(book.remaining(), 5 * MICROS - 400_000);
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

test("an answer that is not an object keeps the entry and says why", async () => {
  const book = await ledger();
  // An array is an object to typeof and carries neither a settled figure nor a
  // reference, so reading one as an outcome would book the reservation as
  // settled and hand the caller undefined. Python refuses the same shape.
  for (const outcome of ["ok", 7, null, undefined, [], [{ value: 1 }]]) {
    await assert.rejects(
      recordSpend(book, "prism_infer", 100_000, async () => outcome),
      (err) => err instanceof BudgetError && /the ledger needs an object/.test(err.message),
    );
  }
  assert.equal(book.remaining(), 5 * MICROS - 600_000, "the money moved, so the reservations stand");
});

test("json that parses but is not a ledger refuses spending", async () => {
  const book = await ledger();
  for (const text of ["null", "[]", "0", '"x"', '{"version": 1}', '{"entries": {}}', '{"entries": "5"}']) {
    await writeFile(book.path, text);
    assert.throws(
      () => book.remaining(),
      (err) => err instanceof BudgetError && /so spending is refused/.test(err.message),
      text,
    );
  }
});

test("an entry that cannot be type-checked refuses the file rather than being dropped", async () => {
  const book = await ledger();
  const bad = ['"x"', "null", '{"at": "now", "micros": 1}', '{"at": 1, "micros": "1"}', '{"at": 1}',
    '{"at": 1, "micros": -5}', '{"at": -1, "micros": 5}', '{"at": 1, "micros": true}'];
  for (const entry of bad) {
    await writeFile(book.path, `{"entries": [${entry}]}`);
    assert.throws(() => book.remaining(), BudgetError, entry);
  }
});

test("bytes that are not utf-8 are refused rather than patched up", async () => {
  const book = await ledger();
  await writeFile(book.path, Buffer.from('{"entries": [{"at": 1, "micros": 1, "tool": "\xff\xfe"}]}', "latin1"));
  assert.throws(() => book.remaining(), BudgetError);
});

test("a byte order mark is a ledger and not a corruption", async () => {
  const book = await ledger();
  const body = JSON.stringify({ version: 1, entries: [{ id: "a", at: Date.now(), tool: "prism_lease", micros: 400_000 }] });
  await writeFile(book.path, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(body, "utf8")]));
  assert.equal(book.remaining(), 5 * MICROS - 400_000);
  assert.equal(book.status().spent_last_24h, "0.400000 USDG");
});

test("a stamp no date can hold refuses the file, and the last one a date can hold does not", async () => {
  const book = await ledger();
  for (const at of [2.6e14, MAX_AT_MS + 1]) {
    await writeFile(book.path, `{"entries": [{"at": ${at}, "micros": 1}]}`);
    assert.throws(() => book.status(), /an at a date can hold/, String(at));
  }
  await writeFile(book.path, `{"entries": [{"at": ${MAX_AT_MS}, "micros": 1}]}`);
  assert.equal(book.status(MAX_AT_MS).charges_last_24h[0].at, "9999-12-31T23:59:59.999Z");
});

test("a clock that is not milliseconds is refused before the file is touched", async () => {
  const book = await ledger();
  // Date.now() * 1e6 where the ledger wanted milliseconds. Written through, it
  // would date an entry past year 9999: unprintable on one side and unprunable
  // on both, for good.
  for (const now of [Date.now() * 1e6, MAX_AT_MS + 1, -1, Number.NaN]) {
    assert.throws(
      () => book.commit({ tool: "prism_lease", micros: 400_000, now }),
      /milliseconds since the epoch/,
      String(now),
    );
  }
  assert.equal(existsSync(book.path), false);
});

test("a settlement above the reservation is refused, because the reservation is the ceiling", async () => {
  const book = await ledger();
  const id = book.commit({ tool: "prism_lease", micros: 400_000 });
  assert.equal(book.settle(id, { micros: 900_000, reference: "0xtx" }), true);
  assert.equal(book.remaining(), 5 * MICROS - 400_000);
  assert.equal(book.status().charges_last_24h[0].reference, "0xtx");
});

test("one number grammar for both languages", () => {
  // Number() reads the first as 16 and Python's float() reads the second as
  // 1000, and one ledger cannot have two grammars.
  // "٣" is a 3 to Python's float() and nothing to Number(); "﻿" is
  // padding to trim() and a character to Python's strip(). Both are refused
  // here so neither language reads a figure the other cannot.
  for (const bad of ["0x10", "1_000", "1e", "1,5", "0b1", "infinity", "1 2", "\u0663", "\ufeff2", "2\u00a0", "\u001c2"]) {
    assert.throws(() => readBudget({ HOME: "/h", PRISM_DAILY_BUDGET_USDG: bad }), BudgetError, bad);
  }
  for (const [good, micros] of [[" 2 ", 2 * MICROS], ["2.", 2 * MICROS], [".5", 500_000], ["2e0", 2 * MICROS]]) {
    assert.equal(readBudget({ HOME: "/h", PRISM_MAX_USDG: good, PRISM_DAILY_BUDGET_USDG: "9" }).maxPerCallMicros, micros);
  }
});

test("a ceiling too large to multiply is refused rather than silently clamped", () => {
  assert.throws(
    () => callCeiling(1e308, 1 * MICROS),
    (err) => err instanceof BudgetError && err.message === "max_usdg must be at most 1000000000000 USDG.",
  );
  assert.equal(callCeiling(1e12, 1 * MICROS), 1 * MICROS);
});

test("a temp file left behind by anyone else cannot lend the ledger its permissions", async () => {
  const book = await ledger();
  const tmp = `${book.path}.${process.pid}.tmp`;
  writeFileSync(tmp, "stale");
  chmodSync(tmp, 0o666);
  book.commit({ tool: "prism_lease", micros: 1 });
  assert.equal(statSync(book.path).mode & 0o777, 0o600);
  assert.equal(existsSync(tmp), false);
});

test("a symlinked ledger is written through rather than replaced", async () => {
  const book = await ledger();
  const real = join(await mkdtemp(join(tmpdir(), "prism-real-")), "spend.json");
  writeFileSync(real, '{"version": 1, "entries": []}\n');
  symlinkSync(real, book.path);
  book.commit({ tool: "prism_lease", micros: 400_000 });
  assert.equal(statSync(book.path, { bigint: false }).isFile(), true);
  assert.equal(JSON.parse(readFileSync(real, "utf8")).entries[0].micros, 400_000);
});

test("a symlinked ledger whose target is not there yet is created through the link", async () => {
  const book = await ledger();
  const real = join(await mkdtemp(join(tmpdir(), "prism-real-")), "spend.json");
  symlinkSync(real, book.path);
  book.commit({ tool: "prism_lease", micros: 400_000 });
  assert.equal(lstatSync(book.path).isSymbolicLink(), true, "the first write replaced the link with a file");
  assert.equal(JSON.parse(readFileSync(real, "utf8")).entries[0].micros, 400_000);
});

test("an entry id is not a number a caller sharing the file can reproduce", async () => {
  const book = await ledger({ dailyMicros: 0 });
  const ids = new Set();
  for (let i = 0; i < 200; i += 1) {
    const id = book.commit({ tool: "prism_lease", micros: 1 });
    assert.match(id, /^[0-9a-z]+-[0-9a-f]{16}$/, id);
    ids.add(id);
  }
  assert.equal(ids.size, 200);
});

test("status leaves out a tool the entry never had", async () => {
  const book = await ledger();
  const at = Date.parse("2025-08-24T01:46:40.000Z");
  await writeFile(book.path, JSON.stringify({ version: 1, entries: [{ id: "x", at, micros: 5 }] }));
  assert.deepEqual(book.status(at).charges_last_24h, [{ at: "2025-08-24T01:46:40.000Z", amount: "0.000005 USDG" }]);
});

// The clock stepping forward past LOCK_STALE_MS is enough to make a live lock
// look abandoned, and before the token the holder came back and deleted the
// lock its breaker was working under.
test("a holder never deletes the lock that broke it", async () => {
  const book = await ledger({ lockWaitMs: 100 });
  const lock = `${book.path}.lock`;
  const first = holder(book.path, `${book.path}.a`, 2000);
  const mine = await awaitFile(lock);

  const stale = new Date(Date.now() - 60_000);
  utimesSync(lock, stale, stale);
  const second = holder(book.path, `${book.path}.b`, 6000);
  await awaitFile(`${book.path}.b`);
  const theirs = readFileSync(lock, "latin1");
  assert.notEqual(theirs, mine, "the breaker took the lock without claiming it");

  assert.equal(await exited(first), 0);
  assert.equal(readFileSync(lock, "latin1"), theirs, "the holder deleted a lock it did not own");
  assert.throws(() => book.commit({ tool: "prism_lease", micros: 1 }), BudgetError);

  assert.equal(await exited(second), 0);
  assert.equal(existsSync(lock), false, "the owner left its lock behind");
});

// Both halves of what keeps two writers out of one file once a lock has been
// broken: a live holder refreshes its lock as it writes, and a write whose lock
// changed hands anyway is abandoned rather than published.
test("a lock is refreshed as it is written, so a slow write is not read as abandoned", async () => {
  const book = await ledger();
  const lock = `${book.path}.lock`;
  const slow = script(SLOW_WRITER, book.path, `${book.path}.read`, "500", "2000");
  await awaitFile(`${book.path}.read`);
  const stale = new Date(Date.now() - 60_000);
  utimesSync(lock, stale, stale);

  await awaitFile(`${book.path}.read.written`);
  assert.ok(Date.now() - statSync(lock).mtimeMs < 15_000, "a live holder's lock aged into staleness");
  assert.equal(await exited(slow), 0);
});

test("a write whose lock was broken under it is refused rather than erasing the charge that took it", async () => {
  const book = await ledger();
  const slow = script(SLOW_WRITER, book.path, `${book.path}.read`, "3000", "0");
  await awaitFile(`${book.path}.read`);
  const breaker = script(BREAKER, book.path);

  assert.equal(await exited(breaker), 0, breaker.said());
  assert.notEqual(await exited(slow), 0, "the slower write published under a lock it no longer held");
  assert.match(slow.said(), /lost the ledger lock; nothing written/);
  assert.equal(existsSync(`${book.path}.read.written`), false);
  assert.deepEqual(
    JSON.parse(readFileSync(book.path, "utf8")).entries.map((e) => e.micros),
    [100_000],
    "the slower write erased the charge of the process that broke its lock",
  );
});

test("two processes cannot both be inside the ledger", async () => {
  const book = await ledger({ lockWaitMs: 100 });
  const held = holder(book.path, `${book.path}.a`, 1500);
  await awaitFile(`${book.path}.a`);
  assert.throws(() => book.commit({ tool: "prism_lease", micros: 1 }), BudgetError);
  assert.equal(await exited(held), 0);
  assert.ok(book.commit({ tool: "prism_lease", micros: 1 }));
});

// A link is how one wallet's ledger ends up configured under two names, and a
// lock named after the caller's spelling would let both names inside the file at
// once. Each would have read the day's total before the other's charge existed,
// and the one that wrote second would erase it.
test("one ledger reached by two names is one lock", async () => {
  const book = await ledger({ lockWaitMs: 100 });
  const target = join(await mkdtemp(join(tmpdir(), "prism-real-")), "spend.json");
  symlinkSync(target, book.path);
  const other = new SpendLedger({
    ledgerPath: target,
    dailyMicros: 5 * MICROS,
    maxPerCallMicros: 1 * MICROS,
    lockWaitMs: 100,
  });

  const held = holder(book.path, `${book.path}.a`, 1500);
  await awaitFile(`${book.path}.a`);
  assert.throws(() => other.commit({ tool: "prism_lease", micros: 1 }), BudgetError);
  assert.equal(await exited(held), 0);
  assert.ok(other.commit({ tool: "prism_lease", micros: 1 }));
});
