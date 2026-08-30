// What stands between a model deciding to rent a GPU and a wallet paying for it.
// The real ceiling is the balance; fund the agent wallet with what you are
// willing to lose. This is the second line, and it exists because `max_usdg`
// never was one: it bounds a single lease and says nothing about the fortieth in
// a row, which is what an unattended agent actually does.
//
// Spend is written before the money moves and reverted only when the attempt
// provably cost nothing, so a crash between funding and reply is counted rather
// than forgiven. The file is shared across clients on purpose: one wallet gets
// one daily ceiling whoever is holding it.
import { mkdirSync, readFileSync, renameSync, writeFileSync, openSync, closeSync, unlinkSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

const MICROS = 1_000_000;
const DAY_MS = 86_400_000;
// Entries older than this are dropped on write. Two days covers the rolling
// window with room for a clock that stepped backwards.
const MEMORY_MS = 2 * DAY_MS;
const LOCK_STALE_MS = 15_000;
const LOCK_WAIT_MS = 5_000;

export class BudgetError extends Error {
  constructor(message, detail = {}) {
    super(message);
    this.name = "BudgetError";
    this.detail = detail;
  }
}

export const usdg = (micros) => `${(Number(micros) / MICROS).toFixed(6)} USDG`;

function positiveNumber(raw, fallback, name) {
  if (raw === undefined || raw === null || String(raw).trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    throw new BudgetError(`${name} must be a non-negative number of USDG, got ${JSON.stringify(raw)}`);
  }
  return value;
}

// One .mcp.json serves every client, and they disagree about templates: Claude
// Code expands ${user_config.x} before launch, Codex passes it through. Reading
// the literal template as a value would turn "no wallet configured" into
// "wallet configured and broken", so an unexpanded placeholder is nothing.
export function stripUnexpanded(env = process.env) {
  for (const [key, value] of Object.entries(env)) {
    if (key.startsWith("PRISM_") && /^\$\{[^}]*\}$/.test(String(value ?? "").trim())) delete env[key];
  }
  return env;
}

export function defaultLedgerPath(env = process.env) {
  if (env.PRISM_LEDGER_PATH) return env.PRISM_LEDGER_PATH;
  return join(env.HOME || homedir(), ".prism", "spend.json");
}

// A missing budget is not an unlimited one. The default is deliberately small:
// enough for a handful of real leases, cheap enough that discovering the plugin
// spends money costs about the price of a coffee rather than a rent cheque.
export function readBudget(env = process.env) {
  const maxPerCall = positiveNumber(env.PRISM_MAX_USDG, 1, "PRISM_MAX_USDG");
  const daily = positiveNumber(env.PRISM_DAILY_BUDGET_USDG, 5, "PRISM_DAILY_BUDGET_USDG");
  if (maxPerCall <= 0) throw new BudgetError("PRISM_MAX_USDG must be above zero");
  // A per-call cap above the day's allowance is a cap in name only, and the
  // mismatch is always a configuration mistake rather than an intention.
  if (daily > 0 && maxPerCall > daily) {
    throw new BudgetError(
      `PRISM_MAX_USDG (${maxPerCall}) cannot exceed PRISM_DAILY_BUDGET_USDG (${daily}); lower the per-call cap or raise the daily one`,
    );
  }
  return {
    maxPerCallMicros: Math.round(maxPerCall * MICROS),
    // Zero means the operator explicitly removed the daily ceiling. It is not
    // the default and it is not what a missing variable produces.
    dailyMicros: Math.round(daily * MICROS),
    ledgerPath: defaultLedgerPath(env),
  };
}

// What a single call is allowed to spend, given what it asked for. The caller's
// figure is written by the thing being bounded, so it lowers the operator's
// ceiling and can never lift it.
export function callCeiling(maxUsdg, ceilingMicros) {
  if (maxUsdg === undefined || maxUsdg === null) return ceilingMicros;
  if (typeof maxUsdg !== "number" || !Number.isFinite(maxUsdg) || maxUsdg <= 0) {
    throw new BudgetError("max_usdg must be a positive number of USDG.");
  }
  return Math.min(Math.round(maxUsdg * MICROS), ceilingMicros);
}

// A lock rather than last-write-wins, because two clients sharing one wallet is
// the case this file exists for. A lock older than LOCK_STALE_MS belonged to a
// process that died; breaking it is safe and not breaking it wedges the wallet.
function withLock(path, fn, waitMs = LOCK_WAIT_MS) {
  const lock = `${path}.lock`;
  mkdirSync(dirname(path), { recursive: true });
  const deadline = Date.now() + waitMs;
  for (;;) {
    let fd;
    try {
      fd = openSync(lock, "wx");
    } catch (err) {
      if (err?.code !== "EEXIST") throw err;
      let age = 0;
      try {
        age = Date.now() - statSync(lock).mtimeMs;
      } catch {
        continue; // it vanished between the open and the stat; retry immediately
      }
      if (age > LOCK_STALE_MS) {
        try {
          unlinkSync(lock);
        } catch {
          /* another process broke it first, which is the outcome we wanted */
        }
        continue;
      }
      if (Date.now() > deadline) {
        throw new BudgetError(
          `the spend ledger at ${path} is locked by another Prism process; nothing was charged. Retry in a moment.`,
        );
      }
      // Busy-wait deliberately: this holds for milliseconds and the alternative
      // is making every caller of a synchronous ledger asynchronous.
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
      continue;
    }
    try {
      closeSync(fd);
      return fn();
    } finally {
      try {
        unlinkSync(lock);
      } catch {
        /* already gone */
      }
    }
  }
}

function readState(path) {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    if (!parsed || !Array.isArray(parsed.entries)) return { entries: [] };
    return { entries: parsed.entries.filter((e) => e && Number.isFinite(e.at) && Number.isFinite(e.micros)) };
  } catch (err) {
    if (err?.code === "ENOENT") return { entries: [] };
    // A corrupt ledger must not read as an empty one: that would hand the
    // caller a fresh day's budget every time the file got truncated.
    throw new BudgetError(
      `the spend ledger at ${path} is unreadable (${err?.message ?? err}), so spending is refused. Move or repair the file.`,
    );
  }
}

function writeState(path, state, now) {
  const entries = state.entries.filter((e) => now - e.at < MEMORY_MS);
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify({ version: 1, entries }, null, 2)}\n`, { mode: 0o600 });
  renameSync(tmp, path);
}

export function spentInWindow(entries, now) {
  return entries.reduce((total, e) => (now - e.at < DAY_MS ? total + e.micros : total), 0);
}

export class SpendLedger {
  constructor({ ledgerPath, dailyMicros, maxPerCallMicros, lockWaitMs = LOCK_WAIT_MS }) {
    this.path = ledgerPath;
    this.dailyMicros = dailyMicros;
    this.maxPerCallMicros = maxPerCallMicros;
    this.lockWaitMs = lockWaitMs;
  }

  // What is left of today, for the caller to show before it asks to spend.
  remaining(now = Date.now()) {
    if (this.dailyMicros <= 0) return null;
    const { entries } = readState(this.path);
    return Math.max(0, this.dailyMicros - spentInWindow(entries, now));
  }

  status(now = Date.now()) {
    const { entries } = readState(this.path);
    const spent = spentInWindow(entries, now);
    return {
      daily_budget: this.dailyMicros > 0 ? usdg(this.dailyMicros) : "unlimited (PRISM_DAILY_BUDGET_USDG=0)",
      spent_last_24h: usdg(spent),
      remaining_today: this.dailyMicros > 0 ? usdg(Math.max(0, this.dailyMicros - spent)) : "unlimited",
      max_per_call: usdg(this.maxPerCallMicros),
      ledger: this.path,
      charges_last_24h: entries
        .filter((e) => now - e.at < DAY_MS)
        .sort((a, b) => b.at - a.at)
        .slice(0, 20)
        .map((e) => ({
          at: new Date(e.at).toISOString(),
          tool: e.tool,
          amount: usdg(e.micros),
          ...(e.reference ? { reference: e.reference } : {}),
        })),
    };
  }

  // Records the spend before the money moves. Returns a handle the caller
  // reverts only when it can prove nothing was charged.
  commit({ tool, micros, now = Date.now() }) {
    if (!Number.isFinite(micros) || micros <= 0) {
      throw new BudgetError("a spend must be a positive number of micros");
    }
    if (micros > this.maxPerCallMicros) {
      throw new BudgetError(
        `${tool} would commit up to ${usdg(micros)}, past the ${usdg(this.maxPerCallMicros)} per-call cap. ` +
          `Lower max_usdg for this call, or raise PRISM_MAX_USDG.`,
        { required: micros, cap: this.maxPerCallMicros },
      );
    }
    return withLock(
      this.path,
      () => {
        const state = readState(this.path);
        const spent = spentInWindow(state.entries, now);
        if (this.dailyMicros > 0 && spent + micros > this.dailyMicros) {
          throw new BudgetError(
            `${tool} would take today's Prism spend to ${usdg(spent + micros)}, past the ${usdg(this.dailyMicros)} ` +
              `daily cap (${usdg(spent)} already spent). Nothing was charged. Raise PRISM_DAILY_BUDGET_USDG to continue.`,
            { spent, requested: micros, cap: this.dailyMicros },
          );
        }
        const id = `${now.toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
        state.entries.push({ id, at: now, tool, micros });
        writeState(this.path, state, now);
        return id;
      },
      this.lockWaitMs,
    );
  }

  // Only for an attempt that provably cost nothing. A funded lease whose command
  // failed is not one of those.
  revert(id) {
    if (!id) return false;
    return withLock(this.path, () => {
      const state = readState(this.path);
      const before = state.entries.length;
      state.entries = state.entries.filter((e) => e.id !== id);
      if (state.entries.length === before) return false;
      writeState(this.path, state, Date.now());
      return true;
    }, this.lockWaitMs);
  }

  // Replaces the reserved figure with what was actually committed on-chain and
  // pins the receipt to it, so the ledger reads like a statement rather than a
  // list of intentions.
  //
  // A payment the endpoint never consumed is redeemed by the next attempt at the
  // same request, so one transaction can settle more than one reservation.
  // Booking each would charge the day twice for money that moved once: a
  // reference already on file keeps its entry and this one is released.
  settle(id, { micros, reference } = {}) {
    if (!id) return false;
    return withLock(this.path, () => {
      const state = readState(this.path);
      const entry = state.entries.find((e) => e.id === id);
      if (!entry) return false;
      const booked = reference ? state.entries.find((e) => e.id !== id && e.reference === reference) : undefined;
      const target = booked ?? entry;
      if (Number.isFinite(micros) && micros >= 0) target.micros = micros;
      if (reference) target.reference = reference;
      if (booked) state.entries = state.entries.filter((e) => e.id !== id);
      writeState(this.path, state, Date.now());
      return true;
    }, this.lockWaitMs);
  }
}

/// Records a spend before the money moves, then reconciles it against what
/// happened. A failure that never reached the chain is given back; anything
/// that funded an escrow or paid an endpoint keeps its entry and gains the
/// transaction that proves it, because a ledger that forgets a spend is worse
/// than no ledger at all.
export async function recordSpend(book, tool, micros, run) {
  const id = book.commit({ tool, micros });
  // Reconciling is bookkeeping and must never be the reason a caller loses a
  // machine it paid for, or the reason a failure is reported as the wrong
  // failure. A ledger that cannot be written says so on stderr and the
  // committed figure stands, which errs towards counting the spend.
  const reconcile = (action, ...args) => {
    try {
      book[action](id, ...args);
    } catch (err) {
      console.error(`prism mcp: could not ${action} the ledger entry for ${tool}: ${err?.message ?? err}`);
    }
  };
  try {
    const { value, settledMicros, reference } = await run();
    reconcile("settle", { micros: settledMicros, reference });
    return value;
  } catch (err) {
    const paid = err?.body?.funding_hash ?? err?.body?.payment_tx;
    if (paid) {
      reconcile("settle", { reference: paid });
    } else if (err?.code === "chain_error") {
      // Signed, broadcast, and then something went wrong reading it back, which
      // is not the same as never having reached the chain. Handing the
      // reservation back would let one wallet fund escrow after escrow through
      // an rpc having a bad hour while the day's ceiling reported nothing
      // spent, so the entry stands at what it reserved.
      reconcile("settle");
    } else {
      reconcile("revert");
    }
    throw err;
  }
}
