// What stands between a model deciding to rent a GPU and a wallet paying for it.
// The real ceiling is the balance; fund the agent wallet with what you are
// willing to lose. This is the second line, and it exists because `max_usdg`
// never was one: it bounds a single lease and says nothing about the fortieth in
// a row, which is what an unattended agent actually does.
//
// Spend is written before the money moves and reverted only when the attempt
// provably cost nothing, so a crash between funding and reply is counted rather
// than forgiven. The file is shared across clients on purpose: one wallet gets
// one daily ceiling whoever is holding it, and the Python SDK's `_budget.py`
// reads and writes the same entries this module does.
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

const MICROS = 1_000_000;
const DAY_MS = 86_400_000;
// Entries older than this are dropped on write. Two days covers the rolling
// window with room for a clock that stepped backwards.
const MEMORY_MS = 2 * DAY_MS;
const LOCK_STALE_MS = 15_000;
const LOCK_WAIT_MS = 5_000;
// Above this a USDG figure is a typo or an attack, and multiplying it out is how
// the arithmetic stops being arithmetic.
const MAX_CALL_USDG = 1e12;
// The last instant both languages can name: Python's datetime stops at year
// 9999 where this one keeps going, so a stamp past this is one only this client
// could print, and it would sit in the file forever.
export const MAX_AT_MS = 253_402_300_799_999;
// One number grammar for both languages. Node's Number() takes "0x10" and
// Python's float() takes "1_000", and an operator who typed either meant
// neither. \d is ASCII here and every decimal digit there is in Python, so the
// range is spelled out: Python reads "٣" as a 3 and no ledger should.
const DECIMAL = /^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$/;
// The two languages also disagree about what padding is: trim() takes U+FEFF
// where Python's strip does not, and Python's takes U+001C where trim() does
// not. Trimming these four leaves one answer on both sides.
const PADDING = new Set([" ", "\t", "\r", "\n"]);

function trim(value) {
  const text = String(value);
  let start = 0;
  let end = text.length;
  while (start < end && PADDING.has(text[start])) start += 1;
  while (end > start && PADDING.has(text[end - 1])) end -= 1;
  return text.slice(start, end);
}

export class BudgetError extends Error {
  constructor(message, detail = {}) {
    super(message);
    this.name = "BudgetError";
    this.detail = detail;
  }
}

export const usdg = (micros) => `${(Number(micros) / MICROS).toFixed(6)} USDG`;

const isAmount = (value) => typeof value === "number" && Number.isFinite(value) && value >= 0;

const isStamp = (value) => isAmount(value) && value <= MAX_AT_MS;

function positiveNumber(raw, fallback, name) {
  const text = raw === undefined || raw === null ? "" : trim(raw);
  if (text === "") return fallback;
  const value = DECIMAL.test(text) ? Number(text) : Number.NaN;
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
    if (key.startsWith("PRISM_") && /^\$\{[^}]*\}$/.test(trim(value ?? ""))) delete env[key];
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
  // Checked before the multiplication, because that is where a figure this size
  // stops being a number.
  if (maxUsdg > MAX_CALL_USDG) throw new BudgetError(`max_usdg must be at most ${MAX_CALL_USDG} USDG.`);
  return Math.min(Math.round(maxUsdg * MICROS), ceilingMicros);
}

function lockOwner(lock) {
  try {
    return readFileSync(lock, "latin1").slice(0, 128);
  } catch {
    return null;
  }
}

// A holder whose lock was broken as stale must not delete the lock its breaker
// now holds, which is how two processes end up inside the ledger at once.
function release(lock, token) {
  if (lockOwner(lock) !== token) return;
  try {
    unlinkSync(lock);
  } catch {
    /* already gone */
  }
}

// The lock this process is writing under, so the write itself can keep it alive
// and refuse to publish under someone else's. A timer would do it in Python,
// where the heartbeat runs on a thread; here the whole ledger is synchronous,
// so nothing on this loop could fire between taking the lock and writing.
let writing = null;

function touch(lock, token) {
  // Refreshing a lock that was broken and retaken would be this process
  // vouching for a lock it does not hold.
  if (lockOwner(lock) !== token) return;
  const stamp = new Date();
  try {
    utimesSync(lock, stamp, stamp);
  } catch {
    /* it went while we were looking at it */
  }
}

const keepLock = () => writing && touch(writing.lock, writing.token);

const holdingLock = () => writing === null || lockOwner(writing.lock) === writing.token;

// A lock rather than last-write-wins, because two clients sharing one wallet is
// the case this file exists for. A holder refreshes its lock as it writes, so a
// lock older than LOCK_STALE_MS belonged to a process that died; breaking it is
// safe and not breaking it wedges the wallet. A break that happens anyway,
// because a machine slept or a clock stepped, is caught at the write.
//
// Exported because the tests that matter here need two real processes inside it.
export function withLock(path, fn, waitMs = LOCK_WAIT_MS) {
  mkdirSync(dirname(path), { recursive: true });
  // The lock names the file the write lands on rather than the name the caller
  // spelled. One client reaching the ledger through a link and another through
  // its target would otherwise hold two different locks over one file, and each
  // would publish a state read before the other's charge existed.
  const lock = `${resolveTarget(path)}.lock`;
  const deadline = Date.now() + waitMs;
  const token = `${process.pid}-${randomBytes(8).toString("hex")}`;
  for (;;) {
    let fd;
    try {
      fd = openSync(lock, "wx", 0o600);
    } catch (err) {
      if (err?.code !== "EEXIST") throw err;
      const held = lockOwner(lock);
      let age = 0;
      try {
        age = Date.now() - statSync(lock).mtimeMs;
      } catch {
        continue; // it vanished between the open and the stat; retry immediately
      }
      if (age > LOCK_STALE_MS) {
        // Break the lock that was read as stale and no other: re-reading the
        // token keeps a slow breaker from deleting a lock a third process took
        // in the meantime.
        if (lockOwner(lock) === held) {
          try {
            unlinkSync(lock);
          } catch {
            /* another process broke it first, which is the outcome we wanted */
          }
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
      writeSync(fd, token);
      fsyncSync(fd);
    } catch (err) {
      closeSync(fd);
      release(lock, token);
      throw err;
    }
    closeSync(fd);
    const outer = writing;
    writing = { lock, token };
    try {
      return fn();
    } finally {
      writing = outer;
      release(lock, token);
    }
  }
}

const unreadable = (path, reason) =>
  new BudgetError(`the spend ledger at ${path} is unreadable (${reason}), so spending is refused. Move or repair the file.`);

function readState(path) {
  let raw;
  try {
    raw = readFileSync(path);
  } catch (err) {
    if (err?.code === "ENOENT") return { entries: [] };
    throw unreadable(path, err?.message ?? err);
  }
  let parsed;
  try {
    // Invalid UTF-8 is refused rather than patched up with replacement
    // characters, because the bytes a ledger cannot read are the bytes it must
    // not spend against.
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch (err) {
    // A corrupt ledger must not read as an empty one: that would hand the
    // caller a fresh day's budget every time the file got truncated.
    throw unreadable(path, err?.message ?? err);
  }
  const entries = parsed && typeof parsed === "object" ? parsed.entries : undefined;
  if (!Array.isArray(entries)) throw unreadable(path, "it holds no list of entries");
  // Dropping the entries that fail this check would be the corrupt-reads-as-
  // empty bug again, one charge at a time.
  for (const entry of entries) {
    if (!entry || typeof entry !== "object" || !isStamp(entry.at) || !isAmount(entry.micros)) {
      throw unreadable(path, "an entry is not a charge with non-negative micros and an at a date can hold");
    }
  }
  return { entries };
}

// The entry is written before the money moves, so it has to survive the crash
// that lands between the two.
function fsyncDir(directory) {
  let fd;
  try {
    fd = openSync(directory, "r");
  } catch {
    return; // not every platform lets a directory be opened, and the rename is still ordered
  }
  try {
    fsyncSync(fd);
  } catch {
    /* some filesystems refuse it */
  } finally {
    closeSync(fd);
  }
}

// A symlinked ledger is written through, not replaced: an operator who pointed
// the path at a file elsewhere means to keep reading that file. realpathSync
// gives up when the target does not exist yet, so a link is followed by hand
// and the last name is resolved against its own directory, which is how the
// first write creates the file through the link rather than over it.
function resolveTarget(path) {
  let current = path;
  for (let hop = 0; hop < 40; hop += 1) {
    try {
      return realpathSync(current);
    } catch {
      /* nothing there yet */
    }
    let link;
    try {
      link = readlinkSync(current);
    } catch {
      break; // a plain name that is not there, which is the ordinary first write
    }
    current = resolve(dirname(current), link);
  }
  try {
    return join(realpathSync(dirname(current)), basename(current));
  } catch {
    return current;
  }
}

// Exported alongside withLock, for the same reason: what a write does when the
// lock under it changed hands can only be tested from a second real process.
export function writeState(path, state, now) {
  const entries = state.entries.filter((e) => now - e.at < MEMORY_MS);
  const target = resolveTarget(path);
  const tmp = `${target}.${process.pid}.tmp`;
  try {
    unlinkSync(tmp);
  } catch {
    /* nothing to clear */
  }
  keepLock();
  // Exclusive, so a temp file left behind by anyone else cannot lend this one
  // its permissions.
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, `${JSON.stringify({ version: 1, entries }, null, 2)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  // The last moment this is still a decision. A lock read as stale is broken by
  // whoever wants it next, and if that happened while these bytes were being
  // prepared they no longer describe the file: publishing them would erase the
  // charge the breaker just recorded.
  if (!holdingLock()) {
    try {
      unlinkSync(tmp);
    } catch {
      /* nothing to clear */
    }
    throw new BudgetError("lost the ledger lock; nothing written");
  }
  renameSync(tmp, target);
  fsyncDir(dirname(target));
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
          ...("tool" in e ? { tool: e.tool } : {}),
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
    // A caller handing this nanoseconds writes an entry no reader can date and
    // no write can prune, which wedges the ledger for good.
    if (!isStamp(now)) {
      throw new BudgetError("a charge has to be stamped in milliseconds since the epoch, and this one is not");
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
        // The suffix separates two charges stamped in the same millisecond, and
        // Math.random makes that a guess anyone sharing the file can make:
        // settle and revert both take an id.
        const id = `${Math.max(Math.trunc(now), 0).toString(36)}-${randomBytes(8).toString("hex")}`;
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
  // list of intentions. The reservation is the ceiling the escrow was funded
  // against, so settling can only lower it.
  //
  // A payment the endpoint never consumed is redeemed by the next attempt at the
  // same request, so one transaction can settle more than one reservation.
  // Booking each would charge the day twice for money that moved once: a
  // reference already on file keeps its entry and this one is released.
  //
  // The fold rests on a reference naming exactly one payment, which holds
  // because recordSpend passes nothing but a transaction this process
  // broadcast. It is bounded to the same tool inside the same day regardless:
  // the file remembers two days, and folding today's reservation into a charge
  // the window no longer counts would take a spend off the day's total rather
  // than deduplicate one.
  settle(id, { micros, reference } = {}) {
    if (!id) return false;
    return withLock(this.path, () => {
      const now = Date.now();
      const state = readState(this.path);
      const entry = state.entries.find((e) => e.id === id);
      if (!entry) return false;
      const booked = reference
        ? state.entries.find(
            (e) => e.id !== id && e.reference === reference && e.tool === entry.tool && now - e.at < DAY_MS,
          )
        : undefined;
      const target = booked ?? entry;
      if (isAmount(micros)) {
        if (micros > target.micros) {
          console.error(
            `prism: a settlement of ${usdg(micros)} is above the ${usdg(target.micros)} reserved for ledger entry ${target.id}; the reservation stands.`,
          );
        } else {
          target.micros = micros;
        }
      }
      if (reference) target.reference = reference;
      if (booked) state.entries = state.entries.filter((e) => e.id !== id);
      writeState(this.path, state, now);
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
  let outcome;
  try {
    outcome = await run();
  } catch (err) {
    // Only a transaction this process put on the wire proves money moved. A
    // failure's body is whatever the control plane sent back, and reading a
    // hash out of it would let the far side decide which reservations stand and
    // which later ones are folded into them.
    const paid = typeof err?.broadcast === "string" && err.broadcast ? err.broadcast : null;
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
  // The attempt ran, so the money is as gone as the caller's ability to
  // describe it. The reservation stands and the shape is reported as the
  // programming error it is.
  // An array carries no settledMicros and no reference, so reading one as an
  // outcome would book the reservation as if it had been settled and hand the
  // caller undefined. Python refuses the same shape.
  if (!outcome || typeof outcome !== "object" || Array.isArray(outcome)) {
    reconcile("settle");
    const shape = outcome === null ? "null" : Array.isArray(outcome) ? "array" : typeof outcome;
    throw new BudgetError(
      `${tool} reported ${shape} where the ledger needs an object of ` +
        `value, settledMicros and reference; the reservation stands.`,
    );
  }
  reconcile("settle", { micros: outcome.settledMicros, reference: outcome.reference });
  return outcome.value;
}
