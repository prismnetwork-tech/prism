"""What stands between a model deciding to rent a GPU and a wallet paying for it.

The real ceiling is the balance; fund the agent wallet with what you are willing
to lose. This is the second line, and it exists because ``max_usdg`` never was
one: it bounds a single lease and says nothing about the fortieth in a row,
which is what an unattended agent actually does.

Spend is written before the money moves and reverted only when the attempt
provably cost nothing, so a crash between funding and reply is counted rather
than forgiven. The file is shared across clients on purpose: one wallet gets one
daily ceiling whoever is holding it, and the Node MCP server in ``mcp/budget.mjs``
reads and writes the same entries this module does.

Two divergences from that module are left alone because no budget can reach
them: Node prints numbers at or above 1e21, or below 1e-4, in exponential form
where Python does not, and its integer sums stop being exact past 2^53. A USDG
figure that large is not a budget.
"""

from __future__ import annotations

import errno
import json
import math
import os
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal, localcontext

MICROS = 1_000_000
DAY_MS = 86_400_000
# Entries older than this are dropped on write. Two days covers the rolling
# window with room for a clock that stepped backwards.
MEMORY_MS = 2 * DAY_MS
LOCK_STALE_MS = 15_000
LOCK_WAIT_MS = 5_000
# A live holder refreshes its lock this often, so a lock older than
# LOCK_STALE_MS is one whose process died rather than one that is being slow.
LOCK_HEARTBEAT_S = 2.0
# Above this a USDG figure is a typo or an attack, and multiplying it out is how
# the arithmetic stops being arithmetic.
MAX_CALL_USDG = 1e12
# The last instant both languages can name: Python's datetime stops at year 9999
# where JavaScript's Date keeps going, so a stamp past this is one only the Node
# client could print, and it would sit in the file forever.
MAX_AT_MS = 253_402_300_799_999

_TEMPLATE = re.compile(r"^\$\{[^}]*\}$")
# One number grammar for both languages. Python's float() takes "1_000" and
# Node's Number() takes "0x10", and an operator who typed either meant neither.
# \d is ASCII in JavaScript and every decimal digit there is in Python, so the
# range is spelled out: Python reads "٣" as a 3 and no ledger should.
_DECIMAL = re.compile(r"^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$")
# The two languages also disagree about what padding is: JavaScript's trim takes
# U+FEFF where Python's strip does not, and Python's takes U+001C where
# JavaScript's does not. Trimming these four leaves one answer on both sides.
_PADDING = " \t\r\n"
_BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"
_MICRO = Decimal("0.000001")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class BudgetError(Exception):
    def __init__(self, message: str, detail: dict | None = None):
        super().__init__(message)
        self.detail = detail or {}


# JavaScript's toFixed breaks an exact tie away from zero where Python's format
# breaks it towards even, and 0.007812|5 USDG has to read the same on both sides
# of one ledger. Decimal(float) is the double's exact value, so the tie decided
# here is the real one rather than an artifact of scaling the figure back up.
def usdg(micros) -> str:
    value = float(micros) / MICROS
    if value == 0:
        return "0.000000 USDG"
    if not math.isfinite(value):
        return f"{value:.6f} USDG"
    with localcontext() as ctx:
        # Room to quantize any finite double without rounding it first.
        ctx.prec = 400
        return f"{Decimal(value).quantize(_MICRO, rounding=ROUND_HALF_UP):f} USDG"


# Node builds this from an integer count of milliseconds; going through a float
# number of seconds loses the last millisecond at the far end of the range.
def _iso(at) -> str:
    return (
        (_EPOCH + timedelta(milliseconds=math.trunc(at)))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _finite(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _amount(value) -> bool:
    return _finite(value) and value >= 0


def _stamp(value) -> bool:
    return _amount(value) and value <= MAX_AT_MS


# JavaScript rounds halves towards positive infinity where Python rounds them to
# even, and both sides of this ledger have to land on the same micro. Adding a
# half first would not do it: 0.49999999999999994 + 0.5 is 1.0 in doubles, and
# Math.round answers 0.
def _round(value: float) -> int:
    floor = math.floor(value)
    return floor + 1 if value - floor >= 0.5 else floor


# Node prints 1 where Python prints 1.0, and these numbers end up inside error
# messages the two implementations are meant to share.
def _fmt(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def _positive_number(raw, fallback: float, name: str) -> float:
    text = "" if raw is None else str(raw).strip(_PADDING)
    if text == "":
        return fallback
    value = float(text) if _DECIMAL.match(text) else math.nan
    if not math.isfinite(value) or value < 0:
        raise BudgetError(f"{name} must be a non-negative number of USDG, got {json.dumps(raw)}")
    return value


# One .mcp.json serves every client, and they disagree about templates: Claude
# Code expands ${user_config.x} before launch, Codex passes it through. Reading
# the literal template as a value would turn "no wallet configured" into "wallet
# configured and broken", so an unexpanded placeholder is nothing.
def strip_unexpanded(env=None):
    target = os.environ if env is None else env
    doomed = [
        key
        for key, value in list(target.items())
        if key.startswith("PRISM_") and _TEMPLATE.match(("" if value is None else str(value)).strip(_PADDING))
    ]
    for key in doomed:
        del target[key]
    return target


def default_ledger_path(env=None) -> str:
    env = os.environ if env is None else env
    if env.get("PRISM_LEDGER_PATH"):
        return env["PRISM_LEDGER_PATH"]
    return os.path.join(env.get("HOME") or os.path.expanduser("~"), ".prism", "spend.json")


@dataclass
class Budget:
    max_per_call_micros: int
    daily_micros: int
    ledger_path: str


# A missing budget is not an unlimited one. The default is deliberately small:
# enough for a handful of real leases, cheap enough that discovering the plugin
# spends money costs about the price of a coffee rather than a rent cheque.
def read_budget(env=None) -> Budget:
    env = os.environ if env is None else env
    max_per_call = _positive_number(env.get("PRISM_MAX_USDG"), 1, "PRISM_MAX_USDG")
    daily = _positive_number(env.get("PRISM_DAILY_BUDGET_USDG"), 5, "PRISM_DAILY_BUDGET_USDG")
    if max_per_call <= 0:
        raise BudgetError("PRISM_MAX_USDG must be above zero")
    # A per-call cap above the day's allowance is a cap in name only, and the
    # mismatch is always a configuration mistake rather than an intention.
    if daily > 0 and max_per_call > daily:
        raise BudgetError(
            f"PRISM_MAX_USDG ({_fmt(max_per_call)}) cannot exceed PRISM_DAILY_BUDGET_USDG ({_fmt(daily)}); "
            "lower the per-call cap or raise the daily one"
        )
    return Budget(
        max_per_call_micros=_round(max_per_call * MICROS),
        # Zero means the operator explicitly removed the daily ceiling. It is not
        # the default and it is not what a missing variable produces.
        daily_micros=_round(daily * MICROS),
        ledger_path=default_ledger_path(env),
    )


# What a single call is allowed to spend, given what it asked for. The caller's
# figure is written by the thing being bounded, so it lowers the operator's
# ceiling and can never lift it.
def call_ceiling(max_usdg, ceiling_micros: int) -> int:
    if max_usdg is None:
        return ceiling_micros
    if not _finite(max_usdg) or max_usdg <= 0:
        raise BudgetError("max_usdg must be a positive number of USDG.")
    # Checked before the multiplication, because that is where a figure this
    # size stops being a number and starts being an exception.
    if max_usdg > MAX_CALL_USDG:
        raise BudgetError(f"max_usdg must be at most {_fmt(MAX_CALL_USDG)} USDG.")
    return min(_round(max_usdg * MICROS), ceiling_micros)


def _lock_owner(lock: str) -> bytes | None:
    try:
        with open(lock, "rb") as fh:
            return fh.read(128)
    except OSError:
        return None


# A holder whose lock was broken as stale must not delete the lock its breaker
# now holds, which is how two processes end up inside the ledger at once.
def _release(lock: str, token: bytes) -> None:
    if _lock_owner(lock) != token:
        return
    try:
        os.unlink(lock)
    except OSError:
        pass


# The lock the calling thread is writing under, so the write itself can keep it
# alive and refuse to publish under someone else's.
_writing = threading.local()


def _touch(lock: str, token: bytes) -> None:
    if _lock_owner(lock) != token:
        # It was broken and retaken. Refreshing it now would be this process
        # vouching for a lock it does not hold.
        return
    stamp = time.time()
    try:
        os.utime(lock, (stamp, stamp))
    except OSError:
        pass


class _Heartbeat:
    """Keeps a held lock looking held.

    Without it, a write that takes longer than LOCK_STALE_MS reads as abandoned
    and the process that breaks it works inside the ledger alongside a live
    writer. With it, a stale lock means the holder died.
    """

    def __init__(self, lock: str, token: bytes):
        self.lock = lock
        self.token = token
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._beat, daemon=True)
        self.thread.start()

    def _beat(self) -> None:
        while not self.done.wait(LOCK_HEARTBEAT_S):
            _touch(self.lock, self.token)

    def close(self) -> None:
        self.done.set()
        self.thread.join(timeout=1)


def _keep_lock() -> None:
    under = getattr(_writing, "lock", None)
    if under:
        _touch(*under)


def _holding_lock() -> bool:
    under = getattr(_writing, "lock", None)
    return under is None or _lock_owner(under[0]) == under[1]


# Where a write lands. A symlinked ledger is written through, not replaced: an
# operator who pointed the path at a file elsewhere means to keep reading that
# file. realpath resolves a link whose target does not exist yet to that target,
# so the first write creates the file through the link rather than over it.
def _target(path: str) -> str:
    return os.path.realpath(path)


# A lock rather than last-write-wins, because two clients sharing one wallet is
# the case this file exists for. A holder refreshes its lock while it works, so
# a lock older than LOCK_STALE_MS belonged to a process that died; breaking it
# is safe and not breaking it wedges the wallet. A break that happens anyway,
# because a machine slept or a clock stepped, is caught at the write.
def _with_lock(path: str, fn, wait_ms: int = LOCK_WAIT_MS):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    # The lock names the file the write lands on rather than the name the caller
    # spelled. One client reaching the ledger through a link and another through
    # its target would otherwise hold two different locks over one file, and
    # each would publish a state read before the other's charge existed.
    lock = f"{_target(path)}.lock"
    deadline = time.time() * 1000 + wait_ms
    token = f"{os.getpid()}-{secrets.token_hex(8)}".encode("utf-8")
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            held = _lock_owner(lock)
            try:
                age = time.time() * 1000 - os.stat(lock).st_mtime * 1000
            except FileNotFoundError:
                continue  # it vanished between the open and the stat; retry immediately
            if age > LOCK_STALE_MS:
                # Break the lock that was read as stale and no other: re-reading
                # the token keeps a slow breaker from deleting a lock a third
                # process took in the meantime.
                if _lock_owner(lock) == held:
                    try:
                        os.unlink(lock)
                    except OSError:
                        pass  # another process broke it first, which is the outcome we wanted
                continue
            if time.time() * 1000 > deadline:
                raise BudgetError(
                    f"the spend ledger at {path} is locked by another Prism process; "
                    "nothing was charged. Retry in a moment."
                )
            time.sleep(0.025)
            continue
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(token)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            _release(lock, token)
            raise
        beat = _Heartbeat(lock, token)
        outer = getattr(_writing, "lock", None)
        _writing.lock = (lock, token)
        try:
            return fn()
        finally:
            _writing.lock = outer
            beat.close()
            _release(lock, token)


def _refuse_constant(name):
    raise ValueError(f"{name} is not a number")


def _unreadable(path: str, reason) -> BudgetError:
    return BudgetError(
        f"the spend ledger at {path} is unreadable ({reason}), so spending is refused. Move or repair the file."
    )


def _read_state(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as err:
        if err.errno == errno.ENOENT:
            return {"entries": []}
        raise _unreadable(path, err)
    try:
        # Python's json reads NaN and Infinity as floats where Node's refuses
        # them outright, and an entry only one side can read is not one to
        # charge a wallet against. The byte order mark an editor may have left
        # is dropped for the same reason: Node's decoder drops it, and a file
        # only Node can read is one only Node stops spending against.
        parsed = json.loads(raw.decode("utf-8-sig"), parse_constant=_refuse_constant)
    except (ValueError, UnicodeDecodeError) as err:
        # A corrupt ledger must not read as an empty one: that would hand the
        # caller a fresh day's budget every time the file got truncated.
        raise _unreadable(path, err)
    entries = parsed.get("entries") if isinstance(parsed, dict) else None
    if not isinstance(entries, list):
        raise _unreadable(path, "it holds no list of entries")
    # Dropping the entries that fail this check would be the corrupt-reads-as-
    # empty bug again, one charge at a time.
    for entry in entries:
        if not isinstance(entry, dict) or not _stamp(entry.get("at")) or not _amount(entry.get("micros")):
            raise _unreadable(path, "an entry is not a charge with non-negative micros and an at a date can hold")
    return {"entries": entries}


# The entry is written before the money moves, so it has to survive the crash
# that lands between the two.
def _fsync_dir(directory: str) -> None:
    fd = os.open(directory or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError:
        pass  # some filesystems refuse it, and the rename is still ordered
    finally:
        os.close(fd)


def _write_state(path: str, state: dict, now: int) -> None:
    entries = [e for e in state["entries"] if now - e["at"] < MEMORY_MS]
    target = _target(path)
    tmp = f"{target}.{os.getpid()}.tmp"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    _keep_lock()
    # Exclusive, so a temp file left behind by anyone else cannot lend this one
    # its permissions.
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"version": 1, "entries": entries}, indent=2) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    # The last moment this is still a decision. A lock read as stale is broken
    # by whoever wants it next, and if that happened while these bytes were
    # being prepared they no longer describe the file: publishing them would
    # erase the charge the breaker just recorded.
    if not _holding_lock():
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise BudgetError("lost the ledger lock; nothing written")
    os.replace(tmp, target)
    _fsync_dir(os.path.dirname(target))


def spent_in_window(entries, now_ms: int) -> int:
    return sum(e["micros"] for e in entries if now_ms - e["at"] < DAY_MS)


def _new_id(now) -> str:
    digits = ""
    value = max(int(now), 0)
    while value:
        digits = _BASE36[value % 36] + digits
        value //= 36
    # The suffix separates two charges stamped in the same millisecond, and a
    # seeded global generator makes that a guess anyone sharing the file can
    # make: settle and revert both take an id.
    return f"{digits or '0'}-{secrets.token_hex(8)}"


class SpendLedger:
    def __init__(self, ledger_path: str, daily_micros: int, max_per_call_micros: int, lock_wait_ms: int = LOCK_WAIT_MS):
        self.path = ledger_path
        self.daily_micros = daily_micros
        self.max_per_call_micros = max_per_call_micros
        self.lock_wait_ms = lock_wait_ms

    # What is left of today, for the caller to show before it asks to spend.
    def remaining(self, now_ms: int | None = None):
        if self.daily_micros <= 0:
            return None
        now_ms = _now_ms() if now_ms is None else now_ms
        entries = _read_state(self.path)["entries"]
        return max(0, self.daily_micros - spent_in_window(entries, now_ms))

    def status(self, now_ms: int | None = None) -> dict:
        now_ms = _now_ms() if now_ms is None else now_ms
        entries = _read_state(self.path)["entries"]
        spent = spent_in_window(entries, now_ms)
        recent = sorted((e for e in entries if now_ms - e["at"] < DAY_MS), key=lambda e: -e["at"])[:20]
        unlimited = "unlimited (PRISM_DAILY_BUDGET_USDG=0)"
        return {
            "daily_budget": usdg(self.daily_micros) if self.daily_micros > 0 else unlimited,
            "spent_last_24h": usdg(spent),
            "remaining_today": usdg(max(0, self.daily_micros - spent)) if self.daily_micros > 0 else "unlimited",
            "max_per_call": usdg(self.max_per_call_micros),
            "ledger": self.path,
            "charges_last_24h": [
                {
                    "at": _iso(e["at"]),
                    **({"tool": e["tool"]} if "tool" in e else {}),
                    "amount": usdg(e["micros"]),
                    **({"reference": e["reference"]} if e.get("reference") else {}),
                }
                for e in recent
            ],
        }

    # Records the spend before the money moves. Returns a handle the caller
    # reverts only when it can prove nothing was charged.
    def commit(self, tool: str, micros, now_ms: int | None = None) -> str:
        if not _finite(micros) or micros <= 0:
            raise BudgetError("a spend must be a positive number of micros")
        if micros > self.max_per_call_micros:
            raise BudgetError(
                f"{tool} would commit up to {usdg(micros)}, past the {usdg(self.max_per_call_micros)} per-call cap. "
                "Lower max_usdg for this call, or raise PRISM_MAX_USDG.",
                {"required": micros, "cap": self.max_per_call_micros},
            )
        now = _now_ms() if now_ms is None else now_ms
        # A caller handing this nanoseconds writes an entry no reader can date
        # and no write can prune, which wedges the ledger for good.
        if not _stamp(now):
            raise BudgetError("a charge has to be stamped in milliseconds since the epoch, and this one is not")

        def write():
            state = _read_state(self.path)
            spent = spent_in_window(state["entries"], now)
            if self.daily_micros > 0 and spent + micros > self.daily_micros:
                raise BudgetError(
                    f"{tool} would take today's Prism spend to {usdg(spent + micros)}, past the "
                    f"{usdg(self.daily_micros)} daily cap ({usdg(spent)} already spent). Nothing was charged. "
                    "Raise PRISM_DAILY_BUDGET_USDG to continue.",
                    {"spent": spent, "requested": micros, "cap": self.daily_micros},
                )
            entry_id = _new_id(now)
            state["entries"].append({"id": entry_id, "at": now, "tool": tool, "micros": micros})
            _write_state(self.path, state, now)
            return entry_id

        return _with_lock(self.path, write, self.lock_wait_ms)

    # Only for an attempt that provably cost nothing. A funded lease whose command
    # failed is not one of those.
    def revert(self, entry_id: str) -> bool:
        if not entry_id:
            return False

        def write():
            state = _read_state(self.path)
            kept = [e for e in state["entries"] if e.get("id") != entry_id]
            if len(kept) == len(state["entries"]):
                return False
            state["entries"] = kept
            _write_state(self.path, state, _now_ms())
            return True

        return _with_lock(self.path, write, self.lock_wait_ms)

    # Replaces the reserved figure with what was actually committed on-chain and
    # pins the receipt to it, so the ledger reads like a statement rather than a
    # list of intentions. The reservation is the ceiling the escrow was funded
    # against, so settling can only lower it.
    #
    # A payment the endpoint never consumed is redeemed by the next attempt at
    # the same request, so one transaction can settle more than one reservation.
    # Booking each would charge the day twice for money that moved once: a
    # reference already on file keeps its entry and this one is released.
    #
    # The fold rests on a reference naming exactly one payment, which holds
    # because record_spend passes nothing but a transaction this process
    # broadcast. It is bounded to the same tool inside the same day regardless:
    # the file remembers two days, and folding today's reservation into a charge
    # the window no longer counts would take a spend off the day's total rather
    # than deduplicate one.
    def settle(self, entry_id: str, micros=None, reference: str | None = None) -> bool:
        if not entry_id:
            return False

        def write():
            now = _now_ms()
            state = _read_state(self.path)
            entry = next((e for e in state["entries"] if e.get("id") == entry_id), None)
            if entry is None:
                return False
            booked = None
            if reference:
                booked = next(
                    (
                        e
                        for e in state["entries"]
                        if e.get("id") != entry_id
                        and e.get("reference") == reference
                        and e.get("tool") == entry.get("tool")
                        and now - e["at"] < DAY_MS
                    ),
                    None,
                )
            target = booked if booked is not None else entry
            if _amount(micros):
                if micros > target["micros"]:
                    print(
                        f"prism: a settlement of {usdg(micros)} is above the {usdg(target['micros'])} reserved "
                        f"for ledger entry {target.get('id')}; the reservation stands.",
                        file=sys.stderr,
                    )
                else:
                    target["micros"] = micros
            if reference:
                target["reference"] = reference
            if booked is not None:
                state["entries"] = [e for e in state["entries"] if e.get("id") != entry_id]
            _write_state(self.path, state, now)
            return True

        return _with_lock(self.path, write, self.lock_wait_ms)


# Records a spend before the money moves, then reconciles it against what
# happened. A failure that never reached the chain is given back; anything that
# funded an escrow or paid an endpoint keeps its entry and gains the transaction
# that proves it, because a ledger that forgets a spend is worse than no ledger.
def record_spend(book: SpendLedger, tool: str, micros: int, run):
    entry_id = book.commit(tool, micros)

    # Reconciling is bookkeeping and must never be the reason a caller loses a
    # machine it paid for, or the reason a failure is reported as the wrong
    # failure. A ledger that cannot be written says so on stderr and the
    # committed figure stands, which errs towards counting the spend.
    def reconcile(action, **kwargs):
        try:
            getattr(book, action)(entry_id, **kwargs)
        except Exception as err:
            print(f"prism mcp: could not {action} the ledger entry for {tool}: {err}", file=sys.stderr)

    try:
        outcome = run()
    except Exception as err:
        # Only a transaction this process put on the wire proves money moved.
        # A failure's body is whatever the control plane sent back, and reading
        # a hash out of it would let the far side decide which reservations
        # stand and which later ones are folded into them.
        paid = getattr(err, "broadcast", None)
        if isinstance(paid, str) and paid:
            reconcile("settle", reference=paid)
        elif getattr(err, "code", None) == "chain_error":
            # Signed, broadcast, and then something went wrong reading it back,
            # which is not the same as never having reached the chain. Handing
            # the reservation back would let one wallet fund escrow after escrow
            # through an rpc having a bad hour while the day's ceiling reported
            # nothing spent, so the entry stands at what it reserved.
            reconcile("settle")
        else:
            reconcile("revert")
        raise

    # The attempt ran, so the money is as gone as the caller's ability to
    # describe it. The reservation stands and the shape is reported as the
    # programming error it is.
    if not isinstance(outcome, dict):
        reconcile("settle")
        raise BudgetError(
            f"{tool} reported {type(outcome).__name__} where the ledger needs a mapping of "
            "value, settled_micros and reference; the reservation stands."
        )
    reconcile("settle", micros=outcome.get("settled_micros"), reference=outcome.get("reference"))
    return outcome.get("value")
