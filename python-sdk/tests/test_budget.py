"""The spend cap, and whether it counts the same money the Node MCP server does."""

from __future__ import annotations

import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from prismnetwork import (
    Budget,
    BudgetError,
    Lease,
    PrismError,
    PrismToolset,
    SpendLedger,
    call_ceiling,
    default_ledger_path,
    read_budget,
    record_spend,
    spent_in_window,
    strip_unexpanded,
    usdg,
)
from prismnetwork._budget import LOCK_HEARTBEAT_S, LOCK_STALE_MS, MAX_AT_MS, _iso, _new_id, _round
from prismnetwork.toolkit import NO_BUDGET

# The Node definition this module is a port of. Absent from an installed wheel,
# present in a checkout, which is where the comparison is worth making.
NODE_MODULE = Path(__file__).resolve().parents[2] / "mcp" / "budget.mjs"
SDK_ROOT = str(Path(__file__).resolve().parents[1])

# A second process that takes the lock and sits inside it, so the ones that
# matter here are real and not two threads pretending.
HOLDER = f"""
import sys, time
sys.path.insert(0, {SDK_ROOT!r})
from prismnetwork._budget import _with_lock
path, mark, hold = sys.argv[1], sys.argv[2], float(sys.argv[3])


def work():
    with open(mark, "w") as fh:
        fh.write("in")
    time.sleep(hold)


_with_lock(path, work, 4000)
"""

# A writer that has read the ledger and not written it yet, which is the window
# a lock broken as stale takes the file out from under.
SLOW_WRITER = f"""
import sys, time
sys.path.insert(0, {SDK_ROOT!r})
import prismnetwork._budget as budget
path, mark, before, after = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
read, write = budget._read_state, budget._write_state


def slow(target):
    state = read(target)
    with open(mark, "w") as fh:
        fh.write("read")
    time.sleep(before)
    return state


def loud(target, state, now):
    write(target, state, now)
    with open(mark + ".written", "w") as fh:
        fh.write("written")
    time.sleep(after)


budget._read_state, budget._write_state = slow, loud
budget.SpendLedger(path, 5_000_000, 1_000_000, lock_wait_ms=4000).commit("prism_slow", 250_000)
"""

# The other half: a process that finds the lock too old to believe, breaks it,
# and records a charge of its own inside it.
BREAKER = f"""
import os, sys, time
sys.path.insert(0, {SDK_ROOT!r})
import prismnetwork._budget as budget
path = sys.argv[1]
stale = time.time() - 20
os.utime(path + ".lock", (stale, stale))
budget.SpendLedger(path, 5_000_000, 1_000_000, lock_wait_ms=4000).commit("prism_breaker", 100_000)
"""

# settle and revert prune against the real clock, exactly as the Node module
# does, so a fixture anchored in the past would delete itself mid-test.
NOW = int(time.time() * 1000)
FIXED = 1_756_000_000_000
DAY_MS = 86_400_000


class Failure(Exception):
    def __init__(self, code=None, body=None, broadcast=None):
        super().__init__(code or "failed")
        self.code = code
        self.body = body
        self.broadcast = broadcast


class LedgerCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "nested", "spend.json")

    def ledger(self, daily=5_000_000, per_call=1_000_000, lock_wait_ms=5000):
        return SpendLedger(self.path, daily, per_call, lock_wait_ms=lock_wait_ms)

    def entries(self):
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)["entries"]


class FormattingTest(unittest.TestCase):
    def test_micros_read_as_usdg_to_six_places(self):
        self.assertEqual(usdg(1_000_000), "1.000000 USDG")
        self.assertEqual(usdg(0), "0.000000 USDG")
        self.assertEqual(usdg(1), "0.000001 USDG")
        self.assertEqual(usdg(12_345_678), "12.345678 USDG")

    # commit() and settle() both take a figure rather than an integer, and a
    # ledger entry that reads as two different amounts is two ledgers.
    def test_a_micro_on_an_exact_half_reads_the_same_as_it_does_in_node(self):
        self.assertEqual(usdg(7812.5), "0.007813 USDG")
        self.assertEqual(usdg(39062.5), "0.039063 USDG")
        self.assertEqual(usdg(-7812.5), "-0.007813 USDG")
        self.assertEqual(usdg(1.5), "0.000002 USDG")
        self.assertEqual(usdg(2.5), "0.000003 USDG")

    def test_a_window_only_counts_the_last_day(self):
        entries = [
            {"at": NOW - 1000, "micros": 500},
            {"at": NOW - DAY_MS + 1, "micros": 300},
            {"at": NOW - DAY_MS, "micros": 900},
            {"at": NOW - 2 * DAY_MS, "micros": 7},
        ]
        self.assertEqual(spent_in_window(entries, NOW), 800)
        self.assertEqual(spent_in_window([], NOW), 0)


class EnvironmentTest(unittest.TestCase):
    def test_an_unexpanded_template_is_not_a_value(self):
        env = {
            "PRISM_KEY": "${user_config.private_key}",
            "PRISM_MAX_USDG": " ${x} ",
            "PRISM_RPC": "https://rpc.example",
            "PRISM_EMPTY": "",
            "HOME": "${nope}",
        }
        self.assertEqual(
            strip_unexpanded(env),
            {"PRISM_RPC": "https://rpc.example", "PRISM_EMPTY": "", "HOME": "${nope}"},
        )

    def test_the_ledger_lives_under_home_unless_told_otherwise(self):
        self.assertEqual(default_ledger_path({"HOME": "/tmp/agent"}), "/tmp/agent/.prism/spend.json")
        self.assertEqual(
            default_ledger_path({"HOME": "/tmp/agent", "PRISM_LEDGER_PATH": "/var/spend.json"}), "/var/spend.json"
        )

    def test_a_missing_budget_is_a_small_one_not_an_unlimited_one(self):
        budget = read_budget({"HOME": "/tmp/agent"})
        self.assertEqual(budget, Budget(1_000_000, 5_000_000, "/tmp/agent/.prism/spend.json"))

    def test_zero_daily_is_the_operator_removing_the_ceiling(self):
        budget = read_budget({"HOME": "/tmp/agent", "PRISM_MAX_USDG": "2.5", "PRISM_DAILY_BUDGET_USDG": "0"})
        self.assertEqual(budget.max_per_call_micros, 2_500_000)
        self.assertEqual(budget.daily_micros, 0)

    def test_a_per_call_cap_above_the_day_is_a_cap_in_name_only(self):
        with self.assertRaises(BudgetError) as caught:
            read_budget({"HOME": "/tmp/a", "PRISM_MAX_USDG": "9", "PRISM_DAILY_BUDGET_USDG": "5"})
        self.assertEqual(
            str(caught.exception),
            "PRISM_MAX_USDG (9) cannot exceed PRISM_DAILY_BUDGET_USDG (5); "
            "lower the per-call cap or raise the daily one",
        )

    def test_nonsense_and_zero_per_call_are_refused(self):
        with self.assertRaises(BudgetError) as caught:
            read_budget({"HOME": "/tmp/a", "PRISM_MAX_USDG": "lots"})
        self.assertEqual(str(caught.exception), 'PRISM_MAX_USDG must be a non-negative number of USDG, got "lots"')

        with self.assertRaises(BudgetError):
            read_budget({"HOME": "/tmp/a", "PRISM_DAILY_BUDGET_USDG": "-1"})

        with self.assertRaises(BudgetError) as caught:
            read_budget({"HOME": "/tmp/a", "PRISM_MAX_USDG": "0"})
        self.assertEqual(str(caught.exception), "PRISM_MAX_USDG must be above zero")

    def test_one_number_grammar_for_both_languages(self):
        # float() would read the first as 1000 and Number() the second as 16,
        # and one ledger cannot have two grammars.
        # "٣" is a 3 to Python's float() and nothing to Number(); U+FEFF is
        # padding to trim() and a character to strip(). Both are refused here
        # so neither language reads a figure the other cannot.
        for bad in ("1_000", "0x10", "1e", "1,5", "0b1", "infinity", "1 2", "٣", "﻿2", "\x1c2", "2\xa0"):
            with self.assertRaises(BudgetError, msg=bad):
                read_budget({"HOME": "/tmp/a", "PRISM_DAILY_BUDGET_USDG": bad})
        for good, micros in ((" 2 ", 2_000_000), ("2.", 2_000_000), (".5", 500_000), ("2e0", 2_000_000)):
            budget = read_budget({"HOME": "/tmp/a", "PRISM_MAX_USDG": good, "PRISM_DAILY_BUDGET_USDG": "9"})
            self.assertEqual(budget.max_per_call_micros, micros, good)

    def test_a_budget_too_large_to_be_a_number_is_refused(self):
        with self.assertRaises(BudgetError):
            read_budget({"HOME": "/tmp/a", "PRISM_DAILY_BUDGET_USDG": "1e400"})


class CallCeilingTest(unittest.TestCase):
    def test_the_caller_can_lower_the_operators_ceiling_and_never_lift_it(self):
        self.assertEqual(call_ceiling(None, 1_000_000), 1_000_000)
        self.assertEqual(call_ceiling(0.25, 1_000_000), 250_000)
        self.assertEqual(call_ceiling(50, 1_000_000), 1_000_000)

    def test_a_ceiling_that_is_not_a_positive_number_is_refused(self):
        for bad in (0, -1, "1", True, float("inf")):
            with self.assertRaises(BudgetError) as caught:
                call_ceiling(bad, 1_000_000)
            self.assertEqual(str(caught.exception), "max_usdg must be a positive number of USDG.")

    def test_a_ceiling_too_large_to_multiply_is_a_budget_error_not_an_overflow(self):
        with self.assertRaises(BudgetError) as caught:
            call_ceiling(1e308, 1_000_000)
        self.assertEqual(str(caught.exception), "max_usdg must be at most 1000000000000 USDG.")
        self.assertEqual(call_ceiling(1e12, 1_000_000), 1_000_000)


class CommitTest(LedgerCase):
    def test_a_commit_is_written_before_the_money_moves(self):
        book = self.ledger()
        entry_id = book.commit("prism_lease", 400_000, now_ms=NOW)
        self.assertEqual(
            self.entries(), [{"id": entry_id, "at": NOW, "tool": "prism_lease", "micros": 400_000}]
        )
        self.assertEqual(book.remaining(NOW), 4_600_000)
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), "0o600")

    def test_a_spend_must_be_a_positive_number_of_micros(self):
        for bad in (0, -5, "1", None):
            with self.assertRaises(BudgetError) as caught:
                self.ledger().commit("prism_lease", bad, now_ms=NOW)
            self.assertEqual(str(caught.exception), "a spend must be a positive number of micros")
        self.assertFalse(os.path.exists(self.path))

    def test_a_call_past_the_per_call_cap_is_refused_before_the_ledger_is_touched(self):
        with self.assertRaises(BudgetError) as caught:
            self.ledger().commit("prism_lease", 1_500_000, now_ms=NOW)
        self.assertEqual(
            str(caught.exception),
            "prism_lease would commit up to 1.500000 USDG, past the 1.000000 USDG per-call cap. "
            "Lower max_usdg for this call, or raise PRISM_MAX_USDG.",
        )
        self.assertEqual(caught.exception.detail, {"required": 1_500_000, "cap": 1_000_000})
        self.assertFalse(os.path.exists(self.path))

    def test_a_call_past_the_daily_cap_charges_nothing(self):
        book = self.ledger()
        for _ in range(5):
            book.commit("prism_lease", 1_000_000, now_ms=NOW)
        with self.assertRaises(BudgetError) as caught:
            book.commit("prism_lease", 1_000_000, now_ms=NOW)
        self.assertEqual(
            str(caught.exception),
            "prism_lease would take today's Prism spend to 6.000000 USDG, past the 5.000000 USDG daily cap "
            "(5.000000 USDG already spent). Nothing was charged. Raise PRISM_DAILY_BUDGET_USDG to continue.",
        )
        self.assertEqual(caught.exception.detail, {"spent": 5_000_000, "requested": 1_000_000, "cap": 5_000_000})
        self.assertEqual(len(self.entries()), 5)
        self.assertEqual(book.remaining(NOW), 0)

    def test_yesterdays_spend_does_not_count_against_today(self):
        book = self.ledger()
        book.commit("prism_lease", 1_000_000, now_ms=NOW - DAY_MS - 1)
        self.assertEqual(book.remaining(NOW), 5_000_000)

    def test_a_clock_that_is_not_milliseconds_is_refused_before_the_file_is_touched(self):
        book = self.ledger()
        # time.time_ns() where the ledger wanted milliseconds. Written through,
        # it would date an entry past year 9999: unprintable on one side and
        # unprunable on both, for good.
        for clock in (NOW * 1_000_000, MAX_AT_MS + 1, -1, float("nan")):
            with self.assertRaises(BudgetError, msg=repr(clock)) as caught:
                book.commit("prism_lease", 400_000, now_ms=clock)
            self.assertIn("milliseconds since the epoch", str(caught.exception))
        self.assertFalse(os.path.exists(self.path))

    def test_an_unlimited_day_has_no_remaining_figure(self):
        book = self.ledger(daily=0)
        book.commit("prism_lease", 1_000_000, now_ms=NOW)
        self.assertIsNone(book.remaining(NOW))

    def test_entries_older_than_two_days_are_dropped_on_write(self):
        book = self.ledger(daily=0)
        book.commit("old", 1_000_000, now_ms=NOW - 2 * DAY_MS)
        book.commit("stale", 1_000_000, now_ms=NOW - 2 * DAY_MS + 1000)
        self.assertEqual([e["tool"] for e in self.entries()], ["old", "stale"])
        book.commit("fresh", 1_000_000, now_ms=NOW)
        self.assertEqual([e["tool"] for e in self.entries()], ["stale", "fresh"])


class StatusTest(LedgerCase):
    def test_status_reads_like_a_statement(self):
        book = self.ledger()
        book.commit("prism_lease", 400_000, now_ms=FIXED - 1000)
        book.commit("prism_infer", 100_000, now_ms=FIXED)
        status = book.status(FIXED)
        self.assertEqual(status["daily_budget"], "5.000000 USDG")
        self.assertEqual(status["spent_last_24h"], "0.500000 USDG")
        self.assertEqual(status["remaining_today"], "4.500000 USDG")
        self.assertEqual(status["max_per_call"], "1.000000 USDG")
        self.assertEqual(status["ledger"], self.path)
        self.assertEqual([c["tool"] for c in status["charges_last_24h"]], ["prism_infer", "prism_lease"])
        self.assertEqual(status["charges_last_24h"][0]["at"], "2025-08-24T01:46:40.000Z")
        self.assertNotIn("reference", status["charges_last_24h"][0])

    def test_an_unlimited_day_says_so(self):
        status = self.ledger(daily=0).status(FIXED)
        self.assertEqual(status["daily_budget"], "unlimited (PRISM_DAILY_BUDGET_USDG=0)")
        self.assertEqual(status["remaining_today"], "unlimited")


class RevertTest(LedgerCase):
    def test_a_reservation_that_cost_nothing_is_given_back(self):
        book = self.ledger()
        entry_id = book.commit("prism_lease", 400_000, now_ms=NOW)
        self.assertTrue(book.revert(entry_id))
        self.assertEqual(self.entries(), [])
        self.assertEqual(book.remaining(NOW), 5_000_000)

    def test_reverting_twice_or_nothing_changes_nothing(self):
        book = self.ledger()
        entry_id = book.commit("prism_lease", 400_000, now_ms=NOW)
        book.revert(entry_id)
        self.assertFalse(book.revert(entry_id))
        self.assertFalse(book.revert(None))


class SettleTest(LedgerCase):
    def test_the_reserved_figure_is_replaced_by_what_was_paid(self):
        book = self.ledger()
        entry_id = book.commit("prism_lease", 400_000, now_ms=NOW)
        self.assertTrue(book.settle(entry_id, micros=120_000, reference="0xdead"))
        self.assertEqual(
            self.entries(),
            [{"id": entry_id, "at": NOW, "tool": "prism_lease", "micros": 120_000, "reference": "0xdead"}],
        )
        self.assertEqual(book.remaining(NOW), 4_880_000)

    def test_settling_without_figures_leaves_the_reservation_standing(self):
        book = self.ledger()
        entry_id = book.commit("prism_lease", 400_000, now_ms=NOW)
        self.assertTrue(book.settle(entry_id))
        self.assertEqual(self.entries()[0]["micros"], 400_000)
        self.assertFalse(book.settle("nobody"))
        self.assertFalse(book.settle(None))

    def test_one_transaction_settling_twice_is_only_charged_once(self):
        book = self.ledger()
        first = book.commit("prism_infer", 300_000, now_ms=NOW)
        book.settle(first, micros=300_000, reference="0xpaid")
        second = book.commit("prism_infer", 300_000, now_ms=NOW)
        self.assertTrue(book.settle(second, micros=250_000, reference="0xpaid"))

        entries = self.entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["id"], first)
        self.assertEqual(entries[0]["micros"], 250_000)
        self.assertEqual(book.remaining(NOW), 4_750_000)

    def test_one_reference_cannot_swallow_the_charges_of_other_tools(self):
        book = self.ledger()
        for tool in ("prism_lease", "prism_infer", "prism_batch_run"):
            book.settle(book.commit(tool, 400_000, now_ms=NOW), micros=400_000, reference="0xSAME")
        self.assertEqual(len(self.entries()), 3)
        self.assertEqual(book.remaining(NOW), 5_000_000 - 1_200_000)

    def test_a_charge_the_day_no_longer_counts_is_not_folded_into(self):
        book = self.ledger()
        yesterday = book.commit("prism_infer", 400_000, now_ms=NOW - DAY_MS - 1000)
        book.settle(yesterday, micros=400_000, reference="0xpaid")
        today = book.commit("prism_infer", 400_000, now_ms=NOW)
        book.settle(today, micros=400_000, reference="0xpaid")
        self.assertEqual(len(self.entries()), 2)
        self.assertEqual(book.remaining(NOW), 4_600_000)


class CorruptionTest(LedgerCase):
    def test_a_corrupt_ledger_refuses_spending_rather_than_reading_as_empty(self):
        os.makedirs(os.path.dirname(self.path))
        Path(self.path).write_text("{not json", encoding="utf-8")
        book = self.ledger()
        for call in (lambda: book.remaining(NOW), lambda: book.status(NOW), lambda: book.commit("t", 1, now_ms=NOW)):
            with self.assertRaises(BudgetError) as caught:
                call()
            self.assertIn(f"the spend ledger at {self.path} is unreadable", str(caught.exception))
            self.assertIn("so spending is refused. Move or repair the file.", str(caught.exception))

    def test_json_that_is_not_a_ledger_refuses_spending(self):
        os.makedirs(os.path.dirname(self.path))
        for text in ("null", "[]", "0", '"x"', '{"version": 1}', '{"entries": {}}', '{"entries": "5"}'):
            Path(self.path).write_text(text, encoding="utf-8")
            with self.assertRaises(BudgetError, msg=text) as caught:
                self.ledger().commit("prism_lease", 1, now_ms=NOW)
            self.assertIn("so spending is refused", str(caught.exception))

    def test_an_entry_that_cannot_be_type_checked_refuses_the_file(self):
        os.makedirs(os.path.dirname(self.path))
        for entry in ('"x"', "null", '{"at": "now", "micros": 1}', '{"at": 1, "micros": "1"}',
                      '{"at": 1}', '{"micros": 1}', '{"at": 1, "micros": -5}', '{"at": -1, "micros": 5}',
                      '{"at": 1, "micros": true}'):
            Path(self.path).write_text('{"entries": [%s]}' % entry, encoding="utf-8")
            with self.assertRaises(BudgetError, msg=entry) as caught:
                self.ledger().remaining(NOW)
            self.assertIn("so spending is refused", str(caught.exception))

    def test_nan_and_infinity_are_not_numbers_a_ledger_may_hold(self):
        os.makedirs(os.path.dirname(self.path))
        for literal in ("NaN", "Infinity", "-Infinity"):
            Path(self.path).write_text('{"entries": [{"at": %d, "micros": %s}]}' % (NOW, literal), encoding="utf-8")
            with self.assertRaises(BudgetError, msg=literal):
                self.ledger().remaining(NOW)

    def test_bytes_that_are_not_utf8_are_refused(self):
        os.makedirs(os.path.dirname(self.path))
        Path(self.path).write_bytes(b'{"entries": [{"at": 1, "micros": 1, "tool": "\xff\xfe"}]}')
        with self.assertRaises(BudgetError):
            self.ledger().remaining(NOW)

    def test_a_byte_order_mark_is_a_ledger_and_not_a_corruption(self):
        os.makedirs(os.path.dirname(self.path))
        body = json.dumps({"version": 1, "entries": [{"id": "a", "at": NOW, "tool": "prism_lease", "micros": 400_000}]})
        Path(self.path).write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))
        book = self.ledger()
        self.assertEqual(book.remaining(NOW), 4_600_000)
        self.assertEqual(book.status(NOW)["spent_last_24h"], "0.400000 USDG")
        self.assertTrue(book.commit("prism_infer", 1, now_ms=NOW))

    def test_a_stamp_no_date_can_hold_refuses_the_file_in_both_languages(self):
        os.makedirs(os.path.dirname(self.path))
        for at in (2.6e14, MAX_AT_MS + 1):
            Path(self.path).write_text('{"entries": [{"at": %r, "micros": 1}]}' % at, encoding="utf-8")
            with self.assertRaises(BudgetError, msg=repr(at)) as caught:
                self.ledger().status(NOW)
            self.assertIn("an at a date can hold", str(caught.exception))
        Path(self.path).write_text('{"entries": [{"at": %d, "micros": 1}]}' % MAX_AT_MS, encoding="utf-8")
        self.assertEqual(
            self.ledger().status(MAX_AT_MS)["charges_last_24h"][0]["at"], "9999-12-31T23:59:59.999Z"
        )


class LockTest(LedgerCase):
    def test_a_lock_left_by_a_dead_process_is_broken(self):
        os.makedirs(os.path.dirname(self.path))
        lock = f"{self.path}.lock"
        Path(lock).write_text("", encoding="utf-8")
        os.utime(lock, (time.time() - 60, time.time() - 60))

        book = self.ledger(lock_wait_ms=200)
        book.commit("prism_lease", 400_000, now_ms=NOW)
        self.assertEqual(len(self.entries()), 1)
        self.assertFalse(os.path.exists(lock))

    def test_a_live_lock_times_out_and_charges_nothing(self):
        os.makedirs(os.path.dirname(self.path))
        lock = f"{self.path}.lock"
        Path(lock).write_text("", encoding="utf-8")

        with self.assertRaises(BudgetError) as caught:
            self.ledger(lock_wait_ms=100).commit("prism_lease", 400_000, now_ms=NOW)
        self.assertEqual(
            str(caught.exception),
            f"the spend ledger at {self.path} is locked by another Prism process; "
            "nothing was charged. Retry in a moment.",
        )
        self.assertFalse(os.path.exists(self.path))
        self.assertTrue(os.path.exists(lock))


class RecordSpendTest(LedgerCase):
    def test_a_success_settles_at_what_was_actually_paid(self):
        book = self.ledger()
        value = record_spend(
            book, "prism_lease", 400_000, lambda: {"value": "ok", "settled_micros": 90_000, "reference": "0xtx"}
        )
        self.assertEqual(value, "ok")
        entries = self.entries()
        self.assertEqual(entries[0]["micros"], 90_000)
        self.assertEqual(entries[0]["reference"], "0xtx")

    def test_a_failure_that_funded_an_escrow_keeps_its_entry(self):
        book = self.ledger()

        def run():
            raise Failure("result_failed", {"funding_hash": "0xfund"}, broadcast="0xfund")

        with self.assertRaises(Failure):
            record_spend(book, "prism_lease", 400_000, run)
        self.assertEqual(self.entries()[0]["micros"], 400_000)
        self.assertEqual(self.entries()[0]["reference"], "0xfund")

    def test_a_payment_the_endpoint_never_answered_keeps_its_entry(self):
        book = self.ledger()

        def run():
            raise Failure("payment_unverified", {"payment_tx": "0xpay"}, broadcast="0xpay")

        with self.assertRaises(Failure):
            record_spend(book, "prism_infer", 400_000, run)
        self.assertEqual(self.entries()[0]["reference"], "0xpay")

    def test_a_broadcast_that_could_not_be_read_back_stands_at_what_it_reserved(self):
        book = self.ledger()

        def run():
            raise Failure("chain_error")

        with self.assertRaises(Failure):
            record_spend(book, "prism_lease", 400_000, run)
        self.assertEqual(self.entries()[0]["micros"], 400_000)
        self.assertNotIn("reference", self.entries()[0])

    def test_a_failure_that_never_reached_the_chain_is_given_back(self):
        book = self.ledger()

        def run():
            raise Failure("bad_request", {"error": "nope"})

        with self.assertRaises(Failure):
            record_spend(book, "prism_lease", 400_000, run)
        self.assertEqual(self.entries(), [])

    def test_an_empty_broadcast_is_an_absence_and_not_a_receipt(self):
        book = self.ledger()

        def run():
            raise Failure("result_failed", {"funding_hash": "0xremote"}, broadcast="")

        with self.assertRaises(Failure):
            record_spend(book, "prism_lease", 400_000, run)
        self.assertEqual(self.entries(), [])

    def test_a_hash_the_control_plane_supplied_is_not_proof_that_money_moved(self):
        book = self.ledger()

        # The shape _agent.py raises when the control plane refuses before the
        # wallet has signed anything: `body` is the far side's own JSON.
        def run():
            raise PrismError(503, "no_capacity", {"error": "no_capacity", "funding_hash": "0xSERVERCHOSEN"})

        for _ in range(6):
            with self.assertRaises(PrismError):
                record_spend(book, "prism_lease_and_run", 500_000, run)
        self.assertEqual(self.entries(), [])
        self.assertEqual(book.remaining(), 5_000_000)

    def test_an_outcome_that_is_not_a_mapping_keeps_the_entry_and_says_why(self):
        book = self.ledger()
        for outcome in ("ok", 7, None, ["value"]):
            book_entries_before = len(self.entries()) if os.path.exists(self.path) else 0
            with self.assertRaises(BudgetError, msg=repr(outcome)) as caught:
                record_spend(book, "prism_lease", 400_000, lambda: outcome)
            self.assertIn("where the ledger needs a mapping", str(caught.exception))
            self.assertEqual(len(self.entries()), book_entries_before + 1)
            self.assertEqual(self.entries()[-1]["micros"], 400_000)

    def test_a_ledger_that_cannot_be_reconciled_never_masks_the_outcome(self):
        book = self.ledger()

        def explode(*_args, **_kwargs):
            raise BudgetError("ledger is on fire")

        book.settle = explode
        paid = {"value": 7, "settled_micros": 1, "reference": None}
        noise = io.StringIO()
        with redirect_stderr(noise):
            value = record_spend(book, "prism_lease", 400_000, lambda: paid)
        self.assertEqual(value, 7)
        self.assertIn(
            "prism mcp: could not settle the ledger entry for prism_lease: ledger is on fire", noise.getvalue()
        )
        self.assertEqual(self.entries()[0]["micros"], 400_000)


class SettleClampTest(LedgerCase):
    def test_a_settlement_above_the_reservation_is_refused_and_said_aloud(self):
        book = self.ledger()
        entry_id = book.commit("prism_lease", 400_000, now_ms=NOW)
        noise = io.StringIO()
        with redirect_stderr(noise):
            self.assertTrue(book.settle(entry_id, micros=900_000, reference="0xtx"))
        self.assertEqual(self.entries()[0]["micros"], 400_000)
        self.assertEqual(self.entries()[0]["reference"], "0xtx")
        self.assertIn("above the 0.400000 USDG reserved", noise.getvalue())

    def test_a_settlement_onto_an_earlier_charge_cannot_raise_it_either(self):
        book = self.ledger()
        first = book.commit("prism_infer", 300_000, now_ms=NOW)
        book.settle(first, micros=100_000, reference="0xpaid")
        retry = book.commit("prism_infer", 300_000, now_ms=NOW)
        with redirect_stderr(io.StringIO()):
            book.settle(retry, micros=300_000, reference="0xpaid")
        self.assertEqual(self.entries()[0]["micros"], 100_000)
        self.assertEqual(book.remaining(NOW), 4_900_000)


class WriteTest(LedgerCase):
    def test_a_pre_seeded_temp_file_cannot_lend_the_ledger_its_permissions(self):
        os.makedirs(os.path.dirname(self.path))
        tmp = f"{self.path}.{os.getpid()}.tmp"
        Path(tmp).write_text("stale", encoding="utf-8")
        os.chmod(tmp, 0o666)
        self.ledger().commit("prism_lease", 1, now_ms=NOW)
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), "0o600")
        self.assertFalse(os.path.exists(tmp))

    def test_a_symlinked_ledger_is_written_through_rather_than_replaced(self):
        os.makedirs(os.path.dirname(self.path))
        real = os.path.join(self.dir, "real-spend.json")
        Path(real).write_text('{"version": 1, "entries": []}\n', encoding="utf-8")
        os.symlink(real, self.path)
        self.ledger().commit("prism_lease", 400_000, now_ms=NOW)
        self.assertTrue(os.path.islink(self.path))
        self.assertEqual(json.loads(Path(real).read_text(encoding="utf-8"))["entries"][0]["micros"], 400_000)

    def test_a_symlinked_ledger_whose_target_is_not_there_yet_is_created_through_the_link(self):
        os.makedirs(os.path.dirname(self.path))
        real = os.path.join(self.dir, "real-spend.json")
        os.symlink(real, self.path)
        self.ledger().commit("prism_lease", 400_000, now_ms=NOW)
        self.assertTrue(os.path.islink(self.path), "the first write replaced the link with a file")
        self.assertEqual(json.loads(Path(real).read_text(encoding="utf-8"))["entries"][0]["micros"], 400_000)

    def test_an_entry_id_is_not_a_number_a_caller_sharing_the_file_can_reproduce(self):
        random.seed(7)
        first = _new_id(NOW)
        random.seed(7)
        self.assertNotEqual(_new_id(NOW), first, "the suffix came from a generator a caller can seed")
        self.assertRegex(first, r"^[0-9a-z]+-[0-9a-f]{16}$")

    def test_status_leaves_out_a_tool_the_entry_never_had(self):
        os.makedirs(os.path.dirname(self.path))
        Path(self.path).write_text(
            json.dumps({"version": 1, "entries": [{"id": "x", "at": FIXED, "micros": 5}]}), encoding="utf-8"
        )
        charge = self.ledger().status(FIXED)["charges_last_24h"][0]
        self.assertEqual(charge, {"at": "2025-08-24T01:46:40.000Z", "amount": "0.000005 USDG"})

    def test_a_float_clock_still_produces_an_id(self):
        book = self.ledger()
        entry_id = book.commit("prism_lease", 1, now_ms=NOW + 0.5)
        self.assertTrue(entry_id.startswith(f"{_new_id(NOW).split('-')[0]}-"))


class LockOwnershipTest(LedgerCase):
    def _await(self, path: str, timeout: float = 10.0) -> bytes:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                body = Path(path).read_bytes()
            except OSError:
                body = b""
            if body:
                return body
            time.sleep(0.02)
        raise AssertionError(f"{path} never appeared")

    def _holder(self, mark: str, hold: str) -> subprocess.Popen:
        held = subprocess.Popen([sys.executable, "-c", HOLDER, self.path, mark, hold])
        self.addCleanup(held.kill)
        return held

    # The clock stepping forward past LOCK_STALE_MS is enough to make a live
    # lock look abandoned, and before the token the holder came back and deleted
    # the lock its breaker was working under.
    def test_a_holder_never_deletes_the_lock_that_broke_it(self):
        os.makedirs(os.path.dirname(self.path))
        lock = f"{self.path}.lock"
        first = self._holder(os.path.join(self.dir, "a"), "2")
        mine = self._await(lock)

        old = time.time() - 60
        os.utime(lock, (old, old))
        second = self._holder(os.path.join(self.dir, "b"), "6")
        self._await(os.path.join(self.dir, "b"))
        theirs = Path(lock).read_bytes()
        self.assertNotEqual(theirs, mine, "the breaker took the lock without claiming it")

        self.assertEqual(first.wait(timeout=20), 0)
        self.assertEqual(Path(lock).read_bytes(), theirs, "the holder deleted a lock it did not own")
        with self.assertRaises(BudgetError):
            self.ledger(lock_wait_ms=100).commit("prism_lease", 1, now_ms=NOW)

        self.assertEqual(second.wait(timeout=20), 0)
        self.assertFalse(os.path.exists(lock), "the owner left its lock behind")

    def _script(self, source: str, *args: str) -> subprocess.Popen:
        child = subprocess.Popen([sys.executable, "-c", source, self.path, *args],
                                 stderr=subprocess.PIPE, text=True)
        self.addCleanup(child.stderr.close)
        self.addCleanup(child.kill)
        return child

    # Both halves of what keeps two writers out of one file once a lock has been
    # broken: a live holder refreshes its lock while it works, and a write whose
    # lock changed hands anyway is abandoned rather than published.
    def test_a_lock_a_live_holder_is_inside_is_not_read_as_abandoned(self):
        os.makedirs(os.path.dirname(self.path))
        lock = f"{self.path}.lock"
        slow = self._script(SLOW_WRITER, f"{self.path}.read", "0.2", "3")
        self._await(f"{self.path}.read")
        old = time.time() - 60
        os.utime(lock, (old, old))

        self._await(f"{self.path}.read.written")
        time.sleep(LOCK_HEARTBEAT_S + 0.5)
        self.assertLess(time.time() - os.stat(lock).st_mtime, LOCK_STALE_MS / 1000,
                        "a live holder's lock aged into staleness")
        with self.assertRaises(BudgetError):
            self.ledger(lock_wait_ms=100).commit("prism_lease", 1, now_ms=NOW)
        self.assertEqual(slow.wait(timeout=20), 0)

    def test_a_write_whose_lock_was_broken_under_it_is_refused(self):
        os.makedirs(os.path.dirname(self.path))
        slow = self._script(SLOW_WRITER, f"{self.path}.read", "3", "0")
        self._await(f"{self.path}.read")
        breaker = self._script(BREAKER)

        self.assertEqual(breaker.wait(timeout=20), 0, breaker.stderr.read())
        self.assertEqual(slow.wait(timeout=20), 1,
                         "the slower write published under a lock it no longer held")
        self.assertIn("lost the ledger lock; nothing written", slow.stderr.read())
        self.assertFalse(os.path.exists(f"{self.path}.read.written"))
        self.assertEqual([e["micros"] for e in self.entries()], [100_000],
                         "the slower write erased the charge of the process that broke its lock")

    def test_two_processes_cannot_both_be_inside_the_ledger(self):
        os.makedirs(os.path.dirname(self.path))
        held = self._holder(os.path.join(self.dir, "a"), "2")
        self._await(os.path.join(self.dir, "a"))
        with self.assertRaises(BudgetError):
            self.ledger(lock_wait_ms=100).commit("prism_lease", 1, now_ms=NOW)
        self.assertEqual(held.wait(timeout=20), 0)
        self.assertTrue(self.ledger(lock_wait_ms=100).commit("prism_lease", 1, now_ms=NOW))

    # A link is how one wallet's ledger ends up configured under two names, and
    # a lock named after the caller's spelling would let both names inside the
    # file at once. Each would have read the day's total before the other's
    # charge existed, and the one that wrote second would erase it.
    def test_one_ledger_reached_by_two_names_is_one_lock(self):
        os.makedirs(os.path.dirname(self.path))
        target = os.path.join(self.dir, "real.json")
        os.symlink(target, self.path)
        held = self._holder(os.path.join(self.dir, "a"), "2")
        self._await(os.path.join(self.dir, "a"))

        with self.assertRaises(BudgetError):
            SpendLedger(target, 5_000_000, 1_000_000, lock_wait_ms=100).commit("prism_lease", 1, now_ms=NOW)
        self.assertEqual(held.wait(timeout=20), 0)
        self.assertTrue(
            SpendLedger(target, 5_000_000, 1_000_000, lock_wait_ms=100).commit("prism_lease", 1, now_ms=NOW)
        )


class ToolsetBudgetTest(LedgerCase):
    class Agent:
        def __init__(self, escrow_micros=None, fail=None, quoted=None):
            self.escrow_micros = escrow_micros
            self.fail = fail
            # What the far side says the escrow holds, where that is not what
            # this wallet deposited.
            self.quoted = quoted
            self.leases = []

        def lease(self, **kwargs):
            self.leases.append(kwargs)
            if self.fail is not None:
                raise self.fail
            held = self.escrow_micros if self.escrow_micros is not None else kwargs["max_deposit"]
            return Lease(
                lease_id=7,
                access={},
                key_path="",
                key_dir="",
                public_key="",
                funding_hash="0xfund",
                quote={"maximum_escrow": self.quoted if self.quoted is not None else held},
                deposit_micros=held,
            )

        def run(self, lease, command):
            return {"code": 0, "stdout": "ok", "stderr": ""}

    def toolset(self, agent, daily=5_000_000, per_call=1_000_000):
        return PrismToolset(agent=agent, budget=self.ledger(daily=daily, per_call=per_call))

    def test_a_model_asking_for_ten_funds_the_operators_one(self):
        agent = self.Agent()
        tools = self.toolset(agent)
        self.assertIn("lease 7 funded onchain", tools.lease_and_run("nvidia-smi", max_usdg=10))
        self.assertEqual(agent.leases[0]["max_deposit"], 1_000_000)
        self.assertEqual(tools.ledger.remaining(), 4_000_000)

    def test_an_omitted_cap_takes_the_operators_ceiling(self):
        agent = self.Agent()
        self.toolset(agent).lease_and_run("nvidia-smi")
        self.assertEqual(agent.leases[0]["max_deposit"], 1_000_000)

    def test_a_lower_cap_from_the_model_is_honoured(self):
        agent = self.Agent()
        tools = self.toolset(agent)
        tools.lease_and_run("nvidia-smi", max_usdg=0.25)
        self.assertEqual(agent.leases[0]["max_deposit"], 250_000)
        self.assertEqual(tools.ledger.remaining(), 4_750_000)

    def test_the_day_is_charged_what_the_escrow_holds(self):
        agent = self.Agent(escrow_micros=200_000)
        tools = self.toolset(agent)
        tools.lease_and_run("nvidia-smi")
        self.assertEqual(tools.ledger.remaining(), 4_800_000)
        self.assertEqual(self.entries()[0]["reference"], "0xfund")

    def test_the_day_is_charged_what_was_deposited_and_not_what_the_quote_says(self):
        # The quote is the other side's document. A remote that raises its own
        # figure after the deposit must not raise what the day is charged.
        agent = self.Agent(escrow_micros=200_000, quoted=900_000)
        tools = self.toolset(agent)
        tools.lease_and_run("nvidia-smi")
        self.assertEqual(tools.ledger.remaining(), 4_800_000)

    def test_a_deposit_above_the_reservation_is_charged_at_the_reservation(self):
        agent = self.Agent(escrow_micros=9_000_000)
        tools = self.toolset(agent)
        tools.lease_and_run("nvidia-smi")
        self.assertEqual(tools.ledger.remaining(), 4_000_000)

    def test_the_daily_cap_refuses_before_anything_is_funded(self):
        agent = self.Agent()
        tools = self.toolset(agent, daily=1_000_000)
        tools.lease_and_run("nvidia-smi")
        refusal = tools.lease_and_run("nvidia-smi")
        self.assertIn("past the 1.000000 USDG daily cap", refusal)
        self.assertIn("Nothing was charged", refusal)
        self.assertEqual(len(agent.leases), 1, "the wallet was asked to fund a lease the budget refused")

    def test_a_lease_that_never_funded_gives_the_reservation_back(self):
        agent = self.Agent(fail=PrismError(402, "cost_exceeds_max", {"required": 9, "max": "1"}))
        tools = self.toolset(agent)
        self.assertIn("The lease did not go through", tools.lease_and_run("nvidia-smi"))
        self.assertEqual(tools.ledger.remaining(), 5_000_000)

    def test_a_lease_funded_before_the_failure_keeps_its_entry(self):
        agent = self.Agent(
            fail=PrismError(502, "lease_failed_after_funding", {"funding_hash": "0xfund"}, broadcast="0xfund")
        )
        tools = self.toolset(agent)
        self.assertIn("The lease did not go through", tools.lease_and_run("nvidia-smi"))
        self.assertEqual(tools.ledger.remaining(), 4_000_000)
        self.assertEqual(self.entries()[0]["reference"], "0xfund")

    # The two shapes PrismAgent.lease now raises, and what the day is charged
    # for each: a deposit the chain took counts even when reading it back
    # failed, and a failure before the wire costs nothing.
    def test_a_deposit_whose_receipt_never_arrived_is_charged_against_the_day(self):
        agent = self.Agent(fail=PrismError(504, "confirmation_timeout",
                                           {"hash": "0xfund", "funding_hash": "0xfund"}, "0xfund"))
        tools = self.toolset(agent)
        self.assertIn("The lease did not go through", tools.lease_and_run("nvidia-smi"))
        self.assertEqual(tools.ledger.remaining(), 4_000_000)
        self.assertEqual(self.entries()[0]["reference"], "0xfund")

    def test_a_failure_before_the_wire_gives_the_reservation_back(self):
        agent = self.Agent(fail=PrismError(502, "pre_broadcast_failure",
                                           {"cause": "rpc refused the connection"}, broadcast=False))
        tools = self.toolset(agent)
        self.assertIn("The lease did not go through", tools.lease_and_run("nvidia-smi"))
        self.assertEqual(tools.ledger.remaining(), 5_000_000)

    def test_a_max_usdg_that_is_not_a_number_is_refused_without_leasing(self):
        agent = self.Agent()
        self.assertEqual(
            self.toolset(agent).lease_and_run("nvidia-smi", max_usdg=-1), "max_usdg must be a positive number of USDG."
        )
        self.assertEqual(agent.leases, [])

    def test_limits_the_operator_got_wrong_stop_spending_and_leave_reading_alone(self):
        agent = self.Agent()
        tools = PrismToolset(agent=agent, budget=None)
        self.assertEqual(tools.lease_and_run("nvidia-smi"), f"This spends money and the spend limits are unusable: {NO_BUDGET}")
        self.assertEqual(agent.leases, [])
        self.assertEqual(tools.budget_status(), NO_BUDGET)

    def test_status_reads_like_the_mcp_servers(self):
        agent = self.Agent(escrow_micros=250_000)
        tools = self.toolset(agent)
        tools.lease_and_run("nvidia-smi")
        status = tools.budget_status()
        self.assertIn("daily budget: 5.000000 USDG", status)
        self.assertIn("spent in the last 24h: 0.250000 USDG", status)
        self.assertIn("remaining today: 4.750000 USDG", status)
        self.assertIn("max per call: 1.000000 USDG", status)
        self.assertIn(f"ledger: {self.path}", status)
        self.assertIn("prism_lease_and_run 0.250000 USDG (0xfund)", status)

    def test_an_empty_day_says_so(self):
        self.assertIn("charges in the last 24h: none", self.toolset(self.Agent()).budget_status())


class CrossLanguageTest(LedgerCase):
    @unittest.skipUnless(shutil.which("node") and NODE_MODULE.exists(), "needs node and a checkout")
    def test_both_sdks_count_the_same_wallet(self):
        book = self.ledger(daily=5_000_000, per_call=1_000_000)
        book.commit("prism_lease", 400_000, now_ms=NOW - 1000)
        settled = book.commit("prism_infer", 900_000, now_ms=NOW - 500)
        book.settle(settled, micros=250_000, reference="0xtx")
        book.commit("prism_lease", 750_000, now_ms=NOW - DAY_MS - 1)  # outside the window for both

        script = """
            import { SpendLedger } from %s;
            const [path, now] = process.argv.slice(1);
            const book = new SpendLedger({ ledgerPath: path, dailyMicros: 5_000_000, maxPerCallMicros: 1_000_000 });
            console.log(JSON.stringify({ remaining: book.remaining(Number(now)) }));
        """ % json.dumps(str(NODE_MODULE))
        out = subprocess.run(
            ["node", "--input-type=module", "-e", script, self.path, str(NOW)],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(out.stdout)["remaining"], book.remaining(NOW))
        self.assertEqual(book.remaining(NOW), 5_000_000 - 650_000)

    @unittest.skipUnless(shutil.which("node") and NODE_MODULE.exists(), "needs node and a checkout")
    def test_both_sdks_write_the_same_money_and_the_same_dates(self):
        # Exact ties are micros = 7812.5 x an odd number, which is where
        # Python's round-half-even and JavaScript's round-half-up part company.
        micros = [7812.5 * odd for odd in range(1, 40, 2)] + [0, 1, 999_999, 1_000_000, 12_345_678]
        stamps = [0, 1, 2.5, NOW, MAX_AT_MS]
        script = """
            import { usdg, SpendLedger } from %s;
            const [path, figures, stamps] = process.argv.slice(1);
            const book = new SpendLedger({ ledgerPath: path, dailyMicros: 0, maxPerCallMicros: 1e12 });
            console.log(JSON.stringify({
                money: JSON.parse(figures).map(usdg),
                dates: JSON.parse(stamps).map((at) => new Date(at).toISOString()),
                status: book.status(Number(%d)),
            }));
        """ % (json.dumps(str(NODE_MODULE)), MAX_AT_MS)
        book = self.ledger(daily=0, per_call=1_000_000_000_000)
        for at in stamps:
            book.commit("prism_infer", 7812.5, now_ms=at)
        out = subprocess.run(
            ["node", "--input-type=module", "-e", script, self.path, json.dumps(micros), json.dumps(stamps)],
            capture_output=True,
            text=True,
            check=True,
        )
        node = json.loads(out.stdout)
        self.assertEqual(node["money"], [usdg(m) for m in micros])
        self.assertEqual(node["dates"], [_iso(at) for at in stamps])
        self.assertEqual(node["status"], book.status(MAX_AT_MS))

    @unittest.skipUnless(shutil.which("node"), "needs node")
    def test_both_sdks_round_a_half_the_same_way(self):
        doubles = [0.49999999999999994, 0.5, 1.5, 2.5, -0.5, -1.5, 0.1 + 0.2, 4_503_599_627_370_497.0]
        script = "console.log(JSON.stringify(JSON.parse(process.argv[1]).map(Math.round)));"
        out = subprocess.run(
            ["node", "-e", script, json.dumps(doubles)], capture_output=True, text=True, check=True
        )
        self.assertEqual(json.loads(out.stdout), [_round(d) for d in doubles])
        self.assertEqual(_round(0.49999999999999994), 0)


if __name__ == "__main__":
    unittest.main()
