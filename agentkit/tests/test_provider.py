"""What the AgentKit actions are allowed to spend.

``max_usdg`` arrives on the action schema, which means a model writes it. It
bounds one lease and says nothing about the fortieth in a row, so the provider
goes through the same ledger the MCP server and the Python SDK write: the
operator's per-call cap clamps every lease and the daily cap ends the day.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from prism_agentkit import PrismActionProvider
from prismnetwork import Lease, SpendLedger
from prismnetwork.toolkit import NO_BUDGET

PREFIX = "PrismActionProvider_"


class Agent:
    address = "0x0000000000000000000000000000000000000001"

    def __init__(self, escrow_micros=None):
        self.escrow_micros = escrow_micros
        self.leases = []
        self.ended = []

    def balances(self):
        return {"address": self.address, "usdg": 1_250_000, "eth": 2 * 10**18}

    def offers(self, min_trust="open"):
        return [{"gpu": {"model": "Test GPU", "vram_mib": 24_576}, "rate_per_second": 25, "trust_class": "isolated"}]

    def lease(self, **kwargs):
        self.leases.append(kwargs)
        held = self.escrow_micros if self.escrow_micros is not None else kwargs["max_deposit"]
        return Lease(
            lease_id=7,
            access={},
            key_path="",
            key_dir="",
            public_key="",
            # One transaction per deposit, as the chain gives them out.
            funding_hash=f"0xfund{len(self.leases)}",
            quote={"maximum_escrow": held},
            # What the escrow pulled, which is what the day is charged. The
            # quote's figure is a ceiling and settling against it overcharges
            # the budget for every lease that ran short of it.
            deposit_micros=held,
            deposit_source="receipt",
        )

    def run(self, lease, command):
        return {"code": 0, "stdout": f"{lease.lease_id}:{command}", "stderr": ""}

    def end_lease(self, lease):
        self.ended.append(lease.lease_id)


class ProviderCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "spend.json")
        self.analytics = patch("coinbase_agentkit.action_providers.action_decorator.send_analytics_event")
        self.analytics.start()
        self.addCleanup(self.analytics.stop)

    def provider(self, agent, daily=5_000_000, per_call=1_000_000):
        book = SpendLedger(self.path, daily, per_call)
        return PrismActionProvider(agent, budget=book)

    def actions(self, provider):
        return {action.name.removeprefix(PREFIX): action for action in provider.get_actions(None)}


class SpendingTest(ProviderCase):
    def test_every_action_the_provider_advertises(self):
        actions = self.actions(self.provider(Agent()))
        self.assertEqual(set(actions), {"budget", "wallet", "list_gpus", "lease_and_run", "run", "end_lease"})

    def test_a_model_asking_for_ten_funds_the_operators_one(self):
        agent = Agent()
        provider = self.provider(agent)
        answer = self.actions(provider)["lease_and_run"].invoke({"command": "nvidia-smi", "max_usdg": 10})
        self.assertIn("lease 7 funded onchain", answer)
        self.assertEqual(agent.leases[0]["max_deposit"], 1_000_000)
        self.assertEqual(provider.tools.ledger.remaining(), 4_000_000)

    def test_an_omitted_cap_takes_the_operators_ceiling(self):
        agent = Agent()
        self.actions(self.provider(agent))["lease_and_run"].invoke({"command": "nvidia-smi"})
        self.assertEqual(agent.leases[0]["max_deposit"], 1_000_000)

    def test_a_lower_cap_from_the_model_is_honoured(self):
        agent = Agent()
        actions = self.actions(self.provider(agent))
        actions["lease_and_run"].invoke(
            {
                "command": "nvidia-smi",
                "duration_seconds": 120,
                "min_vram_mib": 8192,
                "max_usdg": 0.25,
                "min_trust_class": "isolated",
            }
        )
        self.assertEqual(agent.leases[0]["max_deposit"], 250_000)
        self.assertEqual(agent.leases[0]["min_trust_class"], "isolated")

    def test_the_fortieth_lease_in_a_row_is_the_one_the_day_refuses(self):
        agent = Agent()
        actions = self.actions(self.provider(agent, daily=2_000_000))
        for _ in range(2):
            self.assertIn("lease 7 funded onchain", actions["lease_and_run"].invoke({"command": "nvidia-smi"}))
        refusal = actions["lease_and_run"].invoke({"command": "nvidia-smi"})
        self.assertIn("past the 2.000000 USDG daily cap", refusal)
        self.assertIn("Nothing was charged", refusal)
        self.assertEqual(len(agent.leases), 2, "the wallet was asked to fund a lease the budget refused")

    def test_the_day_is_charged_what_the_escrow_holds(self):
        provider = self.provider(Agent(escrow_micros=200_000))
        self.actions(provider)["lease_and_run"].invoke({"command": "nvidia-smi"})
        self.assertEqual(provider.tools.ledger.remaining(), 4_800_000)

    def test_the_budget_action_reads_the_shared_ledger(self):
        provider = self.provider(Agent(escrow_micros=250_000))
        actions = self.actions(provider)
        actions["lease_and_run"].invoke({"command": "nvidia-smi"})
        status = actions["budget"].invoke({})
        self.assertIn("daily budget: 5.000000 USDG", status)
        self.assertIn("spent in the last 24h: 0.250000 USDG", status)
        self.assertIn(f"ledger: {self.path}", status)

    def test_limits_the_operator_got_wrong_stop_spending_and_leave_reading_alone(self):
        agent = Agent()
        actions = self.actions(PrismActionProvider(agent, budget=None))
        self.assertEqual(
            actions["lease_and_run"].invoke({"command": "nvidia-smi"}),
            f"This spends money and the spend limits are unusable: {NO_BUDGET}",
        )
        self.assertEqual(agent.leases, [])
        self.assertEqual(actions["budget"].invoke({}), NO_BUDGET)
        self.assertIn("Test GPU", actions["list_gpus"].invoke({}))


class SessionTest(ProviderCase):
    def test_a_lease_stays_open_for_follow_up_commands(self):
        agent = Agent()
        actions = self.actions(self.provider(agent))
        actions["lease_and_run"].invoke({"command": "nvidia-smi"})
        self.assertTrue(actions["run"].invoke({"lease_id": 7, "command": "echo ready"}).endswith("7:echo ready"))
        self.assertTrue(actions["end_lease"].invoke({"lease_id": 7}).startswith("released lease 7"))
        self.assertEqual(agent.ended, [7])
        self.assertEqual(actions["run"].invoke({"lease_id": 7, "command": "x"}), "No active lease 7 in this session.")

    def test_the_wallet_reads_without_spending(self):
        provider = self.provider(Agent())
        self.assertIn("1.250000 USDG", self.actions(provider)["wallet"].invoke({}))
        self.assertEqual(provider.tools.ledger.remaining(), 5_000_000)


if __name__ == "__main__":
    unittest.main()
