"""The spend-authorisation layer: a decision gates the money and binds to it."""

from __future__ import annotations

import unittest

from web3 import Web3

from prismnetwork._decision import (
    Answer,
    Decision,
    DecisionRefused,
    Policy,
    lease_reference,
    reference_matches,
)

LEASE = Decision(
    action="lease",
    source="jev-1.13.0",
    policy_id="gpu-spend-v1",
    answers=(
        Answer(name="needs_gpu", value=0.94, confidence=0.91),
        Answer(name="worth_escrow", value=True, confidence=0.88),
    ),
)
POLICY = Policy(
    policy_id="gpu-spend-v1",
    allow=frozenset({"lease"}),
    minimums={"needs_gpu": 0.8},
    require=frozenset({"worth_escrow"}),
)


class PolicyTest(unittest.TestCase):
    def test_a_decision_that_clears_the_policy_is_authorised(self):
        self.assertIs(POLICY.authorise(LEASE), LEASE)

    def test_an_action_outside_the_policy_never_reaches_the_wallet(self):
        wrong = Decision(action="drain", source="jev-1.13.0", policy_id="gpu-spend-v1",
                         answers=LEASE.answers)
        with self.assertRaises(DecisionRefused) as refused:
            POLICY.authorise(wrong)
        self.assertIn("not in the policy's allowed set", str(refused.exception))

    def test_confidence_under_the_floor_is_refused_and_says_by_how_much(self):
        weak = Decision(action="lease", source="jev-1.13.0", policy_id="gpu-spend-v1",
                        answers=(Answer("needs_gpu", 0.94, 0.62),
                                 Answer("worth_escrow", True, 0.88)))
        with self.assertRaises(DecisionRefused) as refused:
            POLICY.authorise(weak)
        self.assertIn("0.62", str(refused.exception))
        self.assertIn("0.8", str(refused.exception))

    def test_a_missing_answer_is_refused_rather_than_read_as_zero(self):
        # A source that declined to answer has said nothing, which is not the
        # same as a weak yes and must not be scored as one.
        silent = Decision(action="lease", source="jev-1.13.0", policy_id="gpu-spend-v1",
                          answers=(Answer("needs_gpu", 0.94, 0.91),))
        with self.assertRaises(DecisionRefused) as refused:
            POLICY.authorise(silent)
        self.assertIn("worth_escrow", str(refused.exception))

    def test_an_answer_without_confidence_cannot_satisfy_a_floor(self):
        bare = Decision(action="lease", source="rule:always", policy_id="gpu-spend-v1",
                        answers=(Answer("needs_gpu", True), Answer("worth_escrow", True)))
        with self.assertRaises(DecisionRefused):
            POLICY.authorise(bare)

    def test_a_decision_citing_another_policy_is_refused(self):
        other = Decision(action="lease", source="jev-1.13.0", policy_id="someone-elses",
                         answers=LEASE.answers)
        with self.assertRaises(DecisionRefused) as refused:
            POLICY.authorise(other)
        self.assertIn("someone-elses", str(refused.exception))

    def test_every_refusal_is_reported_at_once(self):
        # A caller fixing one threshold at a time learns the next failure only
        # after spending another round trip on the source that judged.
        bad = Decision(action="drain", source="x", policy_id="gpu-spend-v1",
                       answers=(Answer("needs_gpu", 0.1, 0.1),))
        with self.assertRaises(DecisionRefused) as refused:
            POLICY.authorise(bad)
        self.assertEqual(len(refused.exception.reasons), 3)


class ReferenceTest(unittest.TestCase):
    def test_a_lease_without_a_decision_keeps_the_reference_it_always_had(self):
        self.assertEqual(
            lease_reference("quote-1", None, Web3.keccak),
            bytes(Web3.keccak(text="quote-1")),
        )

    def test_a_decision_changes_the_reference_and_verifies_against_it(self):
        ref = lease_reference("quote-1", LEASE, Web3.keccak)
        self.assertNotEqual(ref, bytes(Web3.keccak(text="quote-1")))
        self.assertTrue(reference_matches("quote-1", LEASE, ref, Web3.keccak))

    def test_a_different_decision_does_not_match_the_lease_it_did_not_fund(self):
        ref = lease_reference("quote-1", LEASE, Web3.keccak)
        other = Decision(action="lease", source="jev-1.13.0", policy_id="gpu-spend-v1",
                         answers=(Answer("needs_gpu", 0.94, 0.90),
                                  Answer("worth_escrow", True, 0.88)))
        self.assertFalse(reference_matches("quote-1", other, ref, Web3.keccak))

    def test_the_same_decision_on_two_quotes_gives_two_references(self):
        # The escrow rejects a client reference it has already seen, so leaving
        # the quote id out of the preimage would make a repeated decision
        # unfundable the second time.
        first = lease_reference("quote-1", LEASE, Web3.keccak)
        second = lease_reference("quote-2", LEASE, Web3.keccak)
        self.assertNotEqual(first, second)

    def test_answer_order_does_not_change_the_reference(self):
        reordered = Decision(action=LEASE.action, source=LEASE.source,
                             policy_id=LEASE.policy_id,
                             answers=tuple(reversed(LEASE.answers)))
        self.assertEqual(
            lease_reference("quote-1", LEASE, Web3.keccak),
            lease_reference("quote-1", reordered, Web3.keccak),
        )

    def test_a_hex_reference_read_back_off_chain_still_matches(self):
        ref = lease_reference("quote-1", LEASE, Web3.keccak)
        self.assertTrue(reference_matches("quote-1", LEASE, "0x" + ref.hex(), Web3.keccak))


class ShapeTest(unittest.TestCase):
    def test_a_decision_must_say_what_judged_it(self):
        with self.assertRaises(ValueError):
            Decision(action="lease", source="  ")

    def test_confidence_outside_zero_to_one_is_refused(self):
        with self.assertRaises(ValueError):
            Answer(name="needs_gpu", value=True, confidence=1.4)

    def test_two_answers_cannot_share_a_name(self):
        with self.assertRaises(ValueError):
            Decision(action="lease", source="x",
                     answers=(Answer("needs_gpu", True), Answer("needs_gpu", False)))




class FundingGateTest(unittest.TestCase):
    """The gate has to sit before the money, not beside it."""

    def _agent(self):
        from prismnetwork._agent import PrismAgent
        agent = PrismAgent.__new__(PrismAgent)
        agent._funded = []
        agent._fund = lambda quote, decision=None: agent._funded.append(decision)
        return agent

    def test_a_refused_decision_never_reaches_the_funding_call(self):
        from prismnetwork import DecisionRefused, Policy, Decision
        agent = self._agent()
        weak = Decision(action="lease", source="jev-1.13.0", policy_id="gpu-spend-v1",
                        answers=(Answer("needs_gpu", 0.9, 0.10),
                                 Answer("worth_escrow", True, 0.9)))
        with self.assertRaises(DecisionRefused):
            agent.fund_quote({"quote_id": "q"}, decision=weak, policy=POLICY)
        self.assertEqual(agent._funded, [], "the wallet was reached despite a refusal")

    def test_a_policy_with_no_decision_at_all_is_refused(self):
        from prismnetwork import DecisionRefused
        agent = self._agent()
        with self.assertRaises(DecisionRefused):
            agent.fund_quote({"quote_id": "q"}, policy=POLICY)
        self.assertEqual(agent._funded, [])


if __name__ == "__main__":
    unittest.main()
