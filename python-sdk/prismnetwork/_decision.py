"""Authorise a spend before it happens, and bind the reason to the lease.

An agent with a wallet can fund an escrow on its own judgement. The operator
who owns that wallet gets the bill and, today, no answer to "why did it spend
this". Recording the reason afterwards does not help: a log written by the
process that spent the money is worth what that process says it is worth.

So the reason is decided first, checked against a policy the caller wrote, and
hashed into the one field the escrow already commits on chain. A lease that was
not authorised never gets funded, and a lease that was carries a reference
nobody can recompute without producing the decision it was funded under.

What this proves and what it does not. It proves a specific decision existed
before the deposit was broadcast and that the caller's own thresholds admitted
it. It says nothing about whether the decision was any good: a confidently
wrong judgement binds exactly as well as a correct one. This is provenance for
a stated reason, not a claim that the reason was sound.

The decision can come from anywhere. A System One model returning calibrated
probabilities, a general model, or a rule in the caller's own code all produce
the same record here, and none of them is a dependency of this SDK. Nothing in
the decision leaves the caller's process except its hash.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")


class DecisionRefused(Exception):
    """The policy did not admit the decision, so nothing was signed or sent."""

    def __init__(self, reasons: list):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


@dataclass(frozen=True)
class Answer:
    """One typed answer. ``value`` is the selected option, the score, or the
    probability that a yes/no question is yes; ``confidence`` is how sure the
    source is that the value is right, which is a different axis and is what a
    threshold should usually read."""

    name: str
    value: object
    confidence: float | None = None

    def __post_init__(self):
        if not _NAME.fullmatch(self.name):
            raise ValueError(f"answer name {self.name!r} is not a lowercase identifier")
        if self.confidence is not None and not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError(f"{self.name}: confidence {self.confidence} is outside 0..1")


@dataclass(frozen=True)
class Decision:
    """Why a spend is about to happen, in a form that hashes deterministically.

    ``source`` names what produced it, for example ``"jev-1.13.0"`` or
    ``"policy:cpu-first"``. It is recorded rather than trusted: this SDK cannot
    tell a model's answer from one a caller typed, and does not pretend to.
    """

    action: str
    source: str
    answers: tuple = ()
    policy_id: str | None = None

    def __post_init__(self):
        if not self.action.strip():
            raise ValueError("a decision needs an action")
        if not self.source.strip():
            raise ValueError("a decision needs a source, so the record says what judged")
        seen = set()
        for answer in self.answers:
            if not isinstance(answer, Answer):
                raise TypeError("answers must be Answer instances")
            if answer.name in seen:
                raise ValueError(f"duplicate answer {answer.name!r}")
            seen.add(answer.name)

    def answer(self, name: str) -> Answer | None:
        return next((a for a in self.answers if a.name == name), None)

    def canonical(self) -> bytes:
        """The exact bytes that get hashed.

        Sorted by name and separator-pinned, so the same decision produces the
        same reference on any machine and in any language. A verifier that
        rebuilds this from a stored decision reaches the same digest or the
        decision is not the one that funded the lease.
        """
        return json.dumps(
            {
                "action": self.action,
                "source": self.source,
                "policy_id": self.policy_id,
                "answers": [
                    {"name": a.name, "value": a.value, "confidence": a.confidence}
                    for a in sorted(self.answers, key=lambda a: a.name)
                ],
            },
            separators=(",", ":"),
            sort_keys=False,
            allow_nan=False,
        ).encode("utf-8")


@dataclass(frozen=True)
class Policy:
    """What the caller will let an agent spend on, written before the spend.

    ``allow`` is the set of actions that may fund anything at all. ``minimums``
    names an answer and the floor its confidence must clear. ``require`` names
    answers that must be present, because an answer the source declined to give
    is not the same as one it gave weakly.
    """

    policy_id: str
    allow: frozenset = frozenset()
    minimums: dict = field(default_factory=dict)
    require: frozenset = frozenset()

    def refusals(self, decision: Decision) -> list:
        """Every reason this decision is not authorised. Empty means it is."""
        reasons = []
        if self.allow and decision.action not in self.allow:
            reasons.append(
                f"action {decision.action!r} is not in the policy's allowed set "
                f"({', '.join(sorted(self.allow))})"
            )
        if decision.policy_id is not None and decision.policy_id != self.policy_id:
            reasons.append(
                f"decision cites policy {decision.policy_id!r}, this is {self.policy_id!r}"
            )
        for name in sorted(self.require):
            if decision.answer(name) is None:
                reasons.append(f"policy requires an answer for {name!r} and none was given")
        for name, floor in sorted(self.minimums.items()):
            answer = decision.answer(name)
            if answer is None:
                reasons.append(f"policy sets a floor for {name!r} and no answer was given")
            elif answer.confidence is None:
                reasons.append(
                    f"{name!r} carries no confidence, so the {floor} floor cannot be met"
                )
            elif float(answer.confidence) < float(floor):
                reasons.append(
                    f"{name!r} confidence {answer.confidence} is under the {floor} floor"
                )
        return reasons

    def authorise(self, decision: Decision) -> Decision:
        """Return the decision, or raise before anything is signed."""
        reasons = self.refusals(decision)
        if reasons:
            raise DecisionRefused(reasons)
        return decision


def lease_reference(quote_id: str, decision: Decision | None, keccak) -> bytes:
    """The bytes32 the escrow records for this lease.

    Without a decision this is what it has always been, the hash of the quote
    id, so an unauthorised caller's leases are byte-identical to before.

    With one, the quote id is hashed together with the decision's digest. The
    escrow refuses a reference it has already seen, so the quote id has to stay
    in the preimage: two runs of the same decision are two different leases and
    must not collide. A verifier with the quote id and the stored decision
    recomputes this exactly, and cannot reach it any other way.
    """
    quote_digest = keccak(text=quote_id)
    if decision is None:
        return bytes(quote_digest)
    return bytes(keccak(bytes(quote_digest) + bytes(keccak(decision.canonical()))))


def decision_digest(decision: Decision | None, keccak=None) -> str | None:
    """The hex digest the control plane needs to know which derivation to expect.

    It is the decision's hash, not the decision: the service can check that the
    funding log commits to something, and cannot read what that something says.
    """
    if decision is None:
        return None
    if keccak is None:
        from web3 import Web3
        keccak = Web3.keccak
    return "0x" + bytes(keccak(decision.canonical())).hex()


def reference_matches(quote_id: str, decision: Decision, reference, keccak) -> bool:
    """Whether this decision is the one that funded that lease."""
    want = lease_reference(quote_id, decision, keccak)
    got = reference if isinstance(reference, (bytes, bytearray)) else bytes.fromhex(
        str(reference).removeprefix("0x")
    )
    return bytes(got) == want
