/// Authorise a spend before it happens, and bind the reason to the lease.
///
/// An agent with a wallet funds an escrow on its own judgement. The operator who
/// owns that wallet gets the bill and, today, no answer to "why did it spend
/// this". A log written afterwards by the process that spent the money is worth
/// what that process says it is worth.
///
/// So the reason is decided first, checked against a policy the caller wrote,
/// and hashed into the one field the escrow already commits on chain. A lease
/// that was not authorised is never funded, and one that was carries a
/// reference nobody can recompute without producing the decision behind it.
///
/// What this proves: a specific decision existed before the deposit was
/// broadcast, and the caller's own thresholds admitted it. What it does not: any
/// claim that the decision was sound. A confidently wrong judgement binds
/// exactly as well as a correct one.
///
/// The decision can come from anywhere. A System One model returning calibrated
/// probabilities, a general model, or a rule in the caller's own code all
/// produce the same record, and none of them is a dependency of this SDK.
/// Nothing but a hash leaves the caller's process.
import { keccak256, stringToBytes, concatBytes, hexToBytes } from "viem";

const NAME = /^[a-z][a-z0-9_]{0,63}$/;

export class DecisionRefused extends Error {
  constructor(reasons) {
    super(reasons.join("; "));
    this.name = "DecisionRefused";
    this.reasons = reasons;
  }
}

/// One typed answer. `value` is the selected option, the score, or the
/// probability that a yes/no question is yes. `confidence` is how sure the
/// source is that the value is right, which is a different axis and is usually
/// what a spending threshold should read.
export function answer(name, value, confidence = null) {
  if (!NAME.test(name)) throw new Error(`answer name ${JSON.stringify(name)} is not a lowercase identifier`);
  if (confidence !== null && !(confidence >= 0 && confidence <= 1)) {
    throw new Error(`${name}: confidence ${confidence} is outside 0..1`);
  }
  return { name, value, confidence };
}

/// Why a spend is about to happen. `source` names what judged, for example
/// "jev-1.13.0" or "policy:cpu-first". It is recorded rather than trusted: this
/// SDK cannot tell a model's answer from one a caller typed, and does not
/// pretend to.
export function decision({ action, source, answers = [], policyId = null }) {
  if (!action?.trim()) throw new Error("a decision needs an action");
  if (!source?.trim()) throw new Error("a decision needs a source, so the record says what judged");
  const seen = new Set();
  for (const a of answers) {
    if (seen.has(a.name)) throw new Error(`duplicate answer ${JSON.stringify(a.name)}`);
    seen.add(a.name);
  }
  return { action, source, answers, policyId };
}

/// The exact bytes that get hashed. Sorted by name and separator-pinned, so the
/// same decision produces the same reference in any language. The Python SDK
/// builds this byte for byte; a cross-language mismatch here would make a lease
/// funded by one unverifiable by the other.
export function canonical(d) {
  return stringToBytes(JSON.stringify({
    action: d.action,
    source: d.source,
    policy_id: d.policyId ?? null,
    answers: [...d.answers]
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
      .map((a) => ({ name: a.name, value: a.value, confidence: a.confidence ?? null })),
  }));
}

/// Every reason this decision is not authorised. Empty means it is.
export function refusals(policy, d) {
  const reasons = [];
  const allow = policy.allow ?? [];
  if (allow.length && !allow.includes(d.action)) {
    reasons.push(
      `action ${JSON.stringify(d.action)} is not in the policy's allowed set (${[...allow].sort().join(", ")})`,
    );
  }
  if (d.policyId != null && d.policyId !== policy.policyId) {
    reasons.push(`decision cites policy ${JSON.stringify(d.policyId)}, this is ${JSON.stringify(policy.policyId)}`);
  }
  for (const name of [...(policy.require ?? [])].sort()) {
    if (!d.answers.some((a) => a.name === name)) {
      reasons.push(`policy requires an answer for ${JSON.stringify(name)} and none was given`);
    }
  }
  for (const [name, floor] of Object.entries(policy.minimums ?? {}).sort()) {
    const a = d.answers.find((x) => x.name === name);
    if (!a) reasons.push(`policy sets a floor for ${JSON.stringify(name)} and no answer was given`);
    else if (a.confidence == null) {
      reasons.push(`${JSON.stringify(name)} carries no confidence, so the ${floor} floor cannot be met`);
    } else if (a.confidence < floor) {
      reasons.push(`${JSON.stringify(name)} confidence ${a.confidence} is under the ${floor} floor`);
    }
  }
  return reasons;
}

/// Return the decision, or throw before anything is signed.
export function authorise(policy, d) {
  const reasons = refusals(policy, d);
  if (reasons.length) throw new DecisionRefused(reasons);
  return d;
}

/// The bytes32 the escrow records for this lease.
///
/// Without a decision this is what it has always been, the hash of the quote id,
/// so an unauthorised caller's leases stay byte-identical to before.
///
/// With one, the quote id is hashed together with the decision's digest. The
/// escrow refuses a reference it has already seen, so the quote id has to stay
/// in the preimage: two runs of the same decision are two different leases and
/// must not collide.
export function leaseReference(quoteId, d) {
  const quoteDigest = keccak256(stringToBytes(quoteId));
  if (!d) return quoteDigest;
  return keccak256(concatBytes([hexToBytes(quoteDigest), hexToBytes(keccak256(canonical(d)))]));
}

/// The hex digest the control plane needs to know which derivation to expect.
/// It is the decision's hash, not the decision: the service can check that the
/// funding log commits to something, and cannot read what that something says.
export function decisionDigest(d) {
  return d ? keccak256(canonical(d)) : null;
}

/// Whether this decision is the one that funded that lease.
export function referenceMatches(quoteId, d, reference) {
  return leaseReference(quoteId, d).toLowerCase() === String(reference).toLowerCase();
}
