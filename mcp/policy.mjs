// The operator's spending rules for leases. The budget caps how much an agent
// may spend; the policy decides whether a given spend has a reason the operator
// accepts. The agent states its reason as a decision, the SDK checks it against
// this policy before anything is quoted, and only the decision's hash leaves
// the machine, bound into the escrow deposit.
import { readFileSync } from "node:fs";
import { answer, decision as makeDecision, decisionDigest, refusals } from "@prismnetwork/agent-sdk/decision";

export class PolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = "PolicyError";
  }
}

const strings = (value, field) => {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string" || !v.trim())) {
    throw new PolicyError(`PRISM_SPEND_POLICY: ${field} must be a list of names`);
  }
  return value;
};

/// PRISM_SPEND_POLICY holds the policy as JSON, or the path to a JSON file.
/// Unset means no policy: a decision is optional and, when given, still binds.
export function readPolicy(raw = process.env.PRISM_SPEND_POLICY) {
  if (raw === undefined || raw.trim() === "") return null;
  let text = raw.trim();
  if (!text.startsWith("{")) {
    try {
      text = readFileSync(text, "utf8");
    } catch (err) {
      throw new PolicyError(`PRISM_SPEND_POLICY: cannot read ${raw}: ${err.code ?? err.message}`);
    }
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new PolicyError("PRISM_SPEND_POLICY is not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new PolicyError("PRISM_SPEND_POLICY must be a JSON object");
  }
  const policyId = parsed.policy_id;
  if (typeof policyId !== "string" || !policyId.trim()) {
    throw new PolicyError("PRISM_SPEND_POLICY needs a policy_id, so every decision records which rules admitted it");
  }
  const minimums = parsed.minimums ?? {};
  if (typeof minimums !== "object" || Array.isArray(minimums)) {
    throw new PolicyError("PRISM_SPEND_POLICY: minimums must map an answer name to a confidence floor");
  }
  for (const [name, floor] of Object.entries(minimums)) {
    if (typeof floor !== "number" || !(floor >= 0 && floor <= 1)) {
      throw new PolicyError(`PRISM_SPEND_POLICY: the floor for ${name} must be a number from 0 to 1`);
    }
  }
  return {
    policyId,
    allow: strings(parsed.allow, "allow"),
    require: strings(parsed.require, "require"),
    minimums,
  };
}

/// What prism_budget shows, so an agent can shape its decision before it asks.
export function describePolicy(policy) {
  if (!policy) return { spend_policy: "none: leases need no stated reason" };
  return {
    spend_policy: {
      policy_id: policy.policyId,
      allowed_actions: policy.allow.length ? policy.allow : "any",
      required_answers: policy.require,
      confidence_floors: policy.minimums,
    },
  };
}

/// The decision a tool call carries, in the SDK's form. Malformed input is the
/// caller's mistake and says which field; a missing decision under a policy is
/// refused with what the policy needs.
export function decisionFrom(input, policy) {
  if (input === undefined || input === null) {
    if (!policy) return null;
    const needs = [
      policy.allow.length ? `action one of ${policy.allow.join(", ")}` : "an action",
      ...policy.require.map((n) => `an answer for ${n}`),
      ...Object.entries(policy.minimums).map(([n, f]) => `${n} with confidence at least ${f}`),
    ];
    throw new PolicyError(
      `the operator's spend policy ${policy.policyId} requires a decision with this lease: ${needs.join("; ")}. Nothing was quoted or funded.`,
    );
  }
  if (typeof input !== "object") throw new PolicyError("decision must be an object with action, source and answers");
  const answers = (input.answers ?? []).map((a) => {
    if (!a || typeof a.name !== "string") throw new PolicyError("each decision answer needs a name");
    return answer(a.name, a.value ?? null, a.confidence ?? null);
  });
  return makeDecision({
    action: input.action,
    source: input.source,
    answers,
    policyId: input.policy_id ?? policy?.policyId ?? null,
  });
}

/// Checked here, before the spend is booked against the budget, so a refused
/// decision neither costs anything nor holds capacity.
export function authorised(policy, d) {
  if (!policy) return;
  const reasons = refusals(policy, d);
  if (reasons.length) {
    throw new PolicyError(`the spend policy ${policy.policyId} refused this lease: ${reasons.join("; ")}. Nothing was quoted or funded.`);
  }
}

export { decisionDigest };
