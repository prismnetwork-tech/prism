export const operatorActions = [
  ["account_risk_hold", "Place account risk hold"],
  ["account_risk_release", "Release account risk hold"],
  ["account_suspend", "Suspend account"],
  ["account_resume", "Resume account"],
  ["node_suspend", "Suspend node"],
  ["node_resume", "Resume node"],
  ["node_certificate_revoke", "Revoke node certificate"],
  ["slash_evidence_record", "Record slash evidence"],
] as const;

export type OperatorAction = typeof operatorActions[number][0];

export type AuditEvent = {
  event_id: string;
  action_id: string;
  actor_subject: string;
  action: OperatorAction;
  target_type: "account" | "node";
  target_id: string;
  reason: string;
  evidence_hash: string | null;
  created_at: string;
};

export type OperatorDispute = {
  lease_id: number;
  node_id: string;
  evidence: {
    gpu_model: string;
    image_digest: string;
    rate_per_second: number;
    deposit_base_units: number;
    duration_seconds: number;
    access_started_at: number;
    access_ended_at: number;
    cuda_ready_at: number;
    interactive_access_ready_at: number;
    gateway_closed_at: number;
    telemetry_records: number;
    evidence_hash: string;
    proposal_integrity_valid: boolean | null;
  };
  proposal: {
    usage_seconds: number;
    receipt_hash: string;
    transaction_hash: string;
  } | null;
  accept_proposal_transaction: {
    to: string;
    value: string;
    data: string;
    method: "resolveDispute(uint256,uint64,bytes32)";
  } | null;
  updated_at: string;
};

export function isAuditEvent(value: unknown): value is AuditEvent {
  if (!isRecord(value)) return false;
  return typeof value.event_id === "string"
    && typeof value.action_id === "string"
    && typeof value.actor_subject === "string"
    && operatorActions.some(([action]) => action === value.action)
    && (value.target_type === "account" || value.target_type === "node")
    && typeof value.target_id === "string"
    && typeof value.reason === "string"
    && (value.evidence_hash === null || typeof value.evidence_hash === "string")
    && typeof value.created_at === "string";
}

export function isOperatorDispute(value: unknown): value is OperatorDispute {
  if (!isRecord(value) || !isRecord(value.evidence)) return false;
  const evidence = value.evidence;
  const proposalIntegrity = evidence.proposal_integrity_valid;
  return isSafeInteger(value.lease_id)
    && typeof value.node_id === "string"
    && typeof evidence.gpu_model === "string"
    && typeof evidence.image_digest === "string"
    && [
      evidence.rate_per_second,
      evidence.deposit_base_units,
      evidence.duration_seconds,
      evidence.access_started_at,
      evidence.access_ended_at,
      evidence.cuda_ready_at,
      evidence.interactive_access_ready_at,
      evidence.gateway_closed_at,
      evidence.telemetry_records,
    ].every(isSafeInteger)
    && typeof evidence.evidence_hash === "string"
    && (proposalIntegrity === null || typeof proposalIntegrity === "boolean")
    && (value.proposal === null || isProposal(value.proposal))
    && (value.accept_proposal_transaction === null || isSafeTransaction(value.accept_proposal_transaction))
    && typeof value.updated_at === "string";
}

function isProposal(value: unknown) {
  return isRecord(value)
    && isSafeInteger(value.usage_seconds)
    && typeof value.receipt_hash === "string"
    && typeof value.transaction_hash === "string";
}

function isSafeTransaction(value: unknown) {
  return isRecord(value)
    && typeof value.to === "string"
    && value.value === "0"
    && typeof value.data === "string"
    && value.method === "resolveDispute(uint256,uint64,bytes32)";
}

function isSafeInteger(value: unknown) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object";
}
