import { describe, expect, it } from "vitest";
import { isOperatorDispute } from "./operator";

const dispute = {
  lease_id: 42,
  node_id: `0x${"ab".repeat(32)}`,
  evidence: {
    gpu_model: "NVIDIA L4",
    image_digest: `sha256:${"cd".repeat(32)}`,
    rate_per_second: 100,
    deposit_base_units: 360_000,
    duration_seconds: 3_600,
    access_started_at: 1_700_000_000,
    access_ended_at: 1_700_003_600,
    cuda_ready_at: 1_700_000_010,
    interactive_access_ready_at: 1_700_000_020,
    gateway_closed_at: 1_700_003_590,
    telemetry_records: 120,
    evidence_hash: `0x${"ef".repeat(32)}`,
    proposal_integrity_valid: true,
  },
  proposal: {
    usage_seconds: 3_570,
    receipt_hash: `0x${"12".repeat(32)}`,
    transaction_hash: `0x${"34".repeat(32)}`,
  },
  accept_proposal_transaction: {
    to: `0x${"56".repeat(20)}`,
    value: "0",
    data: `0x${"78".repeat(100)}`,
    method: "resolveDispute(uint256,uint64,bytes32)",
  },
  updated_at: "2026-07-18T12:00:00Z",
};

describe("operator dispute validation", () => {
  it("accepts a complete dispute record", () => {
    expect(isOperatorDispute(dispute)).toBe(true);
  });

  it("rejects unsafe numeric and transaction shapes", () => {
    expect(isOperatorDispute({ ...dispute, lease_id: Number.MAX_SAFE_INTEGER + 1 })).toBe(false);
    expect(isOperatorDispute({
      ...dispute,
      accept_proposal_transaction: { ...dispute.accept_proposal_transaction, value: "1" },
    })).toBe(false);
  });
});
