import { describe, expect, it } from "vitest";
import { isPublicProofIndex } from "@/lib/proof";

const receipt = {
  receipt_id: "019f0000-0000-7000-8000-000000000000",
  lease_id: "lease-1",
  node_id_hash: `0x${"a".repeat(64)}`,
  gpu_model: "NVIDIA L4",
  runtime_seconds: 60,
  charged_base_units: 1_000_000,
  refunded_base_units: 0,
  provider_paid_base_units: 900_000,
  failure_class: null,
  outcome: "finalized",
  receipt_hash: "b".repeat(64),
  transaction_hash: `0x${"c".repeat(64)}`,
};

describe("isPublicProofIndex", () => {
  it("accepts public proof artifacts", () => {
    expect(isPublicProofIndex({ generated_at: "2026-07-17T18:00:00Z", receipts: [receipt] })).toBe(true);
  });

  it("rejects malformed receipt hashes", () => {
    expect(isPublicProofIndex({ generated_at: "2026-07-17T18:00:00Z", receipts: [{ ...receipt, receipt_hash: "bad" }] })).toBe(false);
  });
});
