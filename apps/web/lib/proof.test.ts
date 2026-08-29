import { describe, expect, it } from "vitest";
import { isPublicProofIndex, recomputeReceiptHash } from "@/lib/proof";
import type { PublicProofReceipt } from "@/lib/proof";

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

const attestation = {
  kind: "nvidia_gpu",
  verdict_digest: "d".repeat(64),
  verifier_version: "prism-attestation/0.1.0",
};

// Exactly as the index published it. The hash was minted by the settlement
// worker, so recomputing it here checks this browser-side payload against the
// Rust that signed it rather than against itself.
const published: PublicProofReceipt = {
  outcome: "finalized",
  lease_id: "52",
  gpu_model: "RTX 6000Ada",
  receipt_id: "9fa86919-eacf-87de-8a2f-373b802c27a9",
  trust_class: "open",
  node_id_hash: "0x8ce4cc842b5a2010b7e73891c5e6ef5a6f44d8ed375026238cdb41e8c7eba2d8",
  receipt_hash: "6423582a59bb54c1afac11202e20aaf1235998d41e0965284961e09f9ffc764e",
  failure_class: null,
  escrow_address: "0x62c042265991bea17b07229322a01850974626da",
  runtime_seconds: 900,
  transaction_hash: "0x96e26448a09ba301951452f737038c1d4443c97af875ea509b2a547e2d4a0301",
  charged_base_units: 199_800,
  refunded_base_units: 0,
  provider_paid_base_units: 179_820,
};

const index = (receipts: unknown[]) => ({ generated_at: "2026-07-17T18:00:00Z", receipts });

describe("isPublicProofIndex", () => {
  it("accepts public proof artifacts", () => {
    expect(isPublicProofIndex(index([receipt]))).toBe(true);
  });

  it("rejects malformed receipt hashes", () => {
    expect(isPublicProofIndex(index([{ ...receipt, receipt_hash: "bad" }]))).toBe(false);
  });

  // One bad receipt fails the whole feed, so a receipt settled before
  // attestation existed has to keep validating on its own terms.
  it("accepts a receipt that carries no attestation", () => {
    expect(isPublicProofIndex(index([receipt, published]))).toBe(true);
  });

  it("accepts a receipt that carries one", () => {
    expect(isPublicProofIndex(index([{ ...receipt, trust_class: "isolated", attestation }]))).toBe(true);
  });

  it("rejects a malformed attestation", () => {
    for (const broken of [
      { ...attestation, verdict_digest: "short" },
      { ...attestation, kind: "" },
      { ...attestation, verifier_version: "v".repeat(65) },
      "nvidia",
    ]) {
      expect(isPublicProofIndex(index([{ ...receipt, attestation: broken }]))).toBe(false);
    }
  });
});

describe("recomputeReceiptHash with an availability credit", () => {
  // The hash is pinned in the Rust that mints it (crates/protocol receipt_hash
  // tests), so this checks the two implementations agree rather than checking
  // this one against itself.
  const credited: PublicProofReceipt = {
    receipt_id: "019f0000-0000-7000-8000-000000000001",
    lease_id: "128",
    node_id_hash: `0x${"a".repeat(64)}`,
    gpu_model: "NVIDIA L40S",
    runtime_seconds: 200,
    charged_base_units: 44_400,
    refunded_base_units: 155_400,
    provider_paid_base_units: 39_960,
    failure_class: "interrupted",
    outcome: "finalized",
    trust_class: "open",
    credited_seconds: 150,
    receipt_hash: "c63e4690f2e6be23ecf474e2f5e813b3eecce5b36a3d4a2b39b3c6e87e7de135",
    transaction_hash: `0x${"c".repeat(64)}`,
  };

  it("agrees with the Rust that minted it", async () => {
    await expect(recomputeReceiptHash(credited)).resolves.toBe(credited.receipt_hash);
  });

  it("accepts a credited receipt into the feed", () => {
    expect(isPublicProofIndex({ generated_at: new Date().toISOString(), receipts: [credited] })).toBe(true);
  });

  it("leaves a receipt settled before the commitment hashing exactly as it did", async () => {
    expect(Object.hasOwn(published, "credited_seconds")).toBe(false);
    await expect(recomputeReceiptHash(published)).resolves.toBe(published.receipt_hash);
  });
});

describe("recomputeReceiptHash", () => {
  it("reproduces the hash a settled receipt was published with", async () => {
    await expect(recomputeReceiptHash(published)).resolves.toBe(published.receipt_hash);
  });

  it("does not reproduce it once an amount is edited", async () => {
    await expect(recomputeReceiptHash({ ...published, charged_base_units: 1 })).resolves.not.toBe(
      published.receipt_hash,
    );
  });

  it("covers the attestation", async () => {
    const first = await recomputeReceiptHash({ ...published, attestation });
    const second = await recomputeReceiptHash({
      ...published,
      attestation: { ...attestation, verdict_digest: "e".repeat(64) },
    });
    expect(first).not.toBe(second);
    expect(first).not.toBe(published.receipt_hash);
  });
});
