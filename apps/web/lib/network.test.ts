import { describe, expect, it } from "vitest";
import { formatHours, formatUsdg, liveCapacity, providerShare, settledTotals } from "@/lib/network";
import type { PublicProofReceipt } from "@/lib/proof";

function receipt(over: Partial<PublicProofReceipt> = {}): PublicProofReceipt {
  return {
    receipt_id: "019f0000-0000-7000-8000-000000000000",
    lease_id: "1",
    node_id_hash: `0x${"a".repeat(64)}`,
    gpu_model: "RTX A6000",
    runtime_seconds: 1_800,
    charged_base_units: 400_000,
    refunded_base_units: 0,
    provider_paid_base_units: 360_000,
    failure_class: null,
    outcome: "finalized",
    receipt_hash: "b".repeat(64),
    transaction_hash: `0x${"c".repeat(64)}`,
    ...over,
  };
}

describe("settledTotals", () => {
  it("sums what the settlements actually recorded", () => {
    const totals = settledTotals([
      receipt(),
      receipt({ gpu_model: "L40S", runtime_seconds: 600, charged_base_units: 133_200, provider_paid_base_units: 119_880 }),
      receipt({ runtime_seconds: 0, charged_base_units: 0, provider_paid_base_units: 0, refunded_base_units: 199_800, outcome: "refunded" }),
    ]);
    expect(totals.leases).toBe(3);
    expect(totals.seconds).toBe(2_400);
    expect(totals.charged).toBe(533_200);
    expect(totals.paidToProviders).toBe(479_880);
    expect(totals.refunded).toBe(199_800);
    expect(totals.refundedLeases).toBe(1);
  });

  it("ranks models by the time they actually served", () => {
    const totals = settledTotals([
      receipt({ gpu_model: "L40S", runtime_seconds: 100 }),
      receipt({ gpu_model: "RTX A6000", runtime_seconds: 900 }),
      receipt({ gpu_model: "RTX A6000", runtime_seconds: 900 }),
    ]);
    expect(totals.models.map((m) => m.model)).toEqual(["RTX A6000", "L40S"]);
    expect(totals.models[0].leases).toBe(2);
    expect(totals.models[0].seconds).toBe(1_800);
  });

  it("counts distinct escrows so lease ids reused across deployments do not read as one series", () => {
    const totals = settledTotals([
      receipt({ escrow_address: "0xAAA" }),
      receipt({ escrow_address: "0xaaa" }),
      receipt({ escrow_address: "0xBBB" }),
    ]);
    expect(totals.escrows).toBe(2);
  });

  it("has no totals to report before anything settles", () => {
    const totals = settledTotals([]);
    expect(totals.leases).toBe(0);
    expect(providerShare(totals)).toBeNull();
  });
});

describe("liveCapacity", () => {
  const offer = (over: Record<string, unknown> = {}) => ({
    node_id: "0xnode",
    gpu: { model: "L40S", vram_mib: 46_068 },
    rate_per_second: 222,
    trust_class: "open",
    ...over,
  });

  it("prices the headline from what an unstaked wallet can rent", () => {
    const capacity = liveCapacity([
      offer({ rate_per_second: 177, staker_only: true }),
      offer({ rate_per_second: 222 }),
    ]);
    expect(capacity.offers).toBe(2);
    expect(capacity.openToEveryone).toBe(1);
    expect(capacity.lowRatePerHour).toBe(222 * 3_600);
  });

  it("reports no price when every offer is reserved for stakers", () => {
    expect(liveCapacity([offer({ staker_only: true })]).lowRatePerHour).toBeNull();
  });

  it("groups models and sums memory", () => {
    const capacity = liveCapacity([offer(), offer(), offer({ gpu: { model: "RTX A6000", vram_mib: 49_140 } })]);
    expect(capacity.models).toEqual([
      { model: "L40S", count: 2 },
      { model: "RTX A6000", count: 1 },
    ]);
    expect(capacity.vramMib).toBe(46_068 * 2 + 49_140);
  });
});

describe("formatting", () => {
  it("reads minutes below the hour and hours above it", () => {
    expect(formatHours(600)).toBe("10 min");
    expect(formatHours(5_400)).toBe("1.5 h");
  });

  it("renders USDG from base units", () => {
    expect(formatUsdg(10_781_820)).toBe("10.78");
  });
});
