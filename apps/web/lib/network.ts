import type { PublicOffer } from "@/app/api/offers/route";
import type { PublicProofReceipt } from "@/lib/proof";

export type ModelTotals = {
  model: string;
  leases: number;
  seconds: number;
  charged: number;
  refunded: number;
};

export type SettledTotals = {
  leases: number;
  seconds: number;
  charged: number;
  paidToProviders: number;
  refunded: number;
  refundedLeases: number;
  models: ModelTotals[];
  escrows: number;
};

export type LiveCapacity = {
  offers: number;
  vramMib: number;
  models: { model: string; count: number }[];
  lowRatePerHour: number | null;
  openToEveryone: number;
};

// Receipts are the settled record: every figure here is the sum of numbers that
// were written to a settlement transaction, not an internal counter.
export function settledTotals(receipts: PublicProofReceipt[]): SettledTotals {
  const models = new Map<string, ModelTotals>();
  const escrows = new Set<string>();
  const totals: SettledTotals = {
    leases: 0,
    seconds: 0,
    charged: 0,
    paidToProviders: 0,
    refunded: 0,
    refundedLeases: 0,
    models: [],
    escrows: 0,
  };

  for (const receipt of receipts) {
    totals.leases += 1;
    totals.seconds += receipt.runtime_seconds;
    totals.charged += receipt.charged_base_units;
    totals.paidToProviders += receipt.provider_paid_base_units;
    totals.refunded += receipt.refunded_base_units;
    if (receipt.refunded_base_units > 0) totals.refundedLeases += 1;
    if (receipt.escrow_address) escrows.add(receipt.escrow_address.toLowerCase());

    const model = models.get(receipt.gpu_model) ?? {
      model: receipt.gpu_model,
      leases: 0,
      seconds: 0,
      charged: 0,
      refunded: 0,
    };
    model.leases += 1;
    model.seconds += receipt.runtime_seconds;
    model.charged += receipt.charged_base_units;
    model.refunded += receipt.refunded_base_units;
    models.set(receipt.gpu_model, model);
  }

  totals.escrows = escrows.size;
  totals.models = [...models.values()].sort((a, b) => b.seconds - a.seconds);
  return totals;
}

export function liveCapacity(offers: PublicOffer[]): LiveCapacity {
  const models = new Map<string, number>();
  let vramMib = 0;
  let lowest: number | null = null;
  let openToEveryone = 0;

  for (const offer of offers) {
    models.set(offer.gpu.model, (models.get(offer.gpu.model) ?? 0) + 1);
    vramMib += offer.gpu.vram_mib;
    // A staker-only offer will not match a wallet without the stake, so the
    // headline price has to come from what anyone can actually rent.
    if (!offer.staker_only) {
      openToEveryone += 1;
      const perHour = offer.rate_per_second * 3_600;
      if (lowest === null || perHour < lowest) lowest = perHour;
    }
  }

  return {
    offers: offers.length,
    vramMib,
    models: [...models.entries()]
      .map(([model, count]) => ({ model, count }))
      .sort((a, b) => b.count - a.count || a.model.localeCompare(b.model)),
    lowRatePerHour: lowest,
    openToEveryone,
  };
}

/// The share of settled charges that reached the supplier rather than the
/// protocol. Null until something has settled, because zero would read as a
/// claim rather than an absence.
export function providerShare(totals: SettledTotals): number | null {
  if (totals.charged <= 0) return null;
  return totals.paidToProviders / totals.charged;
}

export function formatUsdg(baseUnits: number, digits = 2) {
  return (baseUnits / 1_000_000).toLocaleString(undefined, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

export function formatHours(seconds: number) {
  const hours = seconds / 3_600;
  if (hours < 1) return `${Math.round(seconds / 60)} min`;
  return `${hours.toLocaleString(undefined, { maximumFractionDigits: 1 })} h`;
}

export function formatVram(mib: number) {
  return `${Math.round(mib / 1_024).toLocaleString()} GB`;
}
