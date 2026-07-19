export type SupplierNode = {
  offer: {
    node_id: string;
    operator_wallet: string;
    payout_wallet: string;
    gpu: { model: string; vram_mib: number; cuda_major: number };
    rate_per_second: number;
    reliability_bps: number;
    benchmark_score: number;
    bonded: boolean;
    online: boolean;
    updated_at: string;
  };
  suspended: boolean;
  certificate_status: string;
  certificate_expires_at: string | null;
  finalized_leases: number;
  provider_paid_base_units: number;
};

export type SupplierSummary = {
  linked_wallets: string[];
  nodes: SupplierNode[];
  total_provider_paid_base_units: number;
  total_finalized_leases: number;
};

export async function fetchSupplierSummary(signal?: AbortSignal): Promise<SupplierSummary> {
  const response = await fetch("/api/app/supplier/summary", {
    cache: "no-store",
    signal,
  });
  if (!response.ok) throw new Error(response.status === 401 ? "identity_required" : "supplier_unavailable");
  const payload: unknown = await response.json();
  if (!isSupplierSummary(payload)) throw new Error("supplier_response_invalid");
  return payload;
}

export function formatUsdg(value: number) {
  return (value / 1_000_000).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 6,
  });
}

function isSupplierSummary(value: unknown): value is SupplierSummary {
  if (!isRecord(value)
    || !Array.isArray(value.linked_wallets)
    || !value.linked_wallets.every(isAddress)
    || !Array.isArray(value.nodes)
    || !value.nodes.every(isSupplierNode)
    || !isUnsignedInteger(value.total_provider_paid_base_units)
    || !isUnsignedInteger(value.total_finalized_leases)) {
    return false;
  }
  return true;
}

function isSupplierNode(value: unknown): value is SupplierNode {
  if (!isRecord(value)) return false;
  const offer = value.offer;
  if (!isRecord(offer)) return false;
  const gpu = offer.gpu;
  if (!isRecord(gpu)) return false;
  return isNodeId(offer.node_id)
    && isAddress(offer.operator_wallet)
    && isAddress(offer.payout_wallet)
    && typeof gpu.model === "string"
    && gpu.model.length > 0
    && gpu.model.length <= 128
    && isUnsignedInteger(gpu.vram_mib)
    && isUnsignedInteger(gpu.cuda_major)
    && isUnsignedInteger(offer.rate_per_second)
    && isUnsignedInteger(offer.reliability_bps)
    && offer.reliability_bps <= 10_000
    && isUnsignedInteger(offer.benchmark_score)
    && typeof offer.bonded === "boolean"
    && typeof offer.online === "boolean"
    && typeof offer.updated_at === "string"
    && typeof value.suspended === "boolean"
    && typeof value.certificate_status === "string"
    && (value.certificate_expires_at === null || typeof value.certificate_expires_at === "string")
    && isUnsignedInteger(value.finalized_leases)
    && isUnsignedInteger(value.provider_paid_base_units);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isUnsignedInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isAddress(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-f]{40}$/i.test(value);
}

function isNodeId(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-f]{64}$/i.test(value);
}
