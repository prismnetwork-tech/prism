export type PublicProofReceipt = {
  receipt_id: string;
  lease_id: string;
  node_id_hash: string;
  gpu_model: string;
  runtime_seconds: number;
  charged_base_units: number;
  refunded_base_units: number;
  provider_paid_base_units: number;
  failure_class: string | null;
  outcome: "finalized" | "refunded" | "disputed";
  receipt_hash: string;
  transaction_hash: string;
};

export type PublicProofIndex = {
  generated_at: string;
  receipts: PublicProofReceipt[];
};

export function isPublicProofIndex(value: unknown): value is PublicProofIndex {
  if (!value || typeof value !== "object") return false;
  const index = value as Partial<PublicProofIndex>;
  return typeof index.generated_at === "string"
    && !Number.isNaN(Date.parse(index.generated_at))
    && Array.isArray(index.receipts)
    && index.receipts.length <= 1_000
    && index.receipts.every(isPublicProofReceipt);
}

function isPublicProofReceipt(value: unknown): value is PublicProofReceipt {
  if (!value || typeof value !== "object") return false;
  const receipt = value as Partial<PublicProofReceipt>;
  return isBoundedText(receipt.receipt_id, 1, 128)
    && isBoundedText(receipt.lease_id, 1, 128)
    && isHash(receipt.node_id_hash)
    && isBoundedText(receipt.gpu_model, 1, 128)
    && isBaseUnits(receipt.runtime_seconds, 21_600)
    && isBaseUnits(receipt.charged_base_units, 50_000_000)
    && isBaseUnits(receipt.refunded_base_units, 50_000_000)
    && isBaseUnits(receipt.provider_paid_base_units, 45_000_000)
    && (receipt.failure_class === null || isBoundedText(receipt.failure_class, 1, 64))
    && (receipt.outcome === "finalized" || receipt.outcome === "refunded" || receipt.outcome === "disputed")
    && /^[0-9a-f]{64}$/i.test(receipt.receipt_hash ?? "")
    && isHash(receipt.transaction_hash);
}

function isBaseUnits(value: unknown, maximum: number) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function isBoundedText(value: unknown, minimum: number, maximum: number): value is string {
  return typeof value === "string" && value.length >= minimum && value.length <= maximum;
}

function isHash(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}
