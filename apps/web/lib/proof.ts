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
  // Absent on receipts minted before trust classes existed; their settled hash
  // depends on the field staying out of the payload entirely.
  trust_class?: "open" | "isolated" | "attested" | "confidential";
  /// A digest of the verdict this network reached after checking a vendor
  /// signed device report, not the report. Absent on every receipt settled
  /// before device attestation existed.
  attestation?: { kind: string; verdict_digest: string; verifier_version: string };
  /// Seconds the renter held but was not charged for, because the machine had
  /// already stopped answering when the lease was cut short. Absent on a lease
  /// that ran to its end, and on every receipt settled before the availability
  /// commitment existed.
  credited_seconds?: number;
  /// Present for a completed GPU repro. Node reports are signed by an enrolled
  /// device key; managed reports are signed by the Prism gateway after a
  /// centrally orchestrated SSH run. Both bind claims to the settlement, but
  /// neither signature alone proves faithful computation.
  repro?: {
    executor: "node" | "managed";
    token_hash: string;
    spec_hash: string;
    image_digest: string;
    command_hash: string;
    result_hash: string;
    stdout_hash: string;
    stderr_hash: string;
    report_hash: string;
    exit_code: number;
    expected_exit_code: number;
    succeeded: boolean;
    truncated: boolean;
  };
  receipt_hash: string;
  transaction_hash: string;
  /// The escrow that issued this lease id. Ids count from one inside a single
  /// deployment, so this field and `chain_lease_id` are required as a pair on
  /// new artifacts. Receipts minted before the metadata existed may omit both.
  escrow_address?: string;
  /// Decimal id emitted by `escrow_address`. It is additive metadata and is
  /// intentionally excluded from the receipt hash.
  chain_lease_id?: string;
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

const trustClasses = ["open", "isolated", "attested", "confidential"] as const;

function isPublicProofReceipt(value: unknown): value is PublicProofReceipt {
  if (!value || typeof value !== "object") return false;
  const receipt = value as Partial<PublicProofReceipt>;
  return isBoundedText(receipt.receipt_id, 1, 128)
    && isBoundedText(receipt.lease_id, 1, 128)
    && isReceiptIdentity(receipt)
    && isHash(receipt.node_id_hash)
    && isBoundedText(receipt.gpu_model, 1, 128)
    && isBaseUnits(receipt.runtime_seconds, 21_600)
    && isBaseUnits(receipt.charged_base_units, 50_000_000)
    && isBaseUnits(receipt.refunded_base_units, 50_000_000)
    && isBaseUnits(receipt.provider_paid_base_units, 45_000_000)
    && (receipt.failure_class === null || isBoundedText(receipt.failure_class, 1, 64))
    && (receipt.outcome === "finalized" || receipt.outcome === "refunded" || receipt.outcome === "disputed")
    && (receipt.trust_class === undefined || trustClasses.includes(receipt.trust_class))
    && (receipt.attestation === undefined || isAttestation(receipt.attestation))
    && (receipt.credited_seconds === undefined || isBaseUnits(receipt.credited_seconds, 21_600))
    && (receipt.repro === undefined || isReproReceipt(receipt.repro))
    && /^[0-9a-f]{64}$/.test(receipt.receipt_hash ?? "")
    && isHash(receipt.transaction_hash);
}

function isReceiptIdentity(receipt: Partial<PublicProofReceipt>): boolean {
  if (receipt.escrow_address === undefined && receipt.chain_lease_id === undefined) return true;
  return typeof receipt.escrow_address === "string"
    && /^0x[0-9a-f]{40}$/.test(receipt.escrow_address)
    && typeof receipt.chain_lease_id === "string"
    && /^[1-9][0-9]{0,19}$/.test(receipt.chain_lease_id)
    && BigInt(receipt.chain_lease_id) <= 18_446_744_073_709_551_615n
    && receipt.chain_lease_id === receipt.lease_id;
}

function isReproReceipt(value: unknown): value is NonNullable<PublicProofReceipt["repro"]> {
  if (!value || typeof value !== "object") return false;
  const repro = value as Partial<NonNullable<PublicProofReceipt["repro"]>>;
  return (repro.executor === "node" || repro.executor === "managed")
    && isDigest(repro.token_hash)
    && isDigest(repro.spec_hash)
    && typeof repro.image_digest === "string"
    && /^sha256:[0-9a-f]{64}$/.test(repro.image_digest)
    && isDigest(repro.command_hash)
    && isDigest(repro.result_hash)
    && isDigest(repro.stdout_hash)
    && isDigest(repro.stderr_hash)
    && isDigest(repro.report_hash)
    && Number.isSafeInteger(repro.exit_code)
    && Number(repro.exit_code) >= -255
    && Number(repro.exit_code) <= 255
    && Number.isSafeInteger(repro.expected_exit_code)
    && Number(repro.expected_exit_code) >= 0
    && Number(repro.expected_exit_code) <= 255
    && repro.succeeded === (repro.exit_code === repro.expected_exit_code)
    && typeof repro.truncated === "boolean";
}

function isAttestation(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const attestation = value as Partial<NonNullable<PublicProofReceipt["attestation"]>>;
  return isBoundedText(attestation.kind, 1, 32)
    && /^[0-9a-f]{64}$/.test(attestation.verdict_digest ?? "")
    && isBoundedText(attestation.verifier_version, 1, 64);
}

/// The published hash is what the settlement committed to on chain, so a reader
/// can check the artifact here instead of taking the label: this rebuilds the
/// payload the settlement hashed and hashes it again in the browser. Field order
/// is the Rust ReceiptPayload declaration order, because canonical JSON there is
/// serde_json output rather than sorted keys, and the two optional fields drop
/// out of the payload entirely when absent rather than appearing as null.
export async function recomputeReceiptHash(receipt: PublicProofReceipt): Promise<string> {
  const payload: Record<string, unknown> = {
    receipt_id: receipt.receipt_id,
    lease_id: receipt.lease_id,
    node_id_hash: receipt.node_id_hash,
    gpu_model: receipt.gpu_model,
    runtime_seconds: receipt.runtime_seconds,
    charged_base_units: receipt.charged_base_units,
    refunded_base_units: receipt.refunded_base_units,
    provider_paid_base_units: receipt.provider_paid_base_units,
    failure_class: receipt.failure_class ?? null,
    outcome: receipt.outcome,
  };
  if (receipt.trust_class) payload.trust_class = receipt.trust_class;
  if (receipt.attestation) {
    payload.attestation = {
      kind: receipt.attestation.kind,
      verdict_digest: receipt.attestation.verdict_digest,
      verifier_version: receipt.attestation.verifier_version,
    };
  }
  // Zero is a real credit, so this asks whether the field is there rather than
  // whether it is truthy.
  if (receipt.credited_seconds !== undefined) payload.credited_seconds = receipt.credited_seconds;
  if (receipt.repro) {
    payload.repro = {
      executor: receipt.repro.executor,
      token_hash: receipt.repro.token_hash,
      spec_hash: receipt.repro.spec_hash,
      image_digest: receipt.repro.image_digest,
      command_hash: receipt.repro.command_hash,
      result_hash: receipt.repro.result_hash,
      stdout_hash: receipt.repro.stdout_hash,
      stderr_hash: receipt.repro.stderr_hash,
      report_hash: receipt.repro.report_hash,
      exit_code: receipt.repro.exit_code,
      expected_exit_code: receipt.repro.expected_exit_code,
      succeeded: receipt.repro.succeeded,
      truncated: receipt.repro.truncated,
    };
  }
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
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

function isDigest(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
