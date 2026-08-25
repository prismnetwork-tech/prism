export declare const DEFAULT_CONFIDENTIAL_BASE: string;

export type CheckStatus = "pass" | "fail" | "skip";

/// The code the confidential tier is pinned to, read off the live known-good
/// report. The launcher image digest is the root of it: it is measured into the
/// quote and it is what fetches and runs the gateway source.
export interface WorkloadPin {
  launcherImage: string;
  repoUrl: string;
  osImageHash: string;
  /// Optional. The launcher's source commit moves with the deployment, so it is
  /// corroborated against the report rather than pinned, unless one is set here.
  repoCommit?: string | null;
}

export declare const EXPECTED_WORKLOAD: WorkloadPin;

export interface AttestationCheck {
  /// Stable id, e.g. `tdx-quote` or `workload-identity`.
  id: string;
  title: string;
  status: CheckStatus;
  detail?: string;
}

export interface AttestationResult {
  /// `verified` when every check that ran passed and every skip is one of the
  /// documented ones (key custody, and the TLS pin without an observed
  /// certificate). `failed` when a check failed. `incomplete` when nothing
  /// failed and evidence some check needed was not available.
  verdict: "verified" | "failed" | "incomplete";
  checks: AttestationCheck[];
  nonce: string;
  receiptId: string;
  model: string | null;
  keysetDigest: string | null;
  /// `<repo_url> @ <repo_commit>` read out of the measured compose, so it is the
  /// source the launcher actually cloned rather than the report's own claim.
  provenance: string | null;
}

export interface VerifyConfidentialOptions {
  /// The Prism inference gateway the call went through; every fetch but the
  /// NVIDIA and Intel ones is relayed by it.
  base?: string;
  model?: string;
  receiptId: string;
  /// A receipt already fetched when the answer arrived. Receipts live in the
  /// workload's memory only, so passing one is more reliable than a later fetch.
  receipt?: Record<string, unknown> | null;
  requestBytes?: Uint8Array | string | null;
  responseBytes?: Uint8Array | string | null;
  requestHash?: string | null;
  responseHash?: string | null;
  /// Under E2EE the receipt covers the plaintext the workload restored, which
  /// the client reproduces rather than observes.
  restoredRequestBytes?: Uint8Array | string | null;
  restoredRequestHash?: string | null;
  e2ee?: boolean;
  /// The code the enclave must be running. Defaults to the deployment this SDK
  /// ships pinned; `null` downgrades the check to a skip and says so, which
  /// leaves the verdict `incomplete`.
  expectedWorkload?: WorkloadPin | null;
  /// The key set this call's prompt was sealed to, which is what ties the
  /// transcript to the call rather than to whatever the endpoint serves now.
  expectedKeysetDigest?: string | null;
  nonce?: string;
  now?: number;
  /// The TLS leaf SPKI digest this client's own stack observed, when it can see
  /// one. Without it the pin is an honest skip.
  observedSpki?: string | null;
  collateralUrl?: string;
  fetchImpl?: typeof fetch;
}

export declare function verifyConfidential(options: VerifyConfidentialOptions): Promise<AttestationResult>;

export declare function gateNrasClaims(input: {
  overall: Record<string, unknown>;
  gpus: Record<string, Record<string, unknown>>;
  nonce: string;
  now?: number;
}): { ok: boolean; detail: string };

export declare function gateGpuBinding(input: {
  reportData: string;
  signingAddress: string;
  nonce: string;
}): { ok: boolean; detail: string };

/// §9.1 check 4 as a policy: the measured compose has to name the pinned
/// launcher, source and OS image, and to corroborate the report's own
/// `source_provenance`, which the quote does not bind.
export declare function gateWorkloadIdentity(input: {
  appCompose: string;
  osImageHash: string | null;
  provenance?: { repo_url?: string | null; repo_commit?: string | null } | null;
  expected: WorkloadPin;
}): { ok: boolean; detail: string; provenance: string | null };

/// The same appraisal over a report whose compose measurement already holds.
/// `expected` of null reports itself as a caller downgrade rather than a pass.
export declare function appraiseWorkload(
  report: Record<string, unknown>,
  compose: { composeHash?: string },
  expected?: WorkloadPin | null,
): Promise<{ ok: boolean; skipped?: boolean; detail: string; provenance?: string | null }>;

/// The payload of the one pre-system-ready dstack event called `name`, or null
/// when there is not exactly one or its payload does not reproduce the digest
/// the RTMR3 replay chains.
export declare function measuredEvent(events: unknown[], name: string): Promise<string | null>;

/// Whether two verified TD reports describe the same TD. RTMR3 covers the
/// instance id, so this is a per-instance tie.
export declare function sameTd(a: unknown, b: unknown): { ok: boolean; differing: string[] };

export declare function verdictOf(checks: AttestationCheck[], expectedSkips?: string[]): AttestationResult["verdict"];

/// The SHA-256 of the SPKI the TLS server at `url` presented, for the channel
/// check. Meaningful only against a host serving the attested workload itself.
export declare function observeTlsSpki(url: string): Promise<string>;

export declare function renderChecks(result: AttestationResult): string;
