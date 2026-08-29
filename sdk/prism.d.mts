import type { AttestationResult, VerifyConfidentialOptions, WorkloadPin } from "./attest.d.mts";

export declare const robinhoodChain: unknown;
export declare const USDG: string;
export declare const DEFAULT_IMAGE: string;
export declare const TRUST_CLASSES: readonly ["open", "isolated", "attested", "confidential"];

export { DEFAULT_CONFIDENTIAL_BASE, EXPECTED_WORKLOAD, renderChecks, verifyConfidential } from "./attest.d.mts";
export type { AttestationCheck, AttestationResult, WorkloadPin } from "./attest.d.mts";

/// `mode` says which of the two shapes arrived. Brokered capacity fills in
/// `ssh_host` and `ssh_port`; a node that accepts nothing inbound fills in the
/// gateway fields instead and is reached through a relay.
export interface LeaseAccess {
  mode?: "direct_ssh" | "gateway" | string;
  ssh_host?: string;
  ssh_port?: number;
  ssh_user?: string;
  gateway_host?: string;
  relay_port?: number;
  /// The root the relay's certificate chains to, in PEM. It is served under a
  /// private CA, so this is what the client pins.
  gateway_ca?: string;
  token?: string;
  jupyter_path?: string;
  jupyter_token?: string;
  expires_at?: string;
  [key: string]: unknown;
}

/// A local address that forwards to the workspace until it is closed.
export interface RelayForwarder {
  host: string;
  port: number;
  close(): Promise<void>;
}

export interface LeaseHandle {
  leaseId: number;
  access: LeaseAccess;
  keyPath: string;
  keyDir: string;
  publicKey: string;
  fundingHash: string;
  quote: Record<string, unknown>;
}

export interface BatchLeaseHandle {
  leaseId: number;
  result: { exit_code?: number; stdout?: string; stderr?: string; truncated?: boolean };
  fundingHash: string;
  quote: Record<string, unknown>;
}

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface PaidResponse {
  status: number;
  headers: Headers;
  /// The response bytes exactly as they arrived, which is what a signed receipt
  /// over the exchange commits to.
  bytes: Buffer;
  tx: string;
  /// The request as the attempt that was served built it. Under E2EE each
  /// attempt seals its own envelope, so this is the one the receipt covers.
  sent: { bytes: Buffer; headers?: Record<string, string>; [key: string]: unknown };
}

/// One confidential generation, with everything needed to check it afterwards.
export interface ConfidentialRun {
  model: string;
  content: string | null;
  usage: Record<string, unknown> | null;
  receiptId: string | null;
  receipt: Record<string, unknown> | null;
  /// The key set the prompt was encrypted to, when e2ee was on.
  keysetDigest: string | null;
  e2ee: boolean;
  priceMicros: string;
  priceUsdg: string;
  tx: string;
  bytes: { request: Buffer; response: Buffer; restoredRequest?: Buffer };
  verify(options?: Partial<VerifyConfidentialOptions>): Promise<AttestationResult>;
}

export declare class PrismAgent {
  constructor(options: { privateKey: string; escrow: string; apiBase?: string; rpcUrl?: string });
  readonly address: string;
  readonly vault: unknown;
  readonly workspace: unknown;
  authenticate(): Promise<{ session: string }>;
  offers(options?: { minTrust?: string }): Promise<Array<Record<string, unknown>>>;
  balances(): Promise<{ address: string; usdg: string; eth: string }>;
  transferUsdg(to: string, amountMicros: number | string | bigint): Promise<string>;
  quote(options: {
    image: string;
    durationSeconds: number;
    minVramMib?: number;
    preferredNodeId?: string | null;
    minTrustClass?: string;
    command?: string | null;
  }): Promise<Record<string, unknown>>;
  fund(quote: Record<string, unknown>): Promise<{ hash: string; clientReference: string }>;
  confirm(options: { quoteId: string; transactionHash: string; sshAuthorizedKey: string }): Promise<Record<string, unknown>>;
  leases(): Promise<Array<Record<string, unknown>>>;
  access(leaseId: number): Promise<LeaseAccess>;
  result(leaseId: number): Promise<Record<string, unknown>>;
  waitForResult(leaseId: number, options?: { timeoutMs?: number; intervalMs?: number }): Promise<Record<string, unknown>>;
  waitForAccess(leaseId: number, options?: { timeoutMs?: number; intervalMs?: number }): Promise<LeaseAccess>;
  lease(options: {
    image: string;
    durationSeconds: number;
    minVramMib?: number;
    preferredNodeId?: string | null;
    maxDeposit?: number | string | bigint | null;
    minTrustClass?: string;
    command?: string | null;
  }): Promise<LeaseHandle | BatchLeaseHandle>;
  run(
    lease: LeaseHandle,
    command: string,
    options?: { timeoutMs?: number; connectRetries?: number; connectDelayMs?: number; stdin?: string | null },
  ): Promise<RunResult>;
  /// Only for a lease reached through the gateway. Use it for anything that is
  /// not a one-shot command: scp, a notebook client, an interactive shell.
  forward(lease: LeaseHandle, options?: { service?: "ssh" | "jupyter" }): Promise<RelayForwarder>;
  endLease(lease: LeaseHandle): void;
  /// Pay for one call to a metered endpoint, keeping the payment until the
  /// endpoint serves. Bytes are sent verbatim. Pass `seal` instead of `body` for
  /// a request that has to be rebuilt per attempt, with `fingerprint` so the
  /// kept payment still recognises the two attempts as the same request.
  payAndPost(options: {
    base: string;
    path: string;
    price: bigint | number | string;
    payTo: string;
    body?: Uint8Array | string | Record<string, unknown> | null;
    headers?: Record<string, string>;
    seal?: (() => { bytes: Uint8Array; headers?: Record<string, string> }) | null;
    fingerprint?: Uint8Array | string | null;
    retryDelayMs?: number;
    caller?: string;
  }): Promise<PaidResponse>;
  /// One generation from the confidential tier, end-to-end encrypted by default
  /// to a key the serving enclave's attestation quote commits to, from an
  /// enclave running the code `expectedWorkload` pins.
  confidentialInfer(options: {
    prompt?: string;
    messages?: Array<{ role: string; content: string }>;
    model?: string | null;
    maxUsdg?: number;
    maxTokens?: number;
    e2ee?: boolean;
    expectedWorkload?: WorkloadPin | null;
    endpoint?: string;
  }): Promise<ConfidentialRun>;
}

export declare class PrismError extends Error {
  readonly status: number;
  readonly code: string;
  readonly body: Record<string, unknown> | null | undefined;
}
