export declare const robinhoodChain: unknown;
export declare const USDG: string;
export declare const DEFAULT_IMAGE: string;
export declare const TRUST_CLASSES: readonly ["open", "isolated", "attested", "confidential"];

export interface LeaseAccess {
  mode?: string;
  ssh_host?: string;
  ssh_port?: number;
  ssh_user?: string;
  expires_at?: string;
  [key: string]: unknown;
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
  endLease(lease: LeaseHandle): void;
}

export declare class PrismError extends Error {
  readonly status: number;
  readonly code: string;
  readonly body: Record<string, unknown> | null | undefined;
}
