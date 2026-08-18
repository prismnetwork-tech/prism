export declare const robinhoodChain: unknown;
export declare const USDG: string;
export declare const DEFAULT_IMAGE: string;
export declare const TRUST_CLASSES: readonly ["open", "isolated", "attested", "confidential"];

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
}

export declare class PrismError extends Error {
  readonly status: number;
  readonly code: string;
  readonly body: Record<string, unknown> | null | undefined;
}
