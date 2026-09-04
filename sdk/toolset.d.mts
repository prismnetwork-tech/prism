import type { PrismAgent } from "./prism.mjs";

export declare const DEFAULT_ESCROW: string;
export declare const PUBLIC_API: string;
export declare const NO_WALLET: string;

export declare function isRefusal(body: string): boolean;

export declare function agentFromEnv(
  get?: (name: string) => string | undefined,
): PrismAgent | null;

export interface LeaseAndRunOptions {
  command: string;
  durationSeconds?: number;
  minVramMib?: number;
  image?: string;
  maxUsdg?: number;
  minTrustClass?: "open" | "isolated" | "attested" | "confidential";
}

export declare class PrismToolset {
  constructor(options?: { agent?: PrismAgent | null; publicApi?: string });
  readonly agent: PrismAgent | null;
  wallet(): Promise<string>;
  listGpus(minTrustClass?: string): Promise<string>;
  leaseAndRun(options: LeaseAndRunOptions): Promise<string>;
  run(leaseId: number, command: string): Promise<string>;
  endLease(leaseId: number): Promise<string>;
}
