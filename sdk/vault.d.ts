export type TrustFloor = "open" | "isolated" | "attested" | "confidential";

export type VaultItem = {
  item_id: string;
  version: number;
  envelope: { wrapped_key: string; nonce: string; ciphertext: string };
  min_trust_class: TrustFloor;
  label: string;
  created_at: string;
  updated_at: string;
};

export type VaultRelease = {
  item_id: string;
  lease_id: number;
  item_version: number;
  lease_trust_class: TrustFloor;
  released_at: string;
};

/// What the vault client needs from its caller: an address, a way to sign, and
/// a way to reach the control plane. The agent SDK and the browser each supply
/// their own, so the crypto below is written once.
export type VaultTransport = {
  address: string;
  session: unknown;
  authenticate: () => Promise<unknown>;
  signVaultStatement: (statement: string) => Promise<string>;
  vaultRequest: (method: string, segments: string[], options?: { body?: unknown }) => Promise<any>;
};

export declare const VAULT_ENVELOPE_DOMAIN: string;
export declare const VAULT_KEY_STATEMENT: string;
export declare const DEFAULT_TRUST_FLOOR: TrustFloor;

export declare function vaultWallet(address: string): string;
export declare function associatedData(
  wallet: string,
  itemId: string,
  version: number,
  trustFloor: TrustFloor,
): Uint8Array;

export declare class PrismVault {
  constructor(transport: VaultTransport);
  readonly unlocked: boolean;
  readonly wallet: string | null;
  unlock(options?: { passphrase?: string | null }): Promise<this>;
  lock(): void;
  list(): Promise<VaultItem[]>;
  releases(): Promise<VaultRelease[]>;
  put(
    value: unknown,
    options?: {
      itemId?: string | null;
      replaces?: VaultItem | null;
      trustFloor?: TrustFloor;
      label?: string;
    },
  ): Promise<VaultItem>;
  get(itemId: string, options?: { json?: boolean }): Promise<any>;
  open(item: VaultItem, options?: { expectVersion?: number | null }): Promise<string>;
  remove(itemId: string): Promise<null>;
  releaseInto(
    lease: number | { leaseId?: number; lease_id?: number },
    itemId: string,
    options?: { json?: boolean },
  ): Promise<any>;
  static permits(trustFloor: TrustFloor, leaseTrustClass: TrustFloor): boolean;
}

export declare class VaultError extends Error {
  readonly code: string;
  readonly body?: unknown;
}
