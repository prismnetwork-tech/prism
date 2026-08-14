export type TrustFloor = "open" | "isolated" | "attested" | "confidential";

export type WorkspaceSnapshot = {
  wrapped_key: string;
  nonce: string;
  ciphertext_digest: string;
  size_bytes: number;
};

export type Workspace = {
  workspace_id: string;
  name: string;
  version: number;
  snapshot?: WorkspaceSnapshot;
  min_trust_class: TrustFloor;
  created_at: string;
  updated_at: string;
};

/// A presigned upload, valid for fifteen minutes. `version` is the one storage
/// will accept, and it is authenticated into the ciphertext, so the snapshot is
/// sealed after this arrives rather than before.
export type WorkspaceUploadGrant = {
  url: string;
  version: number;
  key: string;
};

export type WorkspaceDownloadGrant = WorkspaceSnapshot & {
  url: string;
  version: number;
};

/// The handle an interactive `lease()` returns. `save` and `restore` reach the
/// machine over SSH, which a batch lease has no key for.
export type LeaseHandle = {
  access: { ssh_host: string; ssh_port: number; ssh_user?: string };
  keyPath: string;
};

/// What the workspace client needs from its caller: an address, a way to sign,
/// a way to reach the control plane, and, for `save` and `restore`, a way to
/// reach the leased machine. `signVaultStatement` is the generic "sign this
/// statement" hook the vault also uses; the statement differs, so the keys do.
export type WorkspaceTransport = {
  address: string;
  session: unknown;
  authenticate: () => Promise<unknown>;
  signVaultStatement: (statement: string) => Promise<string>;
  workspaceRequest: (method: string, segments: string[], options?: { body?: unknown }) => Promise<any>;
  run?: (
    lease: LeaseHandle,
    command: string,
    options?: { timeoutMs?: number; stdin?: string | null },
  ) => Promise<{ code: number; stdout: string; stderr: string; timedOut: boolean }>;
};

export declare const WORKSPACE_ENVELOPE_DOMAIN: string;
export declare const WORKSPACE_KEY_STATEMENT: string;
export declare const DEFAULT_WORKSPACE_TRUST_FLOOR: TrustFloor;

export declare function workspaceAssociatedData(
  wallet: string,
  workspaceId: string,
  version: number,
  trustFloor: TrustFloor,
): Uint8Array;

export declare class PrismWorkspace {
  constructor(transport: WorkspaceTransport);
  readonly unlocked: boolean;
  readonly wallet: string | null;
  unlock(options?: { passphrase?: string | null }): Promise<this>;
  lock(): void;
  list(): Promise<Workspace[]>;
  get(workspaceId: string | Workspace): Promise<Workspace>;
  create(name: string, options?: { minTrustClass?: TrustFloor }): Promise<Workspace>;
  remove(workspaceId: string | Workspace): Promise<null>;
  save(
    lease: LeaseHandle,
    workspaceId: string | Workspace,
    remotePath: string,
    options?: { timeoutMs?: number },
  ): Promise<Workspace>;
  restore(
    lease: LeaseHandle,
    workspaceId: string | Workspace,
    remotePath: string,
    options?: {
      expectVersion?: number | null;
      expectTrustClass?: TrustFloor | null;
      timeoutMs?: number;
    },
  ): Promise<Workspace>;
  static permits(trustFloor: TrustFloor, leaseTrustClass: TrustFloor): boolean;
}

export declare class WorkspaceError extends Error {
  readonly code: string;
  readonly body?: unknown;
}
