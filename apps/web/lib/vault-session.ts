import type { Address, Hex } from "viem";
import { PrismVault, vaultWallet } from "@prismnetwork/agent-sdk/vault";

// The browser reaches the vault through the same wallet-session path an agent
// uses, so a person and their agent open one vault rather than two. The account
// subject is `wallet:<address>` either way.
type SignMessage = (address: Address, message: string) => Promise<Hex>;

async function json(path: string, init?: RequestInit) {
  const response = await fetch(path, {
    ...init,
    headers: { Accept: "application/json", ...(init?.headers ?? {}) },
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    throw new VaultRequestError(response.status, body?.error ?? body?.code ?? "request_failed");
  }
  return body;
}

export class VaultRequestError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

/// Adapts the browser's wallet to the interface the shared vault client
/// expects. The client is the same module the agent SDK ships, so both seal
/// items identically.
export async function openVault(address: Address, sign: SignMessage, passphrase: string | null) {
  const challenge = await json(`/api/agent/challenge?address=${address}`);
  const signature = await sign(address, challenge.message);
  const { session } = await json("/api/agent/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge: challenge.challenge, address, signature }),
  });

  const agent = {
    address,
    session,
    authenticate: async () => {},
    signVaultStatement: (statement: string) => sign(address, statement),
    vaultRequest: async (method: string, segments: string[], options?: { body?: unknown }) =>
      json(`/api/agent/proxy/vault/${segments.join("/")}`, {
        method,
        headers: {
          Authorization: `Bearer ${session}`,
          ...(options?.body ? { "Content-Type": "application/json" } : {}),
        },
        body: options?.body ? JSON.stringify(options.body) : undefined,
      }),
  };

  const vault = new PrismVault(agent);
  await vault.unlock({ passphrase });
  return vault as PrismVault & { wallet: string };
}

export { vaultWallet };
