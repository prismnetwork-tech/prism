// Prism Network agent SDK — headless GPU leasing for wallet-holding agents.
// No browser, no Privy. Authenticate with a wallet signature, pay on-chain, run.
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  encodeFunctionData,
  http,
  keccak256,
  parseAbi,
  stringToBytes,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

export const robinhoodChain = defineChain({
  id: 4663,
  name: "Robinhood Chain",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: ["https://rpc.mainnet.chain.robinhood.com"] } },
});

export const USDG = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";

const erc20Abi = parseAbi([
  "function approve(address spender, uint256 value) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function balanceOf(address owner) view returns (uint256)",
]);
const escrowAbi = parseAbi([
  "function createLease(bytes32 nodeId, uint32 duration, bytes32 clientReference) returns (uint256)",
]);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class PrismAgent {
  constructor({ privateKey, apiBase = "https://prismnetwork.tech", escrow, rpcUrl }) {
    if (!escrow) throw new Error("escrow address is required");
    this.apiBase = apiBase.replace(/\/$/, "");
    this.escrow = escrow;
    this.account = privateKeyToAccount(privateKey);
    const transport = http(rpcUrl ?? robinhoodChain.rpcUrls.default.http[0]);
    this.publicClient = createPublicClient({ chain: robinhoodChain, transport });
    this.walletClient = createWalletClient({ account: this.account, chain: robinhoodChain, transport });
    this.session = null;
  }

  get address() {
    return this.account.address;
  }

  async authenticate() {
    const challenge = await this.#json(`/api/agent/challenge?address=${this.address}`);
    const signature = await this.account.signMessage({ message: challenge.message });
    const session = await this.#json("/api/agent/session", {
      method: "POST",
      body: { challenge: challenge.challenge, address: this.address, signature },
    });
    this.session = session.session;
    return session;
  }

  async offers() {
    return this.#proxy("GET", ["offers"]);
  }

  async quote({ image, durationSeconds, minVramMib, preferredNodeId = null }) {
    return this.#proxy("POST", ["leases", "match"], {
      request: {
        image,
        duration_seconds: durationSeconds,
        min_vram_mib: minVramMib,
        preferred_node_id: preferredNodeId,
      },
    });
  }

  // Approve USDG and create the on-chain lease bound to the quote. The escrow
  // binds funding to keccak256(quote_id) — reproduce it exactly or confirm rejects.
  async fund(quote) {
    const clientReference = keccak256(stringToBytes(quote.quote_id));
    const deposit = BigInt(quote.maximum_escrow);
    const allowance = await this.publicClient.readContract({
      address: USDG,
      abi: erc20Abi,
      functionName: "allowance",
      args: [this.address, this.escrow],
    });
    if (allowance < deposit) {
      const approveHash = await this.walletClient.writeContract({
        address: USDG,
        abi: erc20Abi,
        functionName: "approve",
        args: [this.escrow, deposit],
      });
      await this.publicClient.waitForTransactionReceipt({ hash: approveHash });
    }
    const hash = await this.walletClient.writeContract({
      address: this.escrow,
      abi: escrowAbi,
      functionName: "createLease",
      args: [quote.node_id, Number(quote.duration_seconds), clientReference],
    });
    await this.publicClient.waitForTransactionReceipt({ hash, confirmations: 12 });
    return { hash, clientReference };
  }

  async confirm({ quoteId, transactionHash, sshAuthorizedKey }) {
    return this.#proxy("POST", ["leases", "confirm"], {
      quote_id: quoteId,
      transaction_hash: transactionHash,
      ssh_authorized_key: sshAuthorizedKey,
    });
  }

  async leases() {
    return this.#proxy("GET", ["leases"]);
  }

  async access(leaseId) {
    return this.#proxy("GET", ["leases", String(leaseId), "access"]);
  }

  async waitForAccess(leaseId, { timeoutMs = 600_000, intervalMs = 10_000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const res = await this.#proxy("GET", ["leases", String(leaseId), "access"], null, true);
      if (res.status === 200) return res.body;
      if (res.status !== 404) throw new PrismError(res.status, res.body?.error ?? "access_error");
      await sleep(intervalMs);
    }
    throw new PrismError(408, "access_timeout");
  }

  async #proxy(method, segments, body = null, raw = false) {
    if (!this.session) throw new PrismError(401, "not_authenticated");
    const res = await this.#fetch(`/api/agent/proxy/${segments.join("/")}`, {
      method,
      body,
      headers: { authorization: `Bearer ${this.session}` },
    });
    if (raw) return { status: res.status, body: await res.json().catch(() => null) };
    return this.#unwrap(res);
  }

  async #json(path, init) {
    const res = await this.#fetch(path, init);
    return this.#unwrap(res);
  }

  async #fetch(path, { method = "GET", body = null, headers = {} } = {}) {
    return fetch(`${this.apiBase}${path}`, {
      method,
      headers: { accept: "application/json", ...(body ? { "content-type": "application/json" } : {}), ...headers },
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  async #unwrap(res) {
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new PrismError(res.status, data?.error ?? data?.code ?? "request_failed", data);
    return data;
  }
}

export class PrismError extends Error {
  constructor(status, code, body) {
    super(`prism ${status}: ${code}`);
    this.status = status;
    this.code = code;
    this.body = body;
  }
}
