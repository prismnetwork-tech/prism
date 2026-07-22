// Prism Network agent SDK: headless GPU leasing for wallet-holding agents.
// No browser, no Privy. Authenticate with a wallet signature, pay on-chain, run.
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
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

// A digest-pinned image. MCP and x402 import this so their default can't drift
// from the SDK's.
export const DEFAULT_IMAGE =
  "docker.io/ollama/ollama@sha256:a61a8fd395dbb931cc8cb1b5da7a2510746575c87113fdc45b647ee59ef7f808";

const CONFIRMATIONS = 12;
const FETCH_TIMEOUT_MS = 30_000;

const erc20Abi = parseAbi([
  "function approve(address spender, uint256 value) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function balanceOf(address owner) view returns (uint256)",
  "function transfer(address to, uint256 value) returns (bool)",
]);
const escrowAbi = parseAbi([
  "function createLease(bytes32 nodeId, uint32 duration, bytes32 clientReference) returns (uint256)",
]);

function parseBaseUnits(value, field) {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^[0-9]+$/.test(value)) return BigInt(value);
  throw new PrismError(400, `invalid_quote_${field}`);
}

function parseDuration(value) {
  const n = typeof value === "string" ? Number(value) : value;
  if (!Number.isInteger(n) || n <= 0 || n > 0xff_ff_ff_ff) throw new PrismError(400, "invalid_quote_duration");
  return n;
}

// True only for SSH transport/auth failures (host still booting, key not yet
// synced), not a remote command that happens to exit 255. SSH's own errors are
// prefixed "ssh:" or are the publickey-not-ready case that produces no stdout.
function isSshWarmup(res) {
  if (res.code !== 255 || res.timedOut) return false;
  const e = res.stderr;
  return (
    /(^|\n)ssh: /.test(e) ||
    /kex_exchange_identification|Connection reset by peer/.test(e) ||
    (/Permission denied \(publickey/.test(e) && res.stdout === "")
  );
}

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

  async balances() {
    const [usdg, eth] = await Promise.all([
      this.publicClient.readContract({ address: USDG, abi: erc20Abi, functionName: "balanceOf", args: [this.address] }),
      this.publicClient.getBalance({ address: this.address }),
    ]);
    return { address: this.address, usdg: usdg.toString(), eth: eth.toString() };
  }

  async transferUsdg(to, amountMicros) {
    try {
      const hash = await this.walletClient.writeContract({
        address: USDG,
        abi: erc20Abi,
        functionName: "transfer",
        args: [to, BigInt(amountMicros)],
      });
      const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new PrismError(502, "transfer_reverted", { hash });
      return hash;
    } catch (err) {
      if (err instanceof PrismError) throw err;
      throw new PrismError(502, "chain_error", { cause: err?.shortMessage ?? err?.message ?? String(err) });
    }
  }

  async quote({ image, durationSeconds, minVramMib = 16000, preferredNodeId = null } = {}) {
    if (typeof image !== "string" || !/@sha256:[0-9a-f]{64}$/.test(image)) {
      throw new PrismError(400, "image_must_be_digest_pinned", { hint: "use ollama@sha256:... or DEFAULT_IMAGE" });
    }
    if (!Number.isInteger(durationSeconds) || durationSeconds <= 0) throw new PrismError(400, "invalid_duration");
    if (!Number.isInteger(minVramMib) || minVramMib <= 0) throw new PrismError(400, "invalid_min_vram_mib");
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
  // binds funding to keccak256(quote_id), so reproduce it exactly or confirm rejects.
  async fund(quote) {
    if (typeof quote?.quote_id !== "string" || typeof quote?.node_id !== "string") {
      throw new PrismError(400, "invalid_quote");
    }
    const deposit = parseBaseUnits(quote.maximum_escrow, "maximum_escrow");
    const duration = parseDuration(quote.duration_seconds);
    const clientReference = keccak256(stringToBytes(quote.quote_id));
    try {
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
        const approved = await this.publicClient.waitForTransactionReceipt({ hash: approveHash });
        if (approved.status !== "success") throw new PrismError(402, "approve_reverted", { hash: approveHash });
      }
      const hash = await this.walletClient.writeContract({
        address: this.escrow,
        abi: escrowAbi,
        functionName: "createLease",
        args: [quote.node_id, duration, clientReference],
      });
      // 12 confirmations: the control-plane rejects funding until the tx is final.
      const receipt = await this.publicClient.waitForTransactionReceipt({ hash, confirmations: CONFIRMATIONS });
      if (receipt.status !== "success") throw new PrismError(402, "lease_funding_reverted", { hash });
      return { hash, clientReference };
    } catch (err) {
      if (err instanceof PrismError) throw err;
      throw new PrismError(502, "chain_error", { cause: err?.shortMessage ?? err?.message ?? String(err) });
    }
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
      if (res.status === 200) {
        if (!res.body?.ssh_host && res.body?.mode !== "gateway") throw new PrismError(502, "malformed_access");
        return res.body;
      }
      if (res.status !== 404) throw new PrismError(res.status, res.body?.error ?? "access_error");
      await sleep(intervalMs);
    }
    throw new PrismError(408, "access_timeout");
  }

  // quote -> ssh keygen -> fund on-chain -> confirm -> wait for access.
  async lease({ image, durationSeconds, minVramMib, preferredNodeId = null, maxDeposit = null } = {}) {
    if (!this.session) await this.authenticate();
    const quote = await this.quote({ image, durationSeconds, minVramMib, preferredNodeId });
    if (maxDeposit != null && parseBaseUnits(quote.maximum_escrow, "maximum_escrow") > BigInt(maxDeposit)) {
      throw new PrismError(402, "cost_exceeds_max", { required: quote.maximum_escrow, max: String(maxDeposit) });
    }
    const key = this.#generateSshKey();
    try {
      const funded = await this.fund(quote);
      const record = await this.confirm({
        quoteId: quote.quote_id,
        transactionHash: funded.hash,
        sshAuthorizedKey: key.publicKey,
      });
      if (!Number.isInteger(record?.lease_id)) throw new PrismError(502, "malformed_lease_record");
      const access = await this.waitForAccess(record.lease_id);
      return {
        leaseId: record.lease_id,
        access,
        keyPath: key.keyPath,
        keyDir: key.dir,
        publicKey: key.publicKey,
        fundingHash: funded.hash,
        quote,
      };
    } catch (err) {
      rmSync(key.dir, { recursive: true, force: true });
      throw err;
    }
  }

  // Run a command in the remote login shell over SSH (so pipes, redirects, and
  // $(...) all evaluate on the GPU). Retries through the host's sshd warmup, which
  // can lag a few minutes after the box reports ready.
  async run(lease, command, { timeoutMs = 120_000, connectRetries = 24, connectDelayMs = 10_000 } = {}) {
    if (!lease?.access?.ssh_host || !lease.access.ssh_port || !lease.keyPath) {
      throw new PrismError(400, "invalid_lease_handle");
    }
    if (typeof command !== "string" || command.length === 0) throw new PrismError(400, "command_required");
    const target = {
      host: lease.access.ssh_host,
      port: lease.access.ssh_port,
      user: lease.access.ssh_user ?? "root",
      keyPath: lease.keyPath,
    };
    let last;
    for (let attempt = 0; attempt <= connectRetries; attempt++) {
      const res = await this.#ssh(target, command, timeoutMs);
      if (!isSshWarmup(res)) return res;
      last = res;
      if (attempt < connectRetries) await sleep(connectDelayMs);
    }
    return last;
  }

  // Releases local key material. The on-chain lease settles at the end of its duration.
  endLease(lease) {
    if (lease?.keyDir) {
      try {
        rmSync(lease.keyDir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    }
  }

  #generateSshKey() {
    const dir = mkdtempSync(join(tmpdir(), "prism-ssh-"));
    try {
      const keyPath = join(dir, "id_ed25519");
      execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-q", "-f", keyPath, "-C", "prism-agent"]);
      return { dir, keyPath, publicKey: readFileSync(`${keyPath}.pub`, "utf8").trim() };
    } catch (err) {
      rmSync(dir, { recursive: true, force: true });
      throw new PrismError(500, "ssh_keygen_failed", { cause: err?.message ?? String(err) });
    }
  }

  #ssh(target, command, timeoutMs) {
    const args = [
      "-i", target.keyPath,
      "-p", String(target.port),
      "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null",
      "-o", "BatchMode=yes",
      "-o", "ConnectTimeout=15",
      `${target.user}@${target.host}`,
      command,
    ];
    return new Promise((resolve) => {
      const child = spawn("ssh", args);
      let stdout = "";
      let stderr = "";
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, timeoutMs);
      child.stdout.on("data", (d) => (stdout += d));
      child.stderr.on("data", (d) => (stderr += d));
      child.on("close", (code) => {
        clearTimeout(timer);
        resolve({ code: code ?? -1, stdout: stdout.trim(), stderr: stderr.trim(), timedOut });
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        resolve({ code: 255, stdout: "", stderr: String(err), timedOut });
      });
    });
  }

  async #proxy(method, segments, body = null, raw = false, reauthed = false) {
    if (!this.session) await this.authenticate();
    const res = await this.#fetch(`/api/agent/proxy/${segments.join("/")}`, {
      method,
      body,
      headers: { authorization: `Bearer ${this.session}` },
    });
    // Sessions expire after an hour; provisioning can outlive one. Re-auth once.
    if (res.status === 401 && !reauthed) {
      this.session = null;
      await this.authenticate();
      return this.#proxy(method, segments, body, raw, true);
    }
    if (raw) return { status: res.status, body: await res.json().catch(() => null) };
    return this.#unwrap(res);
  }

  async #json(path, init) {
    const res = await this.#fetch(path, init);
    return this.#unwrap(res);
  }

  async #fetch(path, { method = "GET", body = null, headers = {} } = {}) {
    try {
      return await fetch(`${this.apiBase}${path}`, {
        method,
        headers: { accept: "application/json", ...(body ? { "content-type": "application/json" } : {}), ...headers },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch (err) {
      throw new PrismError(504, "control_plane_unreachable", { cause: err?.message ?? String(err) });
    }
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
