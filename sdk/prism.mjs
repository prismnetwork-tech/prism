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
import { openRelayForwarder } from "./relay.mjs";
import { PrismVault } from "./vault.mjs";
import { PrismWorkspace } from "./workspace.mjs";

export { PrismVault, VaultError, DEFAULT_TRUST_FLOOR, VAULT_KEY_STATEMENT } from "./vault.mjs";
export {
  PrismWorkspace,
  WorkspaceError,
  DEFAULT_WORKSPACE_TRUST_FLOOR,
  WORKSPACE_KEY_STATEMENT,
} from "./workspace.mjs";

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

// Weakest to strongest. "open" means the supplier can read everything the
// workload touches, so an agent handling anything sensitive should raise this.
export const TRUST_CLASSES = ["open", "isolated", "attested", "confidential"];

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

// Matches the limit the control plane and the node both enforce, so a command
// that cannot run is rejected here rather than after an escrow is funded.
export const MAX_COMMAND_BYTES = 8 * 1024;

function assertCommand(value) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new PrismError(400, "invalid_command", { hint: "a batch command cannot be empty" });
  }
  if (Buffer.byteLength(value, "utf8") > MAX_COMMAND_BYTES) {
    throw new PrismError(400, "invalid_command", { hint: "a batch command cannot exceed 8 KiB" });
  }
  return value;
}

function assertTrustClass(value) {
  if (!TRUST_CLASSES.includes(value)) {
    throw new PrismError(400, "invalid_trust_class", { expected: TRUST_CLASSES });
  }
  return value;
}

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
    if (typeof privateKey !== "string" || privateKey.trim() === "") {
      throw new Error(
        "privateKey is required: a 32-byte hex key, with or without 0x (most surfaces read it from PRISM_AGENT_KEY)",
      );
    }
    this.apiBase = apiBase.replace(/\/$/, "");
    this.escrow = escrow;
    const trimmed = privateKey.trim();
    try {
      this.account = privateKeyToAccount(trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`);
    } catch (err) {
      throw new Error(
        `privateKey is not a valid key: ${err?.message ?? err}. Expected 32 bytes of hex, with or without the 0x prefix.`,
      );
    }
    const transport = http(rpcUrl ?? robinhoodChain.rpcUrls.default.http[0]);
    this.publicClient = createPublicClient({ chain: robinhoodChain, transport });
    this.walletClient = createWalletClient({ account: this.account, chain: robinhoodChain, transport });
    this.session = null;
    this.vault = new PrismVault(this);
    this.workspace = new PrismWorkspace(this);
  }

  get address() {
    return this.account.address;
  }

  // The vault and workspace keys are derived from this signature on the
  // caller's machine. It is returned to the client that asked and never sent
  // anywhere.
  async signVaultStatement(statement) {
    return this.account.signMessage({ message: statement });
  }

  async vaultRequest(method, segments, { body = null } = {}) {
    return this.#proxy(method, ["vault", ...segments], { body });
  }

  async workspaceRequest(method, segments, { body = null } = {}) {
    return this.#proxy(method, ["workspaces", ...segments], { body });
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

  async offers({ minTrust = "open" } = {}) {
    return this.#proxy("GET", ["offers"], { query: { min_trust: assertTrustClass(minTrust) } });
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

  async quote({ image, durationSeconds, minVramMib = 16000, preferredNodeId = null, minTrustClass = "open", command = null } = {}) {
    if (typeof image !== "string" || !/@sha256:[0-9a-f]{64}$/.test(image)) {
      throw new PrismError(400, "image_must_be_digest_pinned", { hint: "use ollama@sha256:... or DEFAULT_IMAGE" });
    }
    if (!Number.isInteger(durationSeconds) || durationSeconds <= 0) throw new PrismError(400, "invalid_duration");
    if (!Number.isInteger(minVramMib) || minVramMib <= 0) throw new PrismError(400, "invalid_min_vram_mib");
    return this.#proxy("POST", ["leases", "match"], {
      body: {
        request: {
          image,
          duration_seconds: durationSeconds,
          min_vram_mib: minVramMib,
          preferred_node_id: preferredNodeId,
          min_trust_class: assertTrustClass(minTrustClass),
          ...(command === null ? {} : { command: assertCommand(command) }),
        },
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
      body: {
        quote_id: quoteId,
        transaction_hash: transactionHash,
        ssh_authorized_key: sshAuthorizedKey,
      },
    });
  }

  async leases() {
    return this.#proxy("GET", ["leases"]);
  }

  async access(leaseId) {
    return this.#proxy("GET", ["leases", String(leaseId), "access"]);
  }

  /// The output of a batch lease, once its node has reported.
  async result(leaseId) {
    return this.#proxy("GET", ["leases", String(leaseId), "result"]);
  }

  async waitForResult(leaseId, { timeoutMs = 900_000, intervalMs = 10_000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    let polls = 0;
    while (Date.now() < deadline) {
      const res = await this.#proxy("GET", ["leases", String(leaseId), "result"], { raw: true });
      if (res.status === 200) return res.body;
      // The control plane keeps answering 404 for a batch whose node died
      // without reporting, so check the lease state occasionally and stop
      // waiting once it is terminal. 429 and 5xx are transient; aborting a
      // paid wait on one would strand the deposit.
      if (res.status === 404) {
        polls += 1;
        if (polls % 6 === 0) {
          const state = await this.#terminalState(leaseId);
          if (state) {
            const again = await this.#proxy("GET", ["leases", String(leaseId), "result"], { raw: true });
            if (again.status === 200) return again.body;
            throw new PrismError(502, "batch_no_result", { lease_id: leaseId, state });
          }
        }
      } else if (res.status !== 429 && res.status < 500) {
        throw new PrismError(res.status, res.body?.code ?? "result_failed", res.body);
      }
      await sleep(intervalMs);
    }
    throw new PrismError(408, "result_timeout", { lease_id: leaseId });
  }

  async #terminalState(leaseId) {
    let leases;
    try {
      leases = await this.leases();
    } catch {
      return null;
    }
    const record = Array.isArray(leases) ? leases.find((l) => l.lease_id === leaseId) : null;
    const state = record?.state ?? "";
    const terminal = ["closing", "settlement_pending", "finalized", "refunded", "failed"];
    return terminal.includes(state) ? state : null;
  }

  async waitForAccess(leaseId, { timeoutMs = 600_000, intervalMs = 10_000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const res = await this.#proxy("GET", ["leases", String(leaseId), "access"], { raw: true });
      if (res.status === 200) {
        if (!res.body?.ssh_host && res.body?.mode !== "gateway") throw new PrismError(502, "malformed_access");
        return res.body;
      }
      if (res.status !== 404 && res.status !== 429 && res.status < 500) {
        throw new PrismError(res.status, res.body?.error ?? "access_error", res.body);
      }
      await sleep(intervalMs);
    }
    throw new PrismError(408, "access_timeout", { lease_id: leaseId });
  }

  // quote -> ssh keygen -> fund on-chain -> confirm -> wait for access.
  async lease({
    image,
    durationSeconds,
    minVramMib,
    preferredNodeId = null,
    maxDeposit = null,
    minTrustClass = "open",
    command = null,
  } = {}) {
    if (!this.session) await this.authenticate();
    // A wallet with no balance at all cannot fund anything, and a doomed quote
    // still holds capacity against other renters until it expires. Refuse
    // before quoting.
    const balances = await this.balances();
    if (balances.usdg === "0" || balances.eth === "0") {
      throw new PrismError(402, "wallet_unfunded", {
        address: this.address,
        usdg: balances.usdg,
        eth_wei: balances.eth,
        hint: "the wallet needs USDG for the deposit and native ETH for gas on Robinhood Chain (id 4663) before it can lease",
      });
    }
    const quote = await this.quote({
      image,
      durationSeconds,
      minVramMib,
      preferredNodeId,
      minTrustClass,
      command,
    });
    if (maxDeposit != null && parseBaseUnits(quote.maximum_escrow, "maximum_escrow") > BigInt(maxDeposit)) {
      throw new PrismError(402, "cost_exceeds_max", { required: quote.maximum_escrow, max: String(maxDeposit) });
    }
    const key = this.#generateSshKey();
    let funded = null;
    let leaseId = null;
    try {
      funded = await this.fund(quote);
      const record = await this.confirm({
        quoteId: quote.quote_id,
        transactionHash: funded.hash,
        sshAuthorizedKey: key.publicKey,
      });
      if (!Number.isInteger(record?.lease_id)) {
        throw new PrismError(502, "malformed_lease_record", { funding_hash: funded.hash });
      }
      leaseId = record.lease_id;
      // A batch lease never hands out access, so waiting for it would block
      // until the timeout and then report a failure that never happened. Wait
      // for what the command printed instead.
      if (command !== null) {
        const result = await this.waitForResult(leaseId, { timeoutMs: durationSeconds * 1000 + 900_000 });
        rmSync(key.dir, { recursive: true, force: true });
        return { leaseId, result, fundingHash: funded.hash, quote };
      }
      const access = await this.waitForAccess(leaseId);
      return {
        leaseId,
        access,
        keyPath: key.keyPath,
        keyDir: key.dir,
        publicKey: key.publicKey,
        fundingHash: funded.hash,
        quote,
      };
    } catch (err) {
      // Before funding, the key opens nothing; discard it. After funding it is
      // the only way into a machine that is being paid for, so it stays on
      // disk and the error says where everything is.
      if (funded === null) {
        rmSync(key.dir, { recursive: true, force: true });
        throw err;
      }
      const detail = { funding_hash: funded.hash, lease_id: leaseId, key_path: key.keyPath };
      if (err instanceof PrismError) {
        err.body = { ...(err.body ?? {}), ...detail };
        throw err;
      }
      throw new PrismError(502, "lease_failed_after_funding", { ...detail, cause: err?.message ?? String(err) });
    }
  }

  // Run a command in the remote login shell over SSH (so pipes, redirects, and
  // $(...) all evaluate on the GPU). Retries through the host's sshd warmup, which
  // can lag a few minutes after the box reports ready. `stdin` feeds the command
  // its input, which keeps anything sensitive out of the remote process table.
  async run(lease, command, { timeoutMs = 120_000, connectRetries = 24, connectDelayMs = 10_000, stdin = null } = {}) {
    if (typeof command !== "string" || command.length === 0) throw new PrismError(400, "command_required");
    if (!lease?.keyPath) {
      throw new PrismError(400, "invalid_lease_handle", {
        mode: lease?.access?.mode ?? null,
        lease_id: lease?.leaseId ?? null,
        hint: "the lease handle carries no ssh key",
      });
    }

    // A physical node accepts nothing inbound, so its session arrives through
    // the gateway. Opening the renter's half of that tunnel gives a local port
    // that behaves like any other host, which is why the retry loop below does
    // not care which kind of capacity it is talking to.
    const forwarder =
      lease.access?.mode === "gateway" ? await openRelayForwarder(lease.access) : null;
    try {
      const target = forwarder
        ? {
            host: forwarder.host,
            port: forwarder.port,
            user: lease.access.ssh_user ?? "workspace",
            keyPath: lease.keyPath,
          }
        : {
            host: lease.access?.ssh_host,
            port: lease.access?.ssh_port,
            user: lease.access?.ssh_user ?? "root",
            keyPath: lease.keyPath,
          };
      if (!target.host || !target.port) {
        throw new PrismError(400, "invalid_lease_handle", {
          mode: lease.access?.mode ?? null,
          lease_id: lease.leaseId ?? null,
          hint: "the access grant names no reachable endpoint",
        });
      }
      let last;
      for (let attempt = 0; attempt <= connectRetries; attempt++) {
        const res = await this.#ssh(target, command, timeoutMs, stdin);
        if (!isSshWarmup(res)) return res;
        last = res;
        if (attempt < connectRetries) await sleep(connectDelayMs);
      }
      return last;
    } finally {
      if (forwarder) await forwarder.close();
    }
  }

  /// A local address that forwards to the workspace for as long as it is open.
  /// Use it for anything that is not a one-shot command: `scp`, port forwards,
  /// an interactive shell, a notebook client. The caller closes it.
  async forward(lease, { service = "ssh" } = {}) {
    if (lease?.access?.mode !== "gateway") {
      throw new PrismError(400, "forward_not_supported", {
        mode: lease?.access?.mode ?? null,
        hint: "this lease is reachable directly and needs no relay",
      });
    }
    return openRelayForwarder(lease.access, { service });
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

  #ssh(target, command, timeoutMs, stdin = null) {
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
      if (stdin !== null) {
        // A command that exits before reading its input closes the pipe, which
        // is a normal end to the transfer and not a failure to report.
        child.stdin.on("error", () => {});
        child.stdin.end(stdin);
      }
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

  async #proxy(method, segments, { body = null, raw = false, query = null, reauthed = false } = {}) {
    if (!this.session) await this.authenticate();
    const search = query ? `?${new URLSearchParams(query)}` : "";
    const res = await this.#fetch(`/api/agent/proxy/${segments.join("/")}${search}`, {
      method,
      body,
      headers: { authorization: `Bearer ${this.session}` },
    });
    // Sessions expire after an hour; provisioning can outlive one. Re-auth once.
    if (res.status === 401 && !reauthed) {
      this.session = null;
      await this.authenticate();
      return this.#proxy(method, segments, { body, raw, query, reauthed: true });
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
    this.name = "PrismError";
    this.status = status;
    this.code = code;
    this.body = body;
  }
}
