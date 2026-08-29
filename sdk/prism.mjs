// Prism Network agent SDK: headless GPU leasing for wallet-holding agents.
// No browser, no Privy. Authenticate with a wallet signature, pay on-chain, run.
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
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
import { appraiseWorkload, DEFAULT_CONFIDENTIAL_BASE, EXPECTED_WORKLOAD, verifyConfidential } from "./attest.mjs";
import { decryptResponse, encryptChatRequest } from "./e2ee.mjs";
import { openRelayForwarder } from "./relay.mjs";
import { PrismVault } from "./vault.mjs";
import { toHex, verifyComposeMeasurement, verifyQuote, verifyReportBinding } from "./vendor/aci-verifier/index.mjs";
import { PrismWorkspace } from "./workspace.mjs";

export { DEFAULT_CONFIDENTIAL_BASE, EXPECTED_WORKLOAD, renderChecks, verifyConfidential } from "./attest.mjs";
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
// A generation can wait on a cold box, so the paid call gets its own budget and
// keeps the payment across the wait rather than paying twice.
const PAID_CALL_TIMEOUT_MS = 620_000;
const PAID_CALL_DEADLINE_MS = 600_000;
const PAID_CALL_RETRY_MS = 15_000;
const DEFAULT_MAX_TOKENS = 512;

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

const asBytes = (body) =>
  typeof body === "string" || body instanceof Uint8Array ? body : Buffer.from(JSON.stringify(body), "utf8");

/// A sealed answer, or an error that names the reason it did not open. The
/// service marks an encrypted answer with `x-e2ee-applied`, and a plaintext one
/// fails the AEAD for a reason that has nothing to do with the key.
function decryptAnswer(bytes, clientKey, headers, receiptId) {
  const applied = headers.get("x-e2ee-applied");
  const paidFor = `the generation is paid for, and receipt ${receiptId} still verifies what the workload served`;
  if (applied !== null && applied.toLowerCase() !== "true") {
    throw new PrismError(502, "e2ee_not_applied", {
      cause: `the endpoint answered with x-e2ee-applied: ${applied}`,
      hint: `the enclave returned the answer unencrypted; ${paidFor}`,
    });
  }
  try {
    return decryptResponse(bytes, clientKey);
  } catch (err) {
    if (applied !== null) throw err;
    throw new PrismError(502, "e2ee_not_applied", {
      cause: err?.message ?? String(err),
      hint: `the endpoint marked no answer as encrypted and this one did not open under this call's key; ${paidFor}`,
    });
  }
}

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
      const hash = await this.#submit(() =>
        this.walletClient.writeContract({
          address: USDG,
          abi: erc20Abi,
          functionName: "transfer",
          args: [to, BigInt(amountMicros)],
        }),
      );
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
    return this.#submit(() => this.#fundNow(quote));
  }

  async #fundNow(quote) {
    if (typeof quote?.quote_id !== "string" || typeof quote?.node_id !== "string") {
      throw new PrismError(400, "invalid_quote");
    }
    const deposit = parseBaseUnits(quote.maximum_escrow, "maximum_escrow");
    const duration = parseDuration(quote.duration_seconds);
    const clientReference = keccak256(stringToBytes(quote.quote_id));
    try {
      // Approving and spending are one indivisible step. The approval covers
      // exactly this deposit, so a second lease that read the allowance before
      // this one spent it would find it gone by the time the chain ran it.
      const hash = await (async () => {
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
        const funding = await this.walletClient.writeContract({
          address: this.escrow,
          abi: escrowAbi,
          functionName: "createLease",
          args: [quote.node_id, duration, clientReference],
        });
        // One confirmation here, not for the control-plane's benefit but so the
        // allowance and the nonce are settled before the next lease reads them.
        await this.publicClient.waitForTransactionReceipt({ hash: funding });
        return funding;
      })();
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
        // The control plane names the reason in `code`; without it a lease that
        // will never open access reports as a generic `access_error` and the
        // caller has to go and read the body to learn anything.
        throw new PrismError(res.status, res.body?.error ?? res.body?.code ?? "access_error", res.body);
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
    const key = this.#generateSshKey();
    let quote = null;
    let funded = null;
    let leaseId = null;
    try {
      // One renter takes one machine at a time, up to the point the chain knows
      // it is taken. Asking for a quote releases this renter's other open
      // quotes, so two quotes held at once can name the same machine and the
      // second lease reverts against a node that is no longer free. Only the
      // claim is serialised: provisioning, which is the part that takes
      // minutes, still runs in parallel.
      const record = await this.#submit(async () => {
        quote = await this.quote({
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
        funded = await this.#fundNow(quote);
        return this.confirm({
          quoteId: quote.quote_id,
          transactionHash: funded.hash,
          sshAuthorizedKey: key.publicKey,
        });
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

  // Unconsumed inference payments, keyed by the endpoint, the price and the
  // request they paid for, so a generation that never happened is retried with
  // the payment already made instead of paying for it twice, and a different
  // prompt never inherits it.
  #pendingPayments = new Map();

  /// Pay for one call to a metered endpoint and keep the payment until the
  /// endpoint actually serves. A 503 from an upstream that is merely
  /// unavailable and a 402 for a payment that is only too young both heal by
  /// themselves, so both retry with the same payment; everything else is final
  /// and the payment stays cached for the next attempt at the same request.
  ///
  /// `body` is sent verbatim when it is already bytes, which is what a signed
  /// receipt over the request needs: nothing between the caller and the workload
  /// re-serializes it. Pass `seal` instead for a request that has to be built
  /// fresh per attempt, such as an end-to-end encrypted one whose timestamp the
  /// service only accepts inside a five-minute window, and pass `fingerprint`
  /// so the cache still recognises two attempts as the same request.
  async payAndPost({
    base,
    path,
    price,
    payTo,
    body = null,
    headers = {},
    seal = null,
    fingerprint = null,
    retryDelayMs = PAID_CALL_RETRY_MS,
    caller = "call",
  }) {
    let sent = seal ? seal() : { bytes: asBytes(body), headers };
    const identity = createHash("sha256").update(fingerprint ?? sent.bytes).digest("hex");
    const key = `${base}${path}:${price}:${identity}`;
    let pending = this.#pendingPayments.get(key);
    if (!pending) {
      const tx = await this.transferUsdg(payTo, price);
      const signature = await this.account.signMessage({ message: tx });
      pending = { tx, header: Buffer.from(JSON.stringify({ txHash: tx, signature })).toString("base64") };
      this.#pendingPayments.set(key, pending);
    }
    // The transfer is on-chain and irreversible from here. The signed header is
    // the only thing that redeems it, and it lives in this process.
    const kept = {
      payment_tx: pending.tx,
      payment_header: pending.header,
      hint:
        `the payment (tx ${pending.tx}) settled on-chain and the endpoint did not serve. While this process lives, ` +
        `the next ${caller} for this same request redeems it without paying again. payment_header is what redeems ` +
        "it, so keep it to do that from anywhere else.",
    };
    const deadline = Date.now() + PAID_CALL_DEADLINE_MS;
    for (;;) {
      let res;
      let bytes;
      try {
        res = await fetch(`${base}${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-payment": pending.header, ...sent.headers },
          body: sent.bytes,
          signal: AbortSignal.timeout(PAID_CALL_TIMEOUT_MS),
        });
        bytes = Buffer.from(await res.arrayBuffer());
      } catch (err) {
        throw new PrismError(504, "endpoint_unreachable", { cause: err?.message ?? String(err), ...kept });
      }
      if (res.status === 200) {
        this.#pendingPayments.delete(key);
        // The endpoint replays a stored answer when it sees a payment it has
        // already consumed. That is an answer to an earlier call, so it is not
        // this one's, whatever the status line says.
        if (String(res.headers.get("x-prism-replayed") ?? "").toLowerCase() === "true") {
          throw new PrismError(409, "payment_replayed", {
            cause: `the endpoint replayed an earlier answer for tx ${pending.tx}`,
            hint: "this payment was already consumed by another call; pay again to have this request served",
          });
        }
        return { status: 200, headers: res.headers, bytes, tx: pending.tx, sent };
      }
      const answered = (() => {
        try {
          return JSON.parse(bytes.toString("utf8"));
        } catch {
          return null;
        }
      })();
      // A payment the endpoint has already consumed will never serve anything
      // again, so it stops being something to retry with.
      if (answered?.error === "payment_reused") this.#pendingPayments.delete(key);
      const retryAfter = Number(res.headers.get("retry-after") ?? 0);
      const retryable =
        (res.status === 503 && answered?.error === "upstream_unavailable" && !(retryAfter > 120)) ||
        (res.status === 402 && ["insufficient_confirmations", "tx_not_found"].includes(answered?.error));
      if (!retryable || Date.now() > deadline) {
        const said = [answered?.detail, answered?.retry].filter(Boolean).join("; ");
        throw new PrismError(res.status, answered?.error ?? "generation_failed", {
          cause: said || answered?.error || `status ${res.status}`,
          ...(this.#pendingPayments.has(key) ? kept : { payment_tx: pending.tx }),
        });
      }
      await sleep(retryDelayMs);
      if (seal) sent = seal();
    }
  }

  /// Buy one generation from the confidential tier: an OpenAI-shaped chat
  /// request served by a model running in a GPU TEE, answered with a signed
  /// receipt over the exact bytes of the exchange.
  ///
  /// With `e2ee` on (the default) the message contents are encrypted to a key
  /// the enclave's own attestation quote commits to, established here before
  /// anything is sent or paid, so the relay in between carries ciphertext. The
  /// returned handle keeps those bytes and `verify()` checks the whole chain
  /// against them.
  ///
  /// `expectedWorkload` is the code that enclave must be running, defaulting to
  /// the deployment this SDK ships pinned. Passing `null` skips that appraisal
  /// and leaves the prompt protected only by "some TDX enclave holds the key".
  async confidentialInfer({
    prompt = null,
    messages = null,
    model = null,
    maxUsdg = 0.25,
    maxTokens = DEFAULT_MAX_TOKENS,
    e2ee = true,
    expectedWorkload = EXPECTED_WORKLOAD,
    endpoint = DEFAULT_CONFIDENTIAL_BASE,
  } = {}) {
    const chat = messages ?? (typeof prompt === "string" && prompt.trim() !== "" ? [{ role: "user", content: prompt }] : null);
    if (!Array.isArray(chat) || chat.length === 0) {
      throw new PrismError(400, "prompt_required", { hint: "pass a prompt string or a messages array" });
    }
    if (!Number.isInteger(maxTokens) || maxTokens <= 0) throw new PrismError(400, "invalid_max_tokens");
    const base = String(endpoint).replace(/\/$/, "");
    const chosen = await this.#confidentialModel(base, model, maxTokens);

    // Everything that protects the prompt happens before it is sent: the key it
    // is encrypted to has to be one the hardware quote commits to and the code
    // behind that quote has to be the code this SDK pins, not whatever the
    // relay offered.
    const body = { model: chosen.model, messages: chat, max_tokens: maxTokens };
    const plaintext = Buffer.from(JSON.stringify(body), "utf8");
    let keysetDigest = null;
    let seal = null;
    if (e2ee) {
      const established = await this.#establishKeyset(base, expectedWorkload);
      keysetDigest = established.digest;
      // The service rejects a request whose timestamp is more than five minutes
      // old, and the retry budget is longer than that, so each attempt seals
      // its own envelope with a fresh nonce and clock.
      seal = () => encryptChatRequest(body, established.keyset);
    }

    // Encryption roughly doubles the body, and the relay refuses an oversized
    // one after the payment has been made, so one envelope is built here purely
    // to measure and the attempts seal their own.
    const sized = seal ? seal().bytes : plaintext;
    if (Number.isInteger(chosen.card.max_body_bytes) && sized.length > chosen.card.max_body_bytes) {
      throw new PrismError(413, "request_too_large", {
        required: String(sized.length),
        max: String(chosen.card.max_body_bytes),
      });
    }

    const quote = await this.#confidentialQuote(base, chosen, maxTokens);
    const cap = BigInt(Math.round(maxUsdg * 1e6));
    if (quote.price <= 0n || quote.price > cap) {
      throw new PrismError(402, "cost_exceeds_max", { required: quote.price.toString(), max: cap.toString() });
    }

    const served = await this.payAndPost({
      base,
      path: "/v1/chat/completions",
      price: quote.price,
      payTo: quote.payTo,
      ...(seal ? { seal, fingerprint: plaintext } : { body: plaintext }),
      caller: "confidentialInfer",
    });
    const receiptId = served.headers.get("x-receipt-id");
    const sent = served.sent;
    const answer = seal
      ? decryptAnswer(served.bytes, sent.clientKey, served.headers, receiptId)
      : JSON.parse(served.bytes.toString("utf8"));

    // The workload keeps receipts in memory only, so this one is fetched now
    // and kept, whether or not the caller ever verifies it.
    const receipt = receiptId ? await this.#confidentialReceipt(base, receiptId) : null;

    return {
      model: chosen.model,
      content: answer?.choices?.[0]?.message?.content ?? null,
      usage: answer?.usage ?? null,
      receiptId,
      receipt,
      keysetDigest,
      e2ee: Boolean(seal),
      priceMicros: quote.price.toString(),
      priceUsdg: (Number(quote.price) / 1e6).toFixed(6),
      tx: served.tx,
      bytes: {
        request: sent.bytes,
        response: served.bytes,
        ...(seal ? { restoredRequest: sent.restored } : {}),
      },
      verify: (options = {}) =>
        verifyConfidential({
          base,
          model: chosen.model,
          receiptId,
          receipt,
          requestBytes: sent.bytes,
          responseBytes: served.bytes,
          restoredRequestBytes: seal ? sent.restored : null,
          e2ee: Boolean(seal),
          expectedWorkload,
          expectedKeysetDigest: keysetDigest,
          ...options,
        }),
    };
  }

  /// The confidential half of the endpoint's rate card, and the model this call
  /// should use. The card also states the caps the endpoint enforces, so a
  /// request it would refuse is refused here instead, before it is paid for.
  async #confidentialModel(base, requested, maxTokens) {
    const offer = await this.#publicJson(`${base}/v1/models`, "inference_endpoint_unavailable");
    const card = offer.confidential;
    const models = Object.keys(card?.models ?? {});
    if (models.length === 0) {
      throw new PrismError(503, "no_confidential_model", { hint: `${base} offers no confidential model right now` });
    }
    const model = requested ?? models[0];
    if (!models.includes(model)) {
      throw new PrismError(400, "unknown_model", { hint: `confidential models: ${models.join(", ")}` });
    }
    if (Number.isInteger(card.max_tokens) && maxTokens > card.max_tokens) {
      throw new PrismError(400, "invalid_max_tokens", { hint: `the endpoint caps max_tokens at ${card.max_tokens}` });
    }
    return { model, card, payTo: offer.pay_to ?? null };
  }

  /// The keyset the enclave's quote commits to, and the code behind that quote.
  /// Only the checks that protect the prompt run here, which is every check that
  /// says who can read it: the quote verifies to Intel's root and commits to
  /// this key set and this nonce, the boot log replays to the measurement that
  /// quote states, and the measured compose runs the pinned launcher and source.
  /// The rest of the transcript, receipt included, runs after the answer comes
  /// back. Anything short of all of that refuses to hand over a prompt.
  async #establishKeyset(base, expectedWorkload = EXPECTED_WORKLOAD) {
    const nonce = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32))).toString("hex");
    const report = await this.#publicJson(`${base}/v1/attestation?nonce=${nonce}`, "attestation_unavailable");
    const binding = await verifyReportBinding(report, nonce);
    if (!binding.ok) {
      const bad = binding.checks.find((c) => !c.ok);
      throw new PrismError(502, "attestation_unverified", { cause: bad?.detail ?? bad?.name });
    }
    // Which code the report describes is appraised before its quote is, so a
    // report naming the wrong workload is refused whatever hardware signed it.
    let measurement;
    try {
      measurement = await verifyComposeMeasurement(report);
    } catch (err) {
      throw new PrismError(502, "attestation_unverified", {
        cause: `the report's boot evidence could not be read: ${err?.message ?? err}`,
      });
    }
    const composeHash = measurement.checks.find((c) => c.name === "compose_hash");
    if (!composeHash.ok) throw new PrismError(502, "attestation_unverified", { cause: composeHash.detail });
    const identity = await appraiseWorkload(report, measurement, expectedWorkload);
    if (!identity.ok) {
      throw new PrismError(502, "attestation_unverified", {
        cause: identity.detail,
        hint: "the enclave quoting this key set is not running the code this SDK pins, so no prompt was sent to it",
      });
    }

    const quote = await verifyQuote(report);
    if (!quote.ok) throw new PrismError(502, "quote_unverified", { cause: quote.detail });
    if (quote.status !== "UpToDate") {
      throw new PrismError(502, "quote_unverified", { cause: `the platform TCB is ${quote.status}` });
    }
    // What makes the measurement above authentic: the log replays to the RTMR3
    // the verified quote itself states.
    if (toHex(quote.report.rtMr3) !== toHex(measurement.rtmr3)) {
      throw new PrismError(502, "attestation_unverified", {
        cause: "the boot event log does not replay to the RTMR3 the verified quote states",
      });
    }
    return { digest: binding.workloadKeysetDigest, keyset: binding.keyset, provenance: identity.provenance ?? null };
  }

  /// The endpoint prices each request itself, so the figure comes from an
  /// unpaid request rather than from arithmetic on the rate card.
  async #confidentialQuote(base, chosen, maxTokens) {
    let res;
    try {
      res = await fetch(`${base}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ model: chosen.model, max_tokens: maxTokens }),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch (err) {
      throw new PrismError(504, "inference_endpoint_unavailable", { cause: err?.message ?? String(err) });
    }
    if (res.status !== 402) {
      throw new PrismError(res.status, "no_quote", { hint: "the endpoint did not answer an unpaid request with a price" });
    }
    const body = await res.json().catch(() => null);
    const accepted = (body?.accepts ?? []).find((a) => a.network === "eip155:4663" || a.network === "robinhood");
    const micros = body?.quote?.price_micros ?? accepted?.amount ?? accepted?.maxAmountRequired;
    const payTo = accepted?.payTo ?? chosen.payTo;
    if (micros == null || !payTo) throw new PrismError(502, "no_quote", { cause: "the 402 named no USDG price to pay" });
    return { price: BigInt(micros), payTo };
  }

  async #confidentialReceipt(base, receiptId) {
    try {
      return await this.#publicJson(`${base}/v1/receipts/${encodeURIComponent(receiptId)}`, "receipt_unavailable");
    } catch {
      // The generation is paid for and delivered; a receipt that cannot be
      // fetched right now is a verification the caller loses, not a failure of
      // the call. verify() says so plainly when it runs.
      return null;
    }
  }

  async #publicJson(url, code) {
    let res;
    try {
      res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    } catch (err) {
      throw new PrismError(504, code, { cause: err?.message ?? String(err) });
    }
    if (!res.ok) throw new PrismError(res.status, code, { cause: `${url} answered ${res.status}` });
    const body = await res.json().catch(() => null);
    if (body === null) throw new PrismError(502, code, { cause: `${url} answered with something that is not JSON` });
    return body;
  }

  // A wallet has one nonce, so two transactions prepared at the same moment are
  // handed the same one and the chain refuses the second. Everything that
  // submits from this wallet queues here, which is what lets one wallet fund
  // several leases at once: they provision in parallel, they just do not sign
  // at the same instant.
  #submitting = Promise.resolve();

  #submit(send) {
    const done = this.#submitting.then(send, send);
    this.#submitting = done.then(
      () => {},
      () => {},
    );
    return done;
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
