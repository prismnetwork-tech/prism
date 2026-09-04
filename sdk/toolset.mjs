// A framework-neutral tool surface over PrismAgent. Agent frameworks disagree
// about how a tool is declared but agree about what one is: a named function
// with typed arguments that returns text. PrismToolset holds the wallet, the
// open leases, and the per-lease spending cap in one place so framework
// plugins stay thin wrappers instead of diverging copies of the same logic.
//
// Every method resolves to a string, including on failure. These tools are
// driven by language models, and a model can act on "the wallet holds 0 USDG"
// where a stack trace ends the conversation. Without a wallet the read-only
// questions still answer from the public API, the same degradation the MCP
// server offers.
import { rmSync } from "node:fs";
import { DEFAULT_IMAGE, MAX_COMMAND_BYTES, PrismAgent, PrismError, TRUST_CLASSES } from "./prism.mjs";

export const DEFAULT_ESCROW = "0xfD4228eEEfC49e4b76A0CD40af9fdd546220B2FD";
export const PUBLIC_API = "https://api.prismnetwork.tech";

export const NO_WALLET =
  "No wallet is configured, so this needs PRISM_AGENT_KEY (a funded wallet on Robinhood Chain). " +
  "Looking at capacity and prices works without one.";

const MICROS = 1_000_000;
const TRUST_MESSAGE = `min_trust_class must be one of ${TRUST_CLASSES.join(", ")}.`;
const COMMAND_MESSAGE = "command is required: the shell command to run on the GPU, e.g. 'nvidia-smi'.";
const usdg = (micros) => `${(Number(micros) / MICROS).toFixed(6)} USDG`;

// True for any string the toolset returns to describe a refusal or failure.
// Framework plugins map these to their own failed-action shape instead of
// keeping divergent copies of the wording.
export function isRefusal(body) {
  return (
    body === NO_WALLET ||
    body === TRUST_MESSAGE ||
    body === COMMAND_MESSAGE ||
    body.startsWith("No active lease") ||
    body.startsWith("The lease did not go through") ||
    body.startsWith("The balance check failed") ||
    body.startsWith("The command could not run") ||
    body.startsWith("Prism capacity") ||
    body.startsWith("command exceeds the") ||
    body.startsWith("lease_id must be") ||
    /^Lease \d+ is funded .* but the command could not run/.test(body)
  );
}

// `get` lets hosts with their own settings store (elizaOS runtimes, test
// harnesses) resolve the variables without mutating process.env.
export function agentFromEnv(get = (name) => process.env[name]) {
  const privateKey = (get("PRISM_AGENT_KEY") ?? "").trim();
  if (!privateKey) return null;
  return new PrismAgent({
    privateKey,
    escrow: get("PRISM_ESCROW") || DEFAULT_ESCROW,
    apiBase: get("PRISM_API_BASE") || undefined,
    rpcUrl: get("PRISM_RPC_URL") || undefined,
  });
}

function describe(err) {
  if (err instanceof PrismError) {
    const body = err.body ?? {};
    if (err.code === "cost_exceeds_max") {
      return `the quote needs ${usdg(body.required ?? 0)} but the cap is ${usdg(body.max ?? 0)}; raise maxUsdg or shorten the lease`;
    }
    if (err.code === "wallet_unfunded") {
      return (
        `wallet ${body.address} holds ${usdg(body.usdg ?? 0)} and ${(Number(body.eth_wei ?? 0) / 1e18).toFixed(6)} ` +
        "ETH for gas; fund it on Robinhood Chain (id 4663) before leasing"
      );
    }
    const detail = body.cause ?? body.hint ?? body.message;
    return detail ? `${err.code} (${detail})` : err.code;
  }
  return err?.message ?? String(err);
}

export class PrismToolset {
  #agent;
  #leases = new Map();
  #publicApi;

  constructor({ agent, publicApi } = {}) {
    this.#agent = agent === undefined ? agentFromEnv() : agent;
    this.#publicApi = (publicApi ?? process.env.PRISM_PUBLIC_API ?? PUBLIC_API).replace(/\/$/, "");
    process.once("exit", () => {
      for (const lease of this.#leases.values()) {
        try {
          rmSync(lease.keyDir, { recursive: true, force: true });
        } catch {
          /* best effort */
        }
      }
    });
  }

  get agent() {
    return this.#agent;
  }

  #sweepExpired() {
    const now = Date.now();
    for (const [id, lease] of this.#leases) {
      const expiry = Date.parse(lease.access?.expires_at ?? "");
      if (Number.isFinite(expiry) && expiry < now) {
        this.#agent.endLease(lease);
        this.#leases.delete(id);
      }
    }
  }

  async wallet() {
    if (!this.#agent) return NO_WALLET;
    let b;
    try {
      b = await this.#agent.balances();
    } catch (err) {
      return `The balance check failed: ${describe(err)}`;
    }
    return `address: ${b.address}\nusdg: ${usdg(b.usdg)}\neth: ${(Number(b.eth) / 1e18).toFixed(6)} for gas`;
  }

  async listGpus(minTrustClass = "open") {
    if (!TRUST_CLASSES.includes(minTrustClass)) return TRUST_MESSAGE;
    let offers;
    try {
      if (this.#agent) {
        offers = await this.#agent.offers({ minTrust: minTrustClass });
      } else {
        const url = new URL("/v1/offers", this.#publicApi);
        url.searchParams.set("min_trust", minTrustClass);
        const res = await fetch(url, {
          headers: { accept: "application/json" },
          signal: AbortSignal.timeout(10_000),
        });
        if (!res.ok) return `Prism capacity is unreachable right now (${res.status}).`;
        offers = await res.json().catch(() => null);
      }
    } catch (err) {
      return `Prism capacity is unreachable right now: ${describe(err)}`;
    }
    if (!Array.isArray(offers)) {
      return "Prism capacity answered in an unexpected shape; try again shortly.";
    }
    if (!offers.length) {
      return `No GPUs at trust class '${minTrustClass}' or above are online right now.`;
    }
    return offers
      .map((o) => {
        const perHr = ((Number(o.rate_per_second) * 3600) / MICROS).toFixed(2);
        const row = `${o.gpu?.model ?? "GPU"} · ${o.gpu?.vram_mib ?? "?"} MiB · ${perHr} USDG/hr · ${o.trust_class ?? "open"}`;
        return o.staker_only ? `${row} · stakers only` : row;
      })
      .join("\n");
  }

  async leaseAndRun({
    command,
    durationSeconds = 600,
    minVramMib = 16000,
    image = DEFAULT_IMAGE,
    maxUsdg = 1,
    minTrustClass = "open",
  } = {}) {
    if (!this.#agent) return NO_WALLET;
    if (typeof command !== "string" || command.trim() === "") return COMMAND_MESSAGE;
    if (Buffer.byteLength(command, "utf8") > MAX_COMMAND_BYTES) {
      return `command exceeds the ${MAX_COMMAND_BYTES / 1024} KiB limit; fetch the payload on the box instead of inlining it.`;
    }
    if (!TRUST_CLASSES.includes(minTrustClass)) return TRUST_MESSAGE;
    this.#sweepExpired();
    let lease;
    try {
      lease = await this.#agent.lease({
        image,
        durationSeconds,
        minVramMib,
        maxDeposit: Math.round(maxUsdg * MICROS),
        minTrustClass,
      });
    } catch (err) {
      return `The lease did not go through: ${describe(err)}`;
    }
    this.#leases.set(lease.leaseId, lease);
    let res;
    try {
      res = await this.#agent.run(lease, command);
    } catch (err) {
      return (
        `Lease ${lease.leaseId} is funded (tx ${lease.fundingHash}) but the command could not run: ` +
        `${describe(err)}. The lease stays open; try run(${lease.leaseId}, ...) or release it with endLease.`
      );
    }
    const out = res.stdout || res.stderr || "";
    return `lease ${lease.leaseId} funded onchain (tx ${lease.fundingHash}), exit ${res.code}:\n${out}`;
  }

  async run(leaseId, command) {
    if (!this.#agent) return NO_WALLET;
    leaseId = Number(leaseId);
    if (!Number.isInteger(leaseId) || leaseId <= 0) return "lease_id must be a positive integer.";
    const lease = this.#leases.get(leaseId);
    if (!lease) return `No active lease ${leaseId} in this session.`;
    if (typeof command !== "string" || command.trim() === "") return COMMAND_MESSAGE;
    let res;
    try {
      res = await this.#agent.run(lease, command);
    } catch (err) {
      return `The command could not run on lease ${leaseId}: ${describe(err)}`;
    }
    return `exit ${res.code}:\n${res.stdout || res.stderr || ""}`;
  }

  async endLease(leaseId) {
    if (!this.#agent) return NO_WALLET;
    leaseId = Number(leaseId);
    if (!Number.isInteger(leaseId) || leaseId <= 0) return "lease_id must be a positive integer.";
    const lease = this.#leases.get(leaseId);
    if (!lease) return `No active lease ${leaseId} in this session.`;
    this.#leases.delete(leaseId);
    const out = await this.#agent.endLease(lease);
    if (out.release === "failed") {
      return `Lease ${leaseId} could not be released: ${out.error}. Its access key is gone but the meter may still be running; check receipts for the settled charge.`;
    }
    return `released lease ${leaseId}; billing stopped here and the unused deposit returns after settlement`;
  }
}
