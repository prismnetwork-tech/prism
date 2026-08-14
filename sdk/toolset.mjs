// A framework-neutral tool surface over PrismAgent. Agent frameworks disagree
// about how a tool is declared but agree about what one is: a named function
// with typed arguments that returns text. PrismToolset holds the wallet, the
// open leases, and the spending cap in one place so framework plugins stay
// thin wrappers instead of diverging copies of the same logic.
//
// Without a wallet it still answers the read-only questions (capacity, prices)
// from the public API, the same degradation the MCP server offers.
import { DEFAULT_IMAGE, PrismAgent, TRUST_CLASSES } from "./prism.mjs";

export const DEFAULT_ESCROW = "0x62C042265991bEa17B07229322A01850974626dA";
export const PUBLIC_API = "https://api.prismnetwork.tech";

const MICROS = 1_000_000;
const usdg = (micros) => `${(Number(micros) / MICROS).toFixed(6)} USDG`;

export function agentFromEnv() {
  const privateKey = process.env.PRISM_AGENT_KEY;
  if (!privateKey) return null;
  return new PrismAgent({ privateKey, escrow: process.env.PRISM_ESCROW ?? DEFAULT_ESCROW });
}

const NO_WALLET =
  "No wallet is configured, so this needs PRISM_AGENT_KEY (a funded wallet on Robinhood Chain). " +
  "Looking at capacity and prices works without one.";

export class PrismToolset {
  #agent;
  #leases = new Map();
  #publicApi;

  constructor({ agent, publicApi = PUBLIC_API } = {}) {
    this.#agent = agent === undefined ? agentFromEnv() : agent;
    this.#publicApi = publicApi;
  }

  get agent() {
    return this.#agent;
  }

  async wallet() {
    if (!this.#agent) return NO_WALLET;
    const b = await this.#agent.balances();
    return `address: ${b.address}\nusdg: ${usdg(b.usdg)}\neth: ${(Number(b.eth) / 1e18).toFixed(6)} for gas`;
  }

  async listGpus(minTrust = "open") {
    if (!TRUST_CLASSES.includes(minTrust)) {
      return `min_trust must be one of ${TRUST_CLASSES.join(", ")}`;
    }
    let offers;
    if (this.#agent) {
      offers = await this.#agent.offers({ minTrust });
    } else {
      const url = new URL("/v1/offers", this.#publicApi);
      url.searchParams.set("min_trust", minTrust);
      const res = await fetch(url, { headers: { accept: "application/json" } });
      if (!res.ok) return `Prism capacity is unreachable right now (${res.status}).`;
      offers = await res.json();
    }
    if (!offers.length) return "No GPUs are online to rent right now.";
    return offers
      .map((o) => {
        const perHr = ((Number(o.rate_per_second) * 3600) / MICROS).toFixed(2);
        return `${o.gpu.model} · ${o.gpu.vram_mib} MiB · $${perHr}/hr · ${o.trust_class ?? "open"}`;
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
  }) {
    if (!this.#agent) return NO_WALLET;
    const lease = await this.#agent.lease({
      image,
      durationSeconds,
      minVramMib,
      maxDeposit: Math.round(maxUsdg * MICROS),
      minTrustClass,
    });
    this.#leases.set(lease.leaseId, lease);
    const res = await this.#agent.run(lease, command);
    const out = res.stdout || res.stderr || "";
    return `lease ${lease.leaseId} funded onchain (tx ${lease.fundingHash}), exit ${res.code}:\n${out}`;
  }

  async run(leaseId, command) {
    if (!this.#agent) return NO_WALLET;
    const lease = this.#leases.get(leaseId);
    if (!lease) return `No active lease ${leaseId} in this session.`;
    const res = await this.#agent.run(lease, command);
    return `exit ${res.code}:\n${res.stdout || res.stderr || ""}`;
  }

  endLease(leaseId) {
    if (!this.#agent) return NO_WALLET;
    const lease = this.#leases.get(leaseId);
    if (!lease) return `No active lease ${leaseId} in this session.`;
    this.#agent.endLease(lease);
    this.#leases.delete(leaseId);
    return `released lease ${leaseId}`;
  }
}
