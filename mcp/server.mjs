#!/usr/bin/env node
// Prism Network MCP server: lets an MCP client (Claude, agents) see and lease
// real GPUs. Looking is free and needs no configuration. Leasing spends money,
// so it needs a wallet: PRISM_AGENT_KEY, PRISM_ESCROW.
import { createHash } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import {
  DEFAULT_IMAGE,
  DEFAULT_TRUST_FLOOR,
  hostKeyPolicy,
  PrismAgent,
  TRUST_CLASSES,
  verifyConfidential,
} from "@prismnetwork/agent-sdk";
import { BudgetError, SpendLedger, callCeiling, readBudget, recordSpend, stripUnexpanded } from "./budget.mjs";

stripUnexpanded(process.env);

const IMAGE = process.env.PRISM_DEFAULT_IMAGE ?? DEFAULT_IMAGE;

const PUBLIC_API = process.env.PRISM_PUBLIC_API ?? "https://api.prismnetwork.tech";
// The live lease escrow. Overridable, but its absence must not silently
// disable the wallet the way a missing key does.
const DEFAULT_ESCROW = "0xfD4228eEEfC49e4b76A0CD40af9fdd546220B2FD";
// Matches the limit the SDK and the control plane enforce, so a command that
// cannot run is rejected before an escrow is funded.
const MAX_COMMAND_BYTES = 8 * 1024;

// Refusing to start without a wallet meant nobody could ask what a GPU costs
// without first producing a private key, which is a strange thing to demand of
// someone deciding whether to use you at all.
let agent = null;
let walletProblem = "PRISM_AGENT_KEY is not set";
if (process.env.PRISM_AGENT_KEY) {
  try {
    agent = new PrismAgent({
      privateKey: process.env.PRISM_AGENT_KEY,
      escrow: process.env.PRISM_ESCROW ?? DEFAULT_ESCROW,
      apiBase: process.env.PRISM_API_BASE ?? "https://prismnetwork.tech",
      rpcUrl: process.env.PRISM_RPC_URL,
    });
    walletProblem = null;
  } catch (err) {
    walletProblem = `PRISM_AGENT_KEY is set but unusable: ${err?.message ?? err}`;
  }
}
if (!agent) {
  console.error(
    `prism mcp: no wallet configured (${walletProblem}), so capacity and pricing are readable and leasing is not.`,
  );
}

// A budget the operator got wrong must stop spending, not fall back to none.
// Reading capacity and prices is unaffected, so a typo is discoverable rather
// than fatal.
let ledger = null;
let budgetProblem = null;
try {
  ledger = new SpendLedger(readBudget());
} catch (err) {
  budgetProblem = err?.message ?? String(err);
  console.error(`prism mcp: ${budgetProblem}`);
}

function requireWallet(tool, reason = "spends money") {
  if (!agent) {
    throw new Error(
      `${tool} ${reason} and needs a wallet. None is configured: ${walletProblem}. Fix the environment and restart the server.`,
    );
  }
  return agent;
}

function requireLedger(tool) {
  if (!ledger) {
    throw new Error(`${tool} needs the spend limits, and they are unusable: ${budgetProblem}`);
  }
  return ledger;
}

// The ledger has to be usable before anything is spent, and the refusal names
// the tool that asked.
const spending = (tool, micros, run) => recordSpend(requireLedger(tool), tool, micros, run);

function requireCommand(value) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error("command is required: the shell command to run on the GPU, e.g. 'nvidia-smi'.");
  }
  if (Buffer.byteLength(value, "utf8") > MAX_COMMAND_BYTES) {
    throw new Error(`command exceeds the ${MAX_COMMAND_BYTES / 1024} KiB limit.`);
  }
  return value;
}

// What the caller can check the machine against if they open their own session.
// A lease that publishes nothing says so, rather than leaving the field out and
// letting its absence read as "fine".
function hostKey(access) {
  const policy = hostKeyPolicy(access);
  return policy.fingerprint === null
    ? { host_key: "unpublished: this lease cannot tell you which machine answers" }
    : { host_key_fingerprint: policy.fingerprint, host_key_claim: policy.mode };
}

// What the escrow actually holds, which is what the day's budget should count.
// Booking the caller's ceiling instead charged a 0.2 USDG lease against a 0.5
// USDG cap, so a 5 USDG day bought ten leases where it could afford twenty-five.
function escrowed(quote) {
  const held = Number(quote?.maximum_escrow);
  return Number.isFinite(held) && held > 0 ? held : undefined;
}

// The per-call ceiling is the operator's, not the model's: an omitted max_usdg
// takes PRISM_MAX_USDG rather than a hardcoded number, and a stated one above it
// is clamped back down to it.
function maxDeposit(tool, args) {
  return callCeiling(args.max_usdg, requireLedger(tool).maxPerCallMicros);
}

const PROOF_FEED = process.env.PRISM_PROOF_URL ?? "https://prismnetwork.tech/api/proof";

async function publicJson(url, what) {
  const response = await fetch(url, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`prism ${what} unavailable (${response.status})`);
  const body = await response.json().catch(() => null);
  if (body === null) throw new Error(`prism ${what} answered with something that is not JSON`);
  return body;
}

const leases = new Map();
// null in, null out: a missing price must never render as 0.000000 USDG.
const usdg = (micros) =>
  micros == null || !Number.isFinite(Number(micros)) ? null : `${(Number(micros) / 1e6).toFixed(6)} USDG`;

/// The SDK pays once and keeps the payment until the endpoint actually serves,
/// so a generation that never happened is retried with the payment already made.
async function payAndPost({ base, path, price, payTo, body, tool }) {
  const served = await agent.payAndPost({ base, path, price, payTo, body, caller: tool });
  return { ...JSON.parse(served.bytes.toString("utf8")), paid: usdg(price), payment_tx: served.tx };
}

// What the last few confidential calls sent and received, as digests only, so
// prism_verify_attestation binds its verdict to the real bytes of a call
// without keeping anyone's prompt in memory.
const confidentialCalls = new Map();
const CONFIDENTIAL_HISTORY = 16;

const sha256Prefixed = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

function rememberConfidentialCall(receiptId, record) {
  if (!receiptId) return;
  confidentialCalls.set(receiptId, record);
  while (confidentialCalls.size > CONFIDENTIAL_HISTORY) {
    confidentialCalls.delete(confidentialCalls.keys().next().value);
  }
}

const inferenceBase = () =>
  (process.env.PRISM_INFERENCE_URL ?? "https://api.prismnetwork.tech/inference").replace(/\/$/, "");

/// What the endpoint currently offers, and the model this call should use.
async function inferenceOffer(base, requested) {
  const offer = await publicJson(`${base}/v1/models`, "inference endpoint");
  const model = requested ?? offer.models?.[0];
  if (!model || (Array.isArray(offer.models) && !offer.models.includes(model))) {
    throw new Error(`model must be one of ${offer.models?.join(", ") ?? "(endpoint offered none)"}`);
  }
  return { offer, model, unit: BigInt(offer.price_micros ?? 0) };
}

// The quoted price against the lower of what this call asked for and what the
// operator allows, so the refusal names whichever ceiling stopped it.
function withinCap(tool, price, maxUsdg, fallback, what) {
  const operator = requireLedger(tool).maxPerCallMicros;
  const cap = callCeiling(maxUsdg ?? fallback, operator);
  if (price <= 0n || price > BigInt(cap)) {
    const named = cap === operator ? "PRISM_MAX_USDG" : "max_usdg";
    throw new Error(`the endpoint quotes ${usdg(price)} ${what}, past the ${named} cap of ${usdg(cap)}.`);
  }
}

function sweepExpiredLeases() {
  const now = Date.now();
  for (const [id, lease] of leases) {
    const expiry = Date.parse(lease.access?.expires_at ?? "");
    if (Number.isFinite(expiry) && expiry < now) {
      agent.endLease(lease);
      leases.delete(id);
    }
  }
}

function leaseId(value) {
  const id = Number(value);
  if (!Number.isInteger(id) || id <= 0) throw new Error("lease_id must be a positive integer");
  return id;
}

// Hints a client uses to decide what it may run unattended. `reads` is anything
// that cannot change state or move money; `spends` is anything that can, and it
// carries the Claude Code marker that forces a confirmation prompt on every call
// even in modes that otherwise auto-approve.
const reads = { readOnlyHint: true, openWorldHint: true };
const spends = {
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  _meta: { "anthropic/requiresUserInteraction": true },
};

const TOOLS = [
  {
    name: "prism_budget",
    description: "Show the spending limits this server enforces and what it has already spent in the last 24 hours, with the recent charges. Needs no wallet. Check this before a long job; a lease refused for budget says the same numbers.",
    inputSchema: { type: "object", properties: {} },
    annotations: { title: "Spending limits", readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "prism_wallet",
    description: "Show the agent's wallet address and on-chain balances (USDG and ETH for gas) on Robinhood Chain. Check this before leasing to confirm the wallet can pay.",
    inputSchema: { type: "object", properties: {} },
    annotations: { title: "Wallet balances", ...reads },
  },
  {
    name: "prism_list_gpus",
    description: "List GPUs currently available to lease on Prism Network, with model, VRAM, price per second in USDG, and trust class. Trust class runs open < isolated < attested < confidential; on an 'open' supplier the host operator can read anything the workload touches. Keep secrets and credentials in prism_vault_store rather than on the box, and raise min_trust when the workload itself must not be readable.",
    inputSchema: {
      type: "object",
      properties: {
        min_trust: {
          type: "string",
          enum: TRUST_CLASSES,
          description: "Only list suppliers at or above this trust class (default 'open').",
        },
      },
    },
    annotations: { title: "Available GPUs", ...reads },
  },
  {
    name: "prism_price_index",
    description: "Current GPU pricing on Prism Network by model: sourced low/median/high and settled mean, in USDG per hour. Needs no wallet. Use it to estimate what an analysis job will cost before leasing.",
    inputSchema: { type: "object", properties: {} },
    annotations: { title: "GPU price index", ...reads },
  },
  {
    name: "prism_receipts",
    description: "Recent settled lease receipts from the public proof feed: GPU model, runtime, what was charged and refunded, and the settlement transaction hash on Robinhood Chain. Needs no wallet. Every Prism lease ends in one of these.",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "integer", description: "Max receipts to return (default 10, max 50)." },
      },
    },
    annotations: { title: "Settled receipts", ...reads },
  },
  {
    name: "prism_leases",
    description: "List this wallet's leases on Prism Network with their current state.",
    inputSchema: { type: "object", properties: {} },
    annotations: { title: "Your leases", ...reads },
  },
  {
    name: "prism_batch_run",
    description: "Fund a lease that runs one command with no interactive access at all: the node executes it and reports the signed output. Matches only suppliers at trust class 'isolated' or above, so it can find no supplier when none is online; prefer prism_lease_and_run for broad availability. Output is capped at 64 KiB per stream.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", description: "Shell command to run (max 8 KiB)." },
        duration_seconds: { type: "integer", description: "Paid window in seconds (default 900, max 21600). A command still running at the end is killed and reported exit 124." },
        min_vram_mib: { type: "integer", description: "Minimum GPU memory in MiB (default 16000)." },
        max_usdg: { type: "number", description: "Cost ceiling for this lease in USDG. It lowers the operator's PRISM_MAX_USDG and cannot raise it; omitted, that ceiling applies. See prism_budget." },
      },
      required: ["command"],
    },
    ...spends,
    annotations: { title: "Rent a GPU for one command", ...spends.annotations },
  },
  {
    name: "prism_batch_result",
    description: "Read the output of a batch lease by lease_id, once its node has reported. Use it to recover a result after prism_batch_run timed out.",
    inputSchema: {
      type: "object",
      properties: {
        lease_id: { type: "integer", description: "The lease_id from prism_batch_run's output or error." },
      },
      required: ["lease_id"],
    },
    annotations: { title: "Batch result", ...reads },
  },
  {
    name: "prism_infer",
    description: "Buy one LLM generation from Prism's managed inference endpoint. Pays the quoted USDG price from this wallet (about 0.01 USDG), waits through a cold start when no box is warm (up to a few minutes), and returns the generation with token usage. Cheaper and simpler than leasing when all you need is a completion.",
    inputSchema: {
      type: "object",
      properties: {
        prompt: { type: "string", description: "The prompt to generate from (max 32 KiB)." },
        model: { type: "string", description: "Model to use; defaults to the endpoint's first offered model." },
        max_usdg: { type: "number", description: "Refuse if the quoted price exceeds this (default 0.05). The operator's PRISM_MAX_USDG binds it either way." },
      },
      required: ["prompt"],
    },
    ...spends,
    annotations: { title: "Buy one LLM generation", ...spends.annotations },
  },
  {
    name: "prism_infer_batch",
    description: "Buy many LLM generations from Prism's managed inference endpoint in one paid call. Every prompt runs whole on a rented GPU, spread across every GPU the endpoint holds, so a list of prompts finishes far sooner than the same prompts sent one at a time. Costs the single-generation price times the number of prompts. Returns every answer in order plus a Merkle receipt naming the leases that did the work. Use it for evals, dataset passes, rollouts, or anything with more than a handful of independent prompts.",
    inputSchema: {
      type: "object",
      properties: {
        prompts: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
          maxItems: 64,
          description: "Independent prompts, answered in the order given (each max 32 KiB).",
        },
        model: { type: "string", description: "Model to use; defaults to the endpoint's first offered model." },
        max_usdg: { type: "number", description: "Refuse if the quoted total exceeds this (default 0.5). The operator's PRISM_MAX_USDG binds it either way." },
      },
      required: ["prompts"],
    },
    ...spends,
    annotations: { title: "Buy many LLM generations", ...spends.annotations },
  },
  {
    name: "prism_confidential_infer",
    description: "Buy one LLM generation that runs inside a GPU TEE, with the message contents encrypted end to end to a key the enclave's own attestation commits to, so Prism's relay in between carries ciphertext and cannot read the prompt or the answer. Costs a little more than prism_infer. Returns the answer, the cost, and a receipt id the workload signed over the exact bytes of the exchange; pass that id to prism_verify_attestation to check the whole chain. Use it for anything the operator of an ordinary endpoint should not be able to read.",
    inputSchema: {
      type: "object",
      properties: {
        prompt: { type: "string", description: "The prompt to generate from." },
        model: { type: "string", description: "Confidential model to use; defaults to the endpoint's first." },
        max_tokens: { type: "integer", description: "Cap on generated tokens (default 512). The price is quoted against this cap." },
        max_usdg: { type: "number", description: "Refuse if the quoted price exceeds this (default 0.25). The operator's PRISM_MAX_USDG binds it either way." },
        e2ee: { type: "boolean", description: "Encrypt message contents to the attested enclave key (default true). Turn it off only when the relay is allowed to read the prompt." },
      },
      required: ["prompt"],
    },
    ...spends,
    annotations: { title: "Buy one confidential LLM generation", ...spends.annotations },
  },
  {
    name: "prism_verify_attestation",
    description: "Check a confidential generation against its signed receipt and the hardware behind it: the TDX quote verifies to Intel's root and commits to the key set that signed the receipt, the boot log replays to the measurement in that quote, the receipt covers the exact bytes of this call, the upstream that ran the model was itself verified, and the GPU is attested by NVIDIA. Returns every check with its result, including the ones that cannot be established today. Needs no wallet.",
    inputSchema: {
      type: "object",
      properties: {
        receipt_id: { type: "string", description: "The receipt_id from prism_confidential_infer." },
        model: { type: "string", description: "Model to fetch GPU evidence for; defaults to the one recorded for this receipt." },
      },
      required: ["receipt_id"],
    },
    annotations: { title: "Check a confidential generation", ...reads },
  },
  {
    name: "prism_lease_and_run",
    description: "Lease a GPU, run one shell command on it, and return the output. The lease stays alive (use prism_run for more commands, prism_end_lease to release). Prefer this for a single command; use prism_lease when you'll run several.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", description: "Shell command to run on the GPU (e.g. 'nvidia-smi')." },
        duration_seconds: { type: "integer", description: "Lease length in seconds (default 900, max 21600)." },
        min_vram_mib: { type: "integer", description: "Minimum GPU memory in MiB (default 16000)." },
        min_trust_class: {
          type: "string",
          enum: TRUST_CLASSES,
          description: "Refuse suppliers below this trust class (default 'open'). Raise it for anything the host operator must not read.",
        },
        max_usdg: { type: "number", description: "Cost ceiling for this lease in USDG. It lowers the operator's PRISM_MAX_USDG and cannot raise it; omitted, that ceiling applies. See prism_budget." },
      },
      required: ["command"],
    },
    ...spends,
    annotations: { title: "Rent a GPU and run a command", ...spends.annotations },
  },
  {
    name: "prism_lease",
    description: "Lease a GPU and keep it running. Returns a lease_id and SSH access. Use prism_run to execute commands and prism_end_lease when done.",
    inputSchema: {
      type: "object",
      properties: {
        duration_seconds: { type: "integer", description: "Lease length in seconds (default 900, max 21600)." },
        min_vram_mib: { type: "integer", description: "Minimum GPU memory in MiB (default 16000)." },
        min_trust_class: {
          type: "string",
          enum: TRUST_CLASSES,
          description: "Refuse suppliers below this trust class (default 'open'). Raise it for anything the host operator must not read.",
        },
        max_usdg: { type: "number", description: "Cost ceiling for this lease in USDG. It lowers the operator's PRISM_MAX_USDG and cannot raise it; omitted, that ceiling applies. See prism_budget." },
      },
    },
    ...spends,
    annotations: { title: "Rent a GPU", ...spends.annotations },
  },
  {
    name: "prism_run",
    description: "Run a shell command on a GPU you already leased with prism_lease.",
    inputSchema: {
      type: "object",
      properties: {
        lease_id: { type: "integer", description: "The lease_id returned by prism_lease." },
        command: { type: "string", description: "Shell command to run." },
        timeout_seconds: { type: "integer", description: "Max seconds to wait (default 120)." },
      },
      required: ["lease_id", "command"],
    },
    annotations: { title: "Run a command on a lease", readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  },
  {
    name: "prism_end_lease",
    description: "Release a lease. Access closes and billing stops here: settlement charges the seconds the lease was open and returns the rest of the deposit. A lease nobody releases bills until its window ends.",
    inputSchema: {
      type: "object",
      properties: { lease_id: { type: "integer" } },
      required: ["lease_id"],
    },
    annotations: { title: "Release a lease", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: "prism_vault_store",
    description: "Store private data (a card, an identity document, an API credential) encrypted under a key derived from this agent's wallet on this machine. Prism receives ciphertext only and cannot read it. Use this instead of writing a secret into a workspace or a file. Returns an item_id; the value is not recoverable without the wallet.",
    inputSchema: {
      type: "object",
      properties: {
        value: { type: "string", description: "The data to seal. Encrypted before it leaves this process." },
        label: { type: "string", description: "Optional plain-text name so the item is findable. Stored unencrypted, so keep it non-revealing (e.g. 'billing card', not the number)." },
        trust_floor: {
          type: "string",
          enum: TRUST_CLASSES,
          description: "The weakest workspace this item may ever be released into. Defaults to 'confidential', which is above anything the network serves today, so the item cannot reach a rented GPU at all. Only lower it deliberately.",
        },
      },
      required: ["value"],
    },
    annotations: { title: "Seal a secret", readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  },
  {
    name: "prism_vault_list",
    description: "List the agent's sealed vault items: item_id, label, version and trust floor. Values are not returned and are not readable by Prism.",
    inputSchema: { type: "object", properties: {} },
    annotations: { title: "List sealed items", ...reads },
  },
  {
    name: "prism_vault_read",
    description: "Decrypt and return one vault item, in this process, using the wallet-derived key. The plaintext exists only here; do not echo it into a leased workspace, a log, or a message.",
    inputSchema: {
      type: "object",
      properties: { item_id: { type: "string", description: "The item_id from prism_vault_store or prism_vault_list." } },
      required: ["item_id"],
    },
    _meta: { "anthropic/requiresUserInteraction": true },
    annotations: { title: "Decrypt one sealed item", readOnlyHint: true, openWorldHint: true },
  },
  {
    name: "prism_vault_delete",
    description: "Permanently delete a vault item. The ciphertext is removed and the value cannot be recovered.",
    inputSchema: {
      type: "object",
      properties: { item_id: { type: "string" } },
      required: ["item_id"],
    },
    ...spends,
    annotations: { title: "Delete a sealed item", ...spends.annotations },
  },
  {
    name: "prism_vault_release",
    description: "Authorize a vault item into a lease you hold and return its plaintext for use there. Refused when the lease's trust class is below the item's trust floor, which is what stops a secret reaching a host that can read it. Every allowed release is recorded against the account.",
    inputSchema: {
      type: "object",
      properties: {
        item_id: { type: "string" },
        lease_id: { type: "integer", description: "A lease from prism_lease." },
      },
      required: ["item_id", "lease_id"],
    },
    ...spends,
    annotations: { title: "Release a secret into a lease", ...spends.annotations },
  },
];

async function handle(name, args) {
  if (name === "prism_budget") return requireLedger(name).status();
  if (name === "prism_wallet") {
    const b = await requireWallet("prism_wallet").balances();
    return { address: b.address, usdg: usdg(b.usdg), eth_wei: b.eth };
  }
  if (name === "prism_list_gpus") {
    const minTrust = args.min_trust ?? "open";
    if (!TRUST_CLASSES.includes(minTrust)) {
      throw new Error(`min_trust must be one of ${TRUST_CLASSES.join(", ")}`);
    }
    let offers;
    if (agent) {
      offers = await agent.offers({ minTrust });
    } else {
      const url = new URL("/v1/offers", PUBLIC_API);
      url.searchParams.set("min_trust", minTrust);
      offers = await publicJson(url, "offers");
    }
    return {
      available: offers.length,
      gpus: offers.map((o) => ({
        model: o.gpu.model,
        vram_mib: o.gpu.vram_mib,
        price_per_second: usdg(o.rate_per_second),
        price_per_hour: usdg(o.rate_per_second * 3600),
        trust: o.trust_class,
        // A staker-only offer will not match a wallet without the stake, so an
        // unstaked renter should budget from the non-staker rows.
        ...(o.staker_only ? { staker_only: true } : {}),
      })),
    };
  }
  if (name === "prism_price_index") {
    const index = await publicJson(new URL("/v1/price-index", PUBLIC_API), "price index");
    return {
      currency: index.currency,
      generated_at: index.generated_at,
      gpus: (index.gpus ?? []).map((g) => ({
        model: g.gpu_model,
        sourced_low_per_hour: usdg(g.sourced_low_micros_per_hour),
        sourced_median_per_hour: usdg(g.sourced_median_micros_per_hour),
        sourced_high_per_hour: usdg(g.sourced_high_micros_per_hour),
        settled_mean_per_hour: usdg(g.settled_mean_micros_per_hour),
        settled_leases: g.settled_leases,
      })),
    };
  }
  if (name === "prism_receipts") {
    const feed = await publicJson(PROOF_FEED, "proof feed");
    if (args.limit !== undefined && (!Number.isInteger(args.limit) || args.limit <= 0)) {
      throw new Error("limit must be a positive integer (max 50)");
    }
    const limit = Math.min(args.limit ?? 10, 50);
    return {
      generated_at: feed.generated_at,
      receipts: (feed.receipts ?? []).slice(0, limit).map((r) => ({
        // The feed numbers leases per escrow deployment, so lease_id repeats
        // across deployments; receipt_id is the unique handle.
        receipt_id: r.receipt_id,
        lease_id: r.lease_id,
        outcome: r.outcome,
        gpu_model: r.gpu_model,
        trust: r.trust_class ?? null,
        runtime_seconds: r.runtime_seconds,
        charged: usdg(r.charged_base_units),
        refunded: usdg(r.refunded_base_units),
        settlement_tx: r.transaction_hash,
      })),
    };
  }
  if (name === "prism_leases") {
    requireWallet(name);
    const all = await agent.leases();
    return {
      total: all.length,
      showing: Math.min(all.length, 20),
      leases: all.slice(0, 20).map((l) => ({
        lease_id: l.lease_id,
        state: l.state,
        image: l.image,
        duration_seconds: l.duration_seconds,
        max_escrow: usdg(l.maximum_escrow),
        trust: l.trust_class,
        funding_tx: l.funding_transaction_hash,
        created_at: l.created_at,
      })),
    };
  }
  if (name === "prism_batch_run") {
    requireCommand(args.command);
    requireWallet(name);
    const cap = maxDeposit(name, args);
    return spending(name, cap, async () => {
      const batch = await agent.lease({
        image: IMAGE,
        durationSeconds: args.duration_seconds ?? 900,
        minVramMib: args.min_vram_mib ?? 16000,
        maxDeposit: cap,
        command: args.command,
      });
      return {
        reference: batch.fundingHash,
        settledMicros: escrowed(batch.quote),
        value: {
          lease_id: batch.leaseId,
          funding_tx: batch.fundingHash,
          exit_code: batch.result?.exit_code,
          stdout: batch.result?.stdout,
          stderr: batch.result?.stderr,
          truncated: batch.result?.truncated ?? false,
        },
      };
    });
  }
  if (name === "prism_batch_result") {
    requireWallet(name, "reads this wallet's leases");
    const id = leaseId(args.lease_id);
    return { lease_id: id, result: await agent.result(id) };
  }
  if (name === "prism_infer") {
    if (typeof args.prompt !== "string" || args.prompt.trim() === "") {
      throw new Error("prompt is required.");
    }
    requireWallet(name);
    const base = inferenceBase();
    const { offer, model, unit } = await inferenceOffer(base, args.model);
    withinCap(name, unit, args.max_usdg, 0.05, "per generation");
    return spending(name, Number(unit), async () => {
      const value = await payAndPost({
        base,
        path: "/v1/inference",
        price: unit,
        payTo: offer.pay_to,
        body: { model, prompt: args.prompt },
        tool: "prism_infer",
      });
      return { value, settledMicros: Number(unit), reference: value.payment_tx };
    });
  }
  if (name === "prism_infer_batch") {
    const prompts = args.prompts;
    if (!Array.isArray(prompts) || !prompts.length) {
      throw new Error("prompts must be a non-empty array of strings.");
    }
    if (prompts.some((p) => typeof p !== "string" || p.trim() === "")) {
      throw new Error("every prompt must be a non-empty string.");
    }
    if (prompts.length > 64) {
      throw new Error(`a batch takes at most 64 prompts; ${prompts.length} were given.`);
    }
    requireWallet(name);
    const base = inferenceBase();
    const { offer, model, unit } = await inferenceOffer(base, args.model);
    const price = unit * BigInt(prompts.length);
    withinCap(name, price, args.max_usdg, 0.5, `for ${prompts.length} generations`);
    return spending(name, Number(price), async () => {
      const value = await payAndPost({
        base,
        path: "/v1/batch",
        price,
        payTo: offer.pay_to,
        body: { model, prompts },
        tool: "prism_infer_batch",
      });
      return { value, settledMicros: Number(price), reference: value.payment_tx };
    });
  }
  if (name === "prism_confidential_infer") {
    if (typeof args.prompt !== "string" || args.prompt.trim() === "") {
      throw new Error("prompt is required.");
    }
    requireWallet(name);
    const base = inferenceBase();
    // The endpoint quotes inside the SDK, so the day is charged the ceiling up
    // front and corrected to the quoted price once the call has been served.
    const cap = callCeiling(args.max_usdg ?? 0.25, requireLedger(name).maxPerCallMicros);
    const run = await spending(name, cap, async () => {
      const served = await agent.confidentialInfer({
        prompt: args.prompt,
        model: args.model,
        maxTokens: args.max_tokens ?? 512,
        maxUsdg: cap / 1e6,
        e2ee: args.e2ee ?? true,
        endpoint: base,
      });
      return { value: served, settledMicros: Number(served.priceMicros), reference: served.tx };
    });
    rememberConfidentialCall(run.receiptId, {
      base,
      model: run.model,
      e2ee: run.e2ee,
      keysetDigest: run.keysetDigest,
      responseHash: sha256Prefixed(run.bytes.response),
      requestHash: sha256Prefixed(run.bytes.request),
      restoredRequestHash: run.bytes.restoredRequest ? sha256Prefixed(run.bytes.restoredRequest) : null,
    });
    return {
      model: run.model,
      content: run.content,
      usage: run.usage,
      receipt_id: run.receiptId,
      paid: usdg(run.priceMicros),
      payment_tx: run.tx,
      e2ee: run.e2ee
        ? "on: the prompt and the answer were encrypted to the enclave's attested key, and the relay carried ciphertext"
        : "off: the relay could read this prompt",
      next: `prism_verify_attestation with receipt_id ${run.receiptId} checks the hardware, the receipt and the GPU behind this answer`,
    };
  }
  if (name === "prism_verify_attestation") {
    if (typeof args.receipt_id !== "string" || args.receipt_id.trim() === "") {
      throw new Error("receipt_id is required: the id prism_confidential_infer returned.");
    }
    // Without the bytes of the call, a receipt still proves what the workload
    // signed, but not that it signed this exchange. That is `incomplete`, and it
    // is a different thing to tell an agent than a failure.
    const remembered = confidentialCalls.get(args.receipt_id) ?? {};
    const bound = remembered.responseHash != null;
    const result = await verifyConfidential({
      base: remembered.base ?? inferenceBase(),
      receiptId: args.receipt_id,
      model: args.model ?? remembered.model,
      e2ee: Boolean(remembered.e2ee),
      requestHash: remembered.requestHash ?? null,
      responseHash: remembered.responseHash ?? null,
      restoredRequestHash: remembered.restoredRequestHash ?? null,
      expectedKeysetDigest: remembered.keysetDigest ?? null,
    });
    const mark = { pass: "ok", fail: "FAIL", skip: "skip" };
    return {
      receipt_id: args.receipt_id,
      verdict: result.verdict,
      verdict_means: {
        verified: "every check that ran passed, and the only skips are the documented ones",
        incomplete: "nothing failed, and evidence some check needed was not available here",
        failed: "a check failed",
      }[result.verdict],
      bound_to_this_session: bound,
      ...(bound
        ? {}
        : { unbound_because: "this server has no record of that call, so the request and response checks could not run" }),
      measured_source: result.provenance,
      checks: result.checks.map((c) => `${mark[c.status]} ${c.title}${c.detail ? `: ${c.detail}` : ""}`),
    };
  }
  if (name === "prism_lease_and_run" || name === "prism_lease") {
    if (name === "prism_lease_and_run") requireCommand(args.command);
    requireWallet(name);
    const cap = maxDeposit(name, args);
    sweepExpiredLeases();
    const lease = await spending(name, cap, async () => {
      const funded = await agent.lease({
        image: IMAGE,
        durationSeconds: args.duration_seconds ?? 900,
        minVramMib: args.min_vram_mib ?? 16000,
        maxDeposit: cap,
        minTrustClass: args.min_trust_class ?? "open",
      });
      return { value: funded, reference: funded.fundingHash, settledMicros: escrowed(funded.quote) };
    });
    leases.set(lease.leaseId, lease);
    const summary = {
      lease_id: lease.leaseId,
      funding_tx: lease.fundingHash,
      // `prism_run` checks this itself. It is in the summary because the
      // caller is being handed an address they may connect to by hand, and an
      // address with no key to check is an invitation to accept whatever
      // answers.
      ssh: {
        host: lease.access.ssh_host,
        port: lease.access.ssh_port,
        user: lease.access.ssh_user,
        ...hostKey(lease.access),
      },
      trust: lease.quote?.trust_class ?? "open",
      expires_at: lease.access.expires_at,
    };
    if (name === "prism_lease") return summary;
    // The lease is paid for by this point; an SSH failure must still hand the
    // caller everything it bought.
    try {
      const out = await agent.run(lease, args.command);
      return { ...summary, command: args.command, exit_code: out.code, stdout: out.stdout, stderr: out.stderr };
    } catch (err) {
      return {
        ...summary,
        error: `the lease is funded but the command could not run: ${err?.message ?? err}`,
        next: `the lease stays open; try prism_run with lease_id ${lease.leaseId}, or prism_end_lease`,
      };
    }
  }
  if (name === "prism_run") {
    requireCommand(args.command);
    const id = leaseId(args.lease_id);
    const lease = leases.get(id);
    if (!lease) throw new Error(`no active lease ${id} in this session`);
    const timeoutSeconds = args.timeout_seconds ?? 120;
    const out = await agent.run(lease, args.command, {
      timeoutMs: timeoutSeconds * 1000,
      connectRetries: 6,
    });
    return { lease_id: id, exit_code: out.code, stdout: out.stdout, stderr: out.stderr };
  }
  if (name === "prism_end_lease") {
    const id = leaseId(args.lease_id);
    const lease = leases.get(id);
    if (!lease) return { lease_id: id, released: false, next: "no lease with this id is open in this session; prism_leases lists the wallet's leases" };
    leases.delete(id);
    const out = await agent.endLease(lease);
    if (out.release === "failed") {
      return { lease_id: id, released: false, error: out.error, next: "the access key is gone but the meter may still be running; check prism_receipts for the settled charge" };
    }
    return { lease_id: id, released: true, release: out.release, next: "billing stopped here; the unused deposit returns after settlement and prism_receipts shows the charge" };
  }
  if (name.startsWith("prism_vault_")) return handleVault(name, args);
  throw new Error(`unknown tool ${name}. Valid tools: ${TOOLS.map((t) => t.name).join(", ")}`);
}

// The vault key is derived here from the wallet signature and stays in this
// process. Nothing in this function sends a key or a plaintext to Prism.
async function handleVault(name, args) {
  const vault = requireWallet(name, "derives the vault key from the wallet").vault;
  if (!vault.unlocked) await vault.unlock();

  if (name === "prism_vault_store") {
    if (typeof args.value !== "string" || args.value.length === 0) {
      throw new Error("value is required");
    }
    const item = await vault.put(args.value, {
      label: args.label ?? "",
      trustFloor: args.trust_floor ?? DEFAULT_TRUST_FLOOR,
    });
    return {
      item_id: item.item_id,
      version: item.version,
      label: item.label,
      trust_floor: item.min_trust_class,
      stored: "sealed on this machine; Prism holds ciphertext only",
    };
  }
  if (name === "prism_vault_list") {
    const items = await vault.list();
    return {
      count: items.length,
      items: items.map((item) => ({
        item_id: item.item_id,
        label: item.label,
        version: item.version,
        trust_floor: item.min_trust_class,
        updated_at: item.updated_at,
      })),
    };
  }
  if (name === "prism_vault_read") {
    return { item_id: args.item_id, value: await vault.get(args.item_id) };
  }
  if (name === "prism_vault_delete") {
    await vault.remove(args.item_id);
    return { item_id: args.item_id, deleted: true };
  }
  if (name === "prism_vault_release") {
    const id = leaseId(args.lease_id);
    return { item_id: args.item_id, lease_id: id, value: await vault.releaseInto(id, args.item_id) };
  }
  throw new Error(`unknown tool ${name}`);
}

const server = new Server({ name: "prism", version: "0.9.0" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    const result = await handle(request.params.name, request.params.arguments ?? {});
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    if (err instanceof BudgetError) {
      return { isError: true, content: [{ type: "text", text: `${err.message} See prism_budget.` }] };
    }
    const body = err?.body ?? {};
    const detail = [
      body.cause,
      body.hint,
      body.required != null ? `required ${body.required}` : null,
      body.max != null ? `cap ${body.max}` : null,
      body.lease_id != null ? `lease_id ${body.lease_id}` : null,
      body.funding_hash ? `funding_tx ${body.funding_hash}` : null,
    ]
      .filter(Boolean)
      .join("; ");
    const text = `error: ${err?.message ?? err}${detail ? ` (${detail})` : ""}`;
    return { isError: true, content: [{ type: "text", text }] };
  }
});

await server.connect(new StdioServerTransport());
console.error("prism mcp server ready");
