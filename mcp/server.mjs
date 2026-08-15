#!/usr/bin/env node
// Prism Network MCP server: lets an MCP client (Claude, agents) see and lease
// real GPUs. Looking is free and needs no configuration. Leasing spends money,
// so it needs a wallet: PRISM_AGENT_KEY, PRISM_ESCROW.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { DEFAULT_IMAGE, DEFAULT_TRUST_FLOOR, PrismAgent, TRUST_CLASSES } from "@prismnetwork/agent-sdk";

const IMAGE = process.env.PRISM_DEFAULT_IMAGE ?? DEFAULT_IMAGE;

const PUBLIC_API = process.env.PRISM_PUBLIC_API ?? "https://api.prismnetwork.tech";
// The live lease escrow. Overridable, but its absence must not silently
// disable the wallet the way a missing key does.
const DEFAULT_ESCROW = "0x62C042265991bEa17B07229322A01850974626dA";
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

function requireWallet(tool, reason = "spends money") {
  if (!agent) {
    throw new Error(
      `${tool} ${reason} and needs a wallet. None is configured: ${walletProblem}. Fix the environment and restart the server.`,
    );
  }
  return agent;
}

function requireCommand(value) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error("command is required: the shell command to run on the GPU, e.g. 'nvidia-smi'.");
  }
  if (Buffer.byteLength(value, "utf8") > MAX_COMMAND_BYTES) {
    throw new Error(`command exceeds the ${MAX_COMMAND_BYTES / 1024} KiB limit.`);
  }
  return value;
}

function maxDeposit(args) {
  const cap = args.max_usdg ?? 1;
  if (typeof cap !== "number" || !Number.isFinite(cap) || cap <= 0) {
    throw new Error("max_usdg must be a positive number of USDG.");
  }
  return Math.round(cap * 1e6);
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

const TOOLS = [
  {
    name: "prism_wallet",
    description: "Show the agent's wallet address and on-chain balances (USDG and ETH for gas) on Robinhood Chain. Check this before leasing to confirm the wallet can pay.",
    inputSchema: { type: "object", properties: {} },
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
  },
  {
    name: "prism_price_index",
    description: "Current GPU pricing on Prism Network by model: sourced low/median/high and settled mean, in USDG per hour. Needs no wallet. Use it to estimate what an analysis job will cost before leasing.",
    inputSchema: { type: "object", properties: {} },
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
  },
  {
    name: "prism_leases",
    description: "List this wallet's leases on Prism Network with their current state.",
    inputSchema: { type: "object", properties: {} },
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
        max_usdg: { type: "number", description: "Hard cap on the USDG this lease may cost (default 1). Raise it deliberately for longer leases." },
      },
      required: ["command"],
    },
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
        max_usdg: { type: "number", description: "Hard cap on the USDG this lease may cost (default 1). Raise it deliberately for longer leases." },
      },
      required: ["command"],
    },
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
        max_usdg: { type: "number", description: "Hard cap on the USDG this lease may cost (default 1). Raise it deliberately for longer leases." },
      },
    },
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
  },
  {
    name: "prism_end_lease",
    description: "Release a lease's local access. The on-chain lease settles at the end of its paid duration.",
    inputSchema: {
      type: "object",
      properties: { lease_id: { type: "integer" } },
      required: ["lease_id"],
    },
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
  },
  {
    name: "prism_vault_list",
    description: "List the agent's sealed vault items: item_id, label, version and trust floor. Values are not returned and are not readable by Prism.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "prism_vault_read",
    description: "Decrypt and return one vault item, in this process, using the wallet-derived key. The plaintext exists only here; do not echo it into a leased workspace, a log, or a message.",
    inputSchema: {
      type: "object",
      properties: { item_id: { type: "string", description: "The item_id from prism_vault_store or prism_vault_list." } },
      required: ["item_id"],
    },
  },
  {
    name: "prism_vault_delete",
    description: "Permanently delete a vault item. The ciphertext is removed and the value cannot be recovered.",
    inputSchema: {
      type: "object",
      properties: { item_id: { type: "string" } },
      required: ["item_id"],
    },
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
  },
];

async function handle(name, args) {
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
    const cap = maxDeposit(args);
    const batch = await agent.lease({
      image: IMAGE,
      durationSeconds: args.duration_seconds ?? 900,
      minVramMib: args.min_vram_mib ?? 16000,
      maxDeposit: cap,
      command: args.command,
    });
    return {
      lease_id: batch.leaseId,
      funding_tx: batch.fundingHash,
      exit_code: batch.result?.exit_code,
      stdout: batch.result?.stdout,
      stderr: batch.result?.stderr,
      truncated: batch.result?.truncated ?? false,
    };
  }
  if (name === "prism_batch_result") {
    requireWallet(name, "reads this wallet's leases");
    const id = leaseId(args.lease_id);
    return { lease_id: id, result: await agent.result(id) };
  }
  if (name === "prism_lease_and_run" || name === "prism_lease") {
    if (name === "prism_lease_and_run") requireCommand(args.command);
    requireWallet(name);
    const cap = maxDeposit(args);
    sweepExpiredLeases();
    const lease = await agent.lease({
      image: IMAGE,
      durationSeconds: args.duration_seconds ?? 900,
      minVramMib: args.min_vram_mib ?? 16000,
      maxDeposit: cap,
      minTrustClass: args.min_trust_class ?? "open",
    });
    leases.set(lease.leaseId, lease);
    const summary = {
      lease_id: lease.leaseId,
      funding_tx: lease.fundingHash,
      ssh: { host: lease.access.ssh_host, port: lease.access.ssh_port, user: lease.access.ssh_user },
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
    if (lease) {
      agent.endLease(lease);
      leases.delete(id);
    }
    return { lease_id: id, released: Boolean(lease) };
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

const server = new Server({ name: "prism", version: "0.6.0" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    const result = await handle(request.params.name, request.params.arguments ?? {});
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
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
