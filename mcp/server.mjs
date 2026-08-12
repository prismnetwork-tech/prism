#!/usr/bin/env node
// Prism Network MCP server: lets an MCP client (Claude, agents) see and lease
// real GPUs. Looking is free and needs no configuration. Leasing spends money,
// so it needs a wallet: PRISM_AGENT_KEY, PRISM_ESCROW.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { DEFAULT_IMAGE, DEFAULT_TRUST_FLOOR, PrismAgent, TRUST_CLASSES } from "@prismnetwork/agent-sdk";

const IMAGE = process.env.PRISM_DEFAULT_IMAGE ?? DEFAULT_IMAGE;

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const PUBLIC_API = process.env.PRISM_PUBLIC_API ?? "https://api.prismnetwork.tech";

// Refusing to start without a wallet meant nobody could ask what a GPU costs
// without first producing a private key, which is a strange thing to demand of
// someone deciding whether to use you at all.
let agent = null;
try {
  agent = new PrismAgent({
    privateKey: requireEnv("PRISM_AGENT_KEY"),
    escrow: requireEnv("PRISM_ESCROW"),
    apiBase: process.env.PRISM_API_BASE ?? "https://prismnetwork.tech",
    rpcUrl: process.env.PRISM_RPC_URL,
  });
} catch {
  console.error(
    "prism mcp: no wallet configured, so capacity and pricing are readable and leasing is not. " +
      "Set PRISM_AGENT_KEY and PRISM_ESCROW to lease.",
  );
}

function requireWallet(tool) {
  if (!agent) {
    throw new Error(
      `${tool} spends money, so it needs a wallet. Set PRISM_AGENT_KEY and PRISM_ESCROW in this server's environment and restart it.`,
    );
  }
  return agent;
}

async function publicOffers(minTrust) {
  const url = new URL("/v1/offers", PUBLIC_API);
  if (minTrust) url.searchParams.set("min_trust", minTrust);
  const response = await fetch(url, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`prism offers unavailable (${response.status})`);
  return response.json();
}

const leases = new Map();
const usdg = (micros) => `${(Number(micros) / 1e6).toFixed(6)} USDG`;

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
    description: "Store private data — a card, an identity document, an API credential — encrypted under a key derived from this agent's wallet on this machine. Prism receives ciphertext only and cannot read it. Use this instead of writing a secret into a workspace or a file. Returns an item_id; the value is not recoverable without the wallet.",
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
    description: "Decrypt and return one vault item, in this process, using the wallet-derived key. The plaintext exists only here — do not echo it into a leased workspace, a log, or a message.",
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
    let offers;
    if (agent) {
      await ensureAuth();
      offers = await agent.offers({ minTrust });
    } else {
      offers = await publicOffers(minTrust);
    }
    return {
      available: offers.length,
      gpus: offers.map((o) => ({
        model: o.gpu.model,
        vram_mib: o.gpu.vram_mib,
        price_per_second: usdg(o.rate_per_second),
        price_per_hour: usdg(o.rate_per_second * 3600),
        trust: o.trust_class,
      })),
    };
  }
  if (name === "prism_lease_and_run" || name === "prism_lease") {
    if (name === "prism_lease_and_run" && !args.command) throw new Error("command is required");
    requireWallet(name);
    await ensureAuth();
    sweepExpiredLeases();
    const lease = await agent.lease({
      image: IMAGE,
      durationSeconds: args.duration_seconds ?? 900,
      minVramMib: args.min_vram_mib ?? 16000,
      minTrustClass: args.min_trust_class ?? "open",
    });
    leases.set(lease.leaseId, lease);
    const summary = {
      lease_id: lease.leaseId,
      ssh: { host: lease.access.ssh_host, port: lease.access.ssh_port, user: lease.access.ssh_user },
      trust: lease.quote?.trust_class ?? "open",
      expires_at: lease.access.expires_at,
    };
    if (name === "prism_lease") return summary;
    const out = await agent.run(lease, args.command);
    return { ...summary, command: args.command, exit_code: out.code, stdout: out.stdout, stderr: out.stderr };
  }
  if (name === "prism_run") {
    if (!args.command) throw new Error("command is required");
    const id = leaseId(args.lease_id);
    const lease = leases.get(id);
    if (!lease) throw new Error(`no active lease ${id} in this session`);
    const out = await agent.run(lease, args.command, {
      timeoutMs: (args.timeout_seconds ?? 120) * 1000,
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
  throw new Error(`unknown tool ${name}`);
}

// The vault key is derived here from the wallet signature and stays in this
// process. Nothing in this function sends a key or a plaintext to Prism.
async function handleVault(name, args) {
  const vault = requireWallet(name).vault;
  await ensureAuth();
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

let authPromise = null;
function ensureAuth() {
  authPromise ??= agent.authenticate().catch((err) => {
    authPromise = null;
    throw err;
  });
  return authPromise;
}

const server = new Server({ name: "prism", version: "0.4.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    const result = await handle(request.params.name, request.params.arguments ?? {});
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    return { isError: true, content: [{ type: "text", text: `error: ${err.message ?? err}` }] };
  }
});

await server.connect(new StdioServerTransport());
console.error("prism mcp server ready");
