#!/usr/bin/env node
// Prism Network MCP server: lets an MCP client (Claude, agents) lease and run on
// real GPUs. Configure with a wallet: PRISM_AGENT_KEY, PRISM_ESCROW.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { DEFAULT_IMAGE, PrismAgent } from "@prism-network/agent-sdk";

const IMAGE = process.env.PRISM_DEFAULT_IMAGE ?? DEFAULT_IMAGE;

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

let agent;
try {
  agent = new PrismAgent({
    privateKey: requireEnv("PRISM_AGENT_KEY"),
    escrow: requireEnv("PRISM_ESCROW"),
    apiBase: process.env.PRISM_API_BASE ?? "https://prismnetwork.tech",
    rpcUrl: process.env.PRISM_RPC_URL,
  });
} catch (err) {
  console.error(`prism mcp config error: ${err.message}. Set PRISM_AGENT_KEY and PRISM_ESCROW in the server env.`);
  process.exit(1);
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
    description: "List GPUs currently available to lease on Prism Network, with model, VRAM, and price per second in USDG.",
    inputSchema: { type: "object", properties: {} },
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
];

async function handle(name, args) {
  if (name === "prism_wallet") {
    const b = await agent.balances();
    return { address: b.address, usdg: usdg(b.usdg), eth_wei: b.eth };
  }
  if (name === "prism_list_gpus") {
    await ensureAuth();
    const offers = await agent.offers();
    return {
      available: offers.length,
      gpus: offers.map((o) => ({
        model: o.gpu.model,
        vram_mib: o.gpu.vram_mib,
        price_per_second: usdg(o.rate_per_second),
        price_per_hour: usdg(o.rate_per_second * 3600),
      })),
    };
  }
  if (name === "prism_lease_and_run" || name === "prism_lease") {
    if (name === "prism_lease_and_run" && !args.command) throw new Error("command is required");
    await ensureAuth();
    sweepExpiredLeases();
    const lease = await agent.lease({
      image: IMAGE,
      durationSeconds: args.duration_seconds ?? 900,
      minVramMib: args.min_vram_mib ?? 16000,
    });
    leases.set(lease.leaseId, lease);
    const summary = {
      lease_id: lease.leaseId,
      ssh: { host: lease.access.ssh_host, port: lease.access.ssh_port, user: lease.access.ssh_user },
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

const server = new Server({ name: "prism", version: "0.1.0" }, { capabilities: { tools: {} } });
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
