#!/usr/bin/env node
// Prism Network MCP server — lets an MCP client (Claude, agents) lease and run on
// real GPUs. Configure with a wallet: PRISM_AGENT_KEY, PRISM_ESCROW.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { PrismAgent } from "@prism-network/agent-sdk";

const DEFAULT_IMAGE =
  process.env.PRISM_DEFAULT_IMAGE ??
  "docker.io/ollama/ollama@sha256:a61a8fd395dbb931cc8cb1b5da7a2510746575c87113fdc45b647ee59ef7f808";

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const agent = new PrismAgent({
  privateKey: requireEnv("PRISM_AGENT_KEY"),
  escrow: requireEnv("PRISM_ESCROW"),
  apiBase: process.env.PRISM_API_BASE ?? "https://prismnetwork.tech",
  rpcUrl: process.env.PRISM_RPC_URL,
});

const leases = new Map();
const usdg = (micros) => `${(Number(micros) / 1e6).toFixed(6)} USDG`;

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
    description: "Lease a GPU, run one shell command on it, and return the output. The lease stays alive (use prism_run for more commands, prism_end_lease to release). This is the fastest way to run a one-off GPU job.",
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
    await ensureAuth();
    const lease = await agent.lease({
      image: DEFAULT_IMAGE,
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
    const lease = leases.get(args.lease_id);
    if (!lease) throw new Error(`no active lease ${args.lease_id} in this session`);
    const out = await agent.run(lease, args.command, {
      timeoutMs: (args.timeout_seconds ?? 120) * 1000,
    });
    return { lease_id: args.lease_id, exit_code: out.code, stdout: out.stdout, stderr: out.stderr };
  }
  if (name === "prism_end_lease") {
    const lease = leases.get(args.lease_id);
    if (lease) {
      agent.endLease(lease);
      leases.delete(args.lease_id);
    }
    return { lease_id: args.lease_id, released: Boolean(lease) };
  }
  throw new Error(`unknown tool ${name}`);
}

let authed = false;
async function ensureAuth() {
  if (!authed) {
    await agent.authenticate();
    authed = true;
  }
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
