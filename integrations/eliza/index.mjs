// Prism Network plugin for elizaOS: an Eliza agent can see live GPU capacity
// and prices, rent a real GPU with an on-chain USDG payment, and run commands
// on it. Actions are plain objects in the 1.x shape, so the plugin has no
// runtime dependency on @elizaos/core.
import { PrismToolset } from "@prismnetwork/agent-sdk/toolset";

const toolset = new PrismToolset();

const text = (message) => message?.content?.text ?? "";

// A command the user quoted in backticks, if any; nvidia-smi otherwise.
function extractCommand(input) {
  const match = input.match(/`([^`]+)`/);
  return match ? match[1] : "nvidia-smi";
}

function extractMinutes(input) {
  const match = input.match(/(\d+)\s*(?:minute|min)\b/i);
  return match ? Math.min(Number(match[1]), 360) * 60 : 600;
}

async function respond(callback, actionName, body) {
  if (callback) await callback({ text: body, actions: [actionName] });
  return { success: true, text: body };
}

const listGpusAction = {
  name: "PRISM_LIST_GPUS",
  similes: ["LIST_GPUS", "GPU_PRICES", "AVAILABLE_GPUS"],
  description:
    "List GPUs available to rent on Prism Network right now, with model, VRAM, price per hour in USDG, and trust class.",
  validate: async (_runtime, message) =>
    /\bgpus?\b|\bprism\b/i.test(text(message)) &&
    /\b(list|available|price|prices|cost|rent|capacity|offer)/i.test(text(message)),
  handler: async (_runtime, _message, _state, _options, callback) =>
    respond(callback, "PRISM_LIST_GPUS", await toolset.listGpus()),
  examples: [
    [
      { name: "{{user}}", content: { text: "what GPUs can you rent right now and at what price?" } },
      {
        name: "{{agent}}",
        content: { text: "RTX 6000Ada · 49140 MiB · $0.64/hr · open", actions: ["PRISM_LIST_GPUS"] },
      },
    ],
  ],
};

const walletAction = {
  name: "PRISM_WALLET",
  similes: ["GPU_WALLET", "PRISM_BALANCE"],
  description: "Show the Prism wallet address and its USDG and gas balances on Robinhood Chain.",
  validate: async (_runtime, message) =>
    /\bprism\b|\bgpu\b/i.test(text(message)) && /\b(wallet|balance|usdg|funds)\b/i.test(text(message)),
  handler: async (_runtime, _message, _state, _options, callback) =>
    respond(callback, "PRISM_WALLET", await toolset.wallet()),
  examples: [
    [
      { name: "{{user}}", content: { text: "how much is left in the GPU wallet?" } },
      { name: "{{agent}}", content: { text: "address: 0x… / 4.8 USDG", actions: ["PRISM_WALLET"] } },
    ],
  ],
};

const leaseAndRunAction = {
  name: "PRISM_LEASE_AND_RUN",
  similes: ["RENT_GPU", "LEASE_GPU", "RUN_ON_GPU"],
  description:
    "Rent a real GPU on Prism Network, run one shell command on it over SSH, and report the output. " +
    "Funds an on-chain USDG escrow; provisioning takes one to four minutes. The command is taken from " +
    "backticks in the message, or defaults to nvidia-smi.",
  validate: async (_runtime, message) =>
    /\b(rent|lease|provision|spin up)\b/i.test(text(message)) && /\bgpus?\b/i.test(text(message)),
  handler: async (_runtime, message, _state, _options, callback) => {
    const input = text(message);
    try {
      const body = await toolset.leaseAndRun({
        command: extractCommand(input),
        durationSeconds: extractMinutes(input),
      });
      return respond(callback, "PRISM_LEASE_AND_RUN", body);
    } catch (err) {
      const body = `The lease did not go through: ${err?.message ?? err}`;
      if (callback) await callback({ text: body, actions: ["PRISM_LEASE_AND_RUN"] });
      return { success: false, text: body, error: err?.message ?? String(err) };
    }
  },
  examples: [
    [
      { name: "{{user}}", content: { text: "rent a GPU for 10 minutes and run `nvidia-smi`" } },
      {
        name: "{{agent}}",
        content: { text: "lease 21 funded onchain, exit 0: NVIDIA RTX A6000 …", actions: ["PRISM_LEASE_AND_RUN"] },
      },
    ],
  ],
};

const capacityProvider = {
  name: "PRISM_CAPACITY",
  description: "Live GPU capacity and pricing on Prism Network.",
  dynamic: true,
  get: async () => {
    const capacity = await toolset.listGpus().catch(() => "unreachable");
    return { text: `GPUs rentable on Prism Network right now:\n${capacity}` };
  },
};

export const prismPlugin = {
  name: "plugin-prism",
  description:
    "Rent real NVIDIA GPUs from Prism Network: live capacity and prices, on-chain USDG leases on Robinhood Chain, command execution over SSH.",
  actions: [listGpusAction, walletAction, leaseAndRunAction],
  providers: [capacityProvider],
};

export default prismPlugin;
