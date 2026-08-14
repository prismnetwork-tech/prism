// Prism Network plugin for elizaOS: an Eliza agent can see live GPU capacity
// and prices, rent a real GPU with an on-chain USDG payment, and run commands
// on it. Actions are plain objects in the 1.x shape, so the plugin has no
// runtime dependency on @elizaos/core.
import { PrismToolset, agentFromEnv, isRefusal } from "@prismnetwork/agent-sdk/toolset";

// One toolset per agent, built on first use. Keys can arrive through the
// runtime's settings (character secrets) rather than process.env, and two
// characters in one process must not share a wallet. A malformed key becomes a
// note the agent can repeat instead of an import-time crash.
const toolsets = new Map();

function toolsetFor(runtime) {
  const id = runtime?.agentId ?? "default";
  let entry = toolsets.get(id);
  if (!entry) {
    const get = (name) => runtime?.getSetting?.(name) ?? process.env[name];
    try {
      entry = { toolset: new PrismToolset({ agent: agentFromEnv(get) }) };
    } catch (err) {
      entry = {
        toolset: new PrismToolset({ agent: null }),
        note: `The configured PRISM_AGENT_KEY is unusable: ${err?.message ?? err}`,
      };
    }
    toolsets.set(id, entry);
  }
  return entry;
}

const text = (message) => message?.content?.text ?? "";

// A command the user quoted in backticks, if any; nvidia-smi otherwise.
function extractCommand(input) {
  const match = input.match(/`([^`]+)`/);
  return match ? match[1] : "nvidia-smi";
}

// An hour is the most a chat request can commit; longer leases go through the SDK.
function extractMinutes(input) {
  const match = input.match(/(\d+)\s*(?:minute|min)\b/i);
  return match ? Math.min(Number(match[1]), 60) * 60 : 600;
}

// A refusal or failure the toolset returns as prose is still a failed action;
// reporting it as success would let the runtime believe the lease happened.
// The toolset owns the wording, so it owns the predicate too.
function failed(body) {
  return isRefusal(body) || body.startsWith("The configured PRISM_AGENT_KEY is unusable");
}

async function respond(callback, actionName, body) {
  if (callback) await callback({ text: body, actions: [actionName] });
  return { success: !failed(body), text: body };
}

const listGpusAction = {
  name: "PRISM_LIST_GPUS",
  similes: ["LIST_GPUS", "GPU_PRICES", "AVAILABLE_GPUS"],
  description:
    "List GPUs available to rent on Prism Network right now, with model, VRAM, price per hour in USDG, and trust class.",
  validate: async (_runtime, message) =>
    /\bgpus?\b|\bprism\b/i.test(text(message)) &&
    /\b(list|available|price|prices|cost|rent|capacity|offer)/i.test(text(message)),
  handler: async (runtime, _message, _state, _options, callback) => {
    const { toolset, note } = toolsetFor(runtime);
    const body = await toolset.listGpus();
    return respond(callback, "PRISM_LIST_GPUS", note ? `${note}\n${body}` : body);
  },
  examples: [
    [
      { name: "{{user}}", content: { text: "what GPUs can you rent right now and at what price?" } },
      {
        name: "{{agent}}",
        content: { text: "RTX 6000Ada · 49140 MiB · 0.64 USDG/hr · open", actions: ["PRISM_LIST_GPUS"] },
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
  handler: async (runtime, _message, _state, _options, callback) => {
    const { toolset, note } = toolsetFor(runtime);
    const body = note ?? (await toolset.wallet());
    return respond(callback, "PRISM_WALLET", body);
  },
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
  // Spends money, so the ask has to be an instruction to rent, not a question
  // about renting: "rent a GPU and run `nvidia-smi`" yes, "what GPUs can you
  // rent and at what price?" no.
  validate: async (_runtime, message) => {
    const input = text(message);
    if (!/\b(rent|lease|provision|spin up)\b/i.test(input) || !/\bgpus?\b/i.test(input)) return false;
    return !/\b(what|which|how|price|prices|cost|available)\b/i.test(input);
  },
  handler: async (runtime, message, _state, _options, callback) => {
    const { toolset, note } = toolsetFor(runtime);
    if (note) return respond(callback, "PRISM_LEASE_AND_RUN", note);
    const input = text(message);
    const body = await toolset.leaseAndRun({
      command: extractCommand(input),
      durationSeconds: extractMinutes(input),
    });
    return respond(callback, "PRISM_LEASE_AND_RUN", body);
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
  get: async (runtime) => {
    const { toolset } = toolsetFor(runtime);
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
