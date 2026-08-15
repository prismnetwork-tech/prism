// Prism Network plugin for the Virtuals Protocol GAME SDK: a GAME agent gets a
// worker whose action space is renting and running on real GPUs, paid on-chain
// in USDG on Robinhood Chain.
//
// GAME delivers every argument as a string, so numeric arguments are parsed
// here and refused with a Failed response when they do not parse. GAME does
// not catch a rejection out of an executable (it would kill the agent loop),
// so every function reports Failed instead of throwing.
import {
  ExecutableGameFunctionResponse,
  ExecutableGameFunctionStatus,
  GameFunction,
  GameWorker,
} from "@virtuals-protocol/game";
import { PrismToolset, isRefusal } from "@prismnetwork/agent-sdk/toolset";

const { Done, Failed } = ExecutableGameFunctionStatus;

function integer(value, fallback) {
  if (value === undefined || value === "") return fallback;
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

// The toolset reports refusals and failures as prose rather than throwing; the
// planner still needs them as Failed, or it records a step that never happened.
function verdict(body) {
  return new ExecutableGameFunctionResponse(isRefusal(body) ? Failed : Done, body);
}

async function attempt(logger, work) {
  try {
    const body = await work();
    logger(body);
    return verdict(body);
  } catch (err) {
    return new ExecutableGameFunctionResponse(Failed, `prism call failed: ${err?.message ?? err}`);
  }
}

export class PrismGamePlugin {
  constructor({ toolset, id = "prism_gpu_worker" } = {}) {
    this.id = id;
    this.toolset = toolset ?? new PrismToolset();
  }

  getWorker() {
    return new GameWorker({
      id: this.id,
      name: "Prism GPU worker",
      description:
        "Rents real NVIDIA GPUs on Prism Network and runs commands on them. Payment is on-chain " +
        "USDG on Robinhood Chain; every lease settles with a verifiable receipt. Look at capacity " +
        "and prices first, then lease only when a task actually needs a GPU.",
      functions: [
        this.listGpusFunction,
        this.walletFunction,
        this.leaseAndRunFunction,
        this.runFunction,
        this.endLeaseFunction,
      ],
      getEnvironment: async () => ({
        gpus_rentable_now: await this.toolset.listGpus().catch(() => "unreachable"),
      }),
    });
  }

  get listGpusFunction() {
    return new GameFunction({
      name: "list_gpus",
      description:
        "List GPUs available to rent right now, with model, VRAM, price per hour in USDG, and trust class.",
      args: [],
      executable: (_args, logger) => attempt(logger, () => this.toolset.listGpus()),
    });
  }

  get walletFunction() {
    return new GameFunction({
      name: "wallet",
      description: "Show the Prism wallet address and its USDG and gas balances on Robinhood Chain.",
      args: [],
      executable: (_args, logger) => attempt(logger, () => this.toolset.wallet()),
    });
  }

  get leaseAndRunFunction() {
    return new GameFunction({
      name: "lease_and_run",
      description:
        "Rent a GPU, run one shell command on it over SSH, and return the output. Funds an on-chain " +
        "USDG escrow and blocks while the machine provisions, usually one to four minutes. The lease " +
        "stays open for follow-up commands with run.",
      args: [
        { name: "command", description: "Shell command to run on the GPU, e.g. nvidia-smi" },
        { name: "duration_seconds", description: "Lease length in seconds (default 600, max 21600)", optional: true },
        { name: "min_vram_mib", description: "Minimum GPU memory in MiB (default 16000)", optional: true },
        { name: "max_usdg", description: "Hard cap on the USDG this lease may cost (default 1)", optional: true },
      ],
      hint: "Leasing spends real USDG. Check wallet and list_gpus first.",
      executable: async (args, logger) => {
        if (!args.command) return new ExecutableGameFunctionResponse(Failed, "command is required");
        const durationSeconds = integer(args.duration_seconds, 600);
        if (durationSeconds === null) {
          return new ExecutableGameFunctionResponse(Failed, "duration_seconds must be a positive integer");
        }
        const minVramMib = integer(args.min_vram_mib, 16000);
        if (minVramMib === null) {
          return new ExecutableGameFunctionResponse(Failed, "min_vram_mib must be a positive integer");
        }
        const maxUsdg = args.max_usdg === undefined || args.max_usdg === "" ? 1 : Number(args.max_usdg);
        if (!Number.isFinite(maxUsdg) || maxUsdg <= 0) {
          return new ExecutableGameFunctionResponse(Failed, "max_usdg must be a positive number");
        }
        logger(`leasing a GPU for ${durationSeconds}s (cap ${maxUsdg} USDG)`);
        return attempt(logger, () =>
          this.toolset.leaseAndRun({
            command: args.command,
            durationSeconds,
            minVramMib,
            maxUsdg,
          }),
        );
      },
    });
  }

  get runFunction() {
    return new GameFunction({
      name: "run",
      description: "Run another shell command on a GPU already leased in this session.",
      args: [
        { name: "lease_id", description: "The lease id returned by lease_and_run" },
        { name: "command", description: "Shell command to run" },
      ],
      executable: async (args, logger) => {
        const leaseId = integer(args.lease_id, null);
        if (leaseId === null) {
          return new ExecutableGameFunctionResponse(Failed, "lease_id must be a positive integer");
        }
        if (!args.command) return new ExecutableGameFunctionResponse(Failed, "command is required");
        return attempt(logger, () => this.toolset.run(leaseId, args.command));
      },
    });
  }

  get endLeaseFunction() {
    return new GameFunction({
      name: "end_lease",
      description: "Release a leased GPU. The on-chain lease settles when its paid window ends.",
      args: [{ name: "lease_id", description: "The lease id to release" }],
      executable: async (args, logger) => {
        const leaseId = integer(args.lease_id, null);
        if (leaseId === null) {
          return new ExecutableGameFunctionResponse(Failed, "lease_id must be a positive integer");
        }
        return attempt(logger, async () => this.toolset.endLease(leaseId));
      },
    });
  }
}

export default PrismGamePlugin;
