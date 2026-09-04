import { ActionProvider } from "@coinbase/agentkit";
import { DEFAULT_IMAGE, PrismAgent, TRUST_CLASSES } from "@prismnetwork/agent-sdk";
import { z } from "zod";

const MICROS_PER_USDG = 1_000_000;
const SECONDS_PER_HOUR = 3_600;

const noArgs = z.object({});

const leaseAndRunArgs = z.object({
  command: z.string().min(1).describe("Shell command to run on the rented GPU"),
  durationSeconds: z.number().int().min(60).max(21_600).default(600).describe("How long to hold the lease"),
  minVramMib: z.number().int().min(1).default(16_000).describe("Minimum GPU memory in MiB"),
  image: z.string().default(DEFAULT_IMAGE).describe("Digest-pinned container image to boot"),
  maxUsdg: z.number().positive().default(1).describe("Hard cap on the USDG this lease may cost"),
  minTrustClass: z
    .enum(TRUST_CLASSES)
    .default("open")
    .describe(
      "Refuse suppliers below this trust class. On an 'open' supplier the host operator can read anything the workload touches.",
    ),
});

const runArgs = z.object({
  leaseId: z.number().int().describe("Lease returned by lease_and_run"),
  command: z.string().min(1).describe("Shell command to run"),
});

const endLeaseArgs = z.object({
  leaseId: z.number().int().describe("Lease to release"),
});

function usdg(micros) {
  return `${(Number(micros) / MICROS_PER_USDG).toFixed(6)} USDG`;
}

function perHour(ratePerSecond) {
  return `$${((Number(ratePerSecond) * SECONDS_PER_HOUR) / MICROS_PER_USDG).toFixed(2)}/hr`;
}

function fromEnvironment() {
  const privateKey = process.env.PRISM_AGENT_KEY;
  const escrow = process.env.PRISM_ESCROW;
  if (!privateKey || !escrow) {
    throw new Error("PRISM_AGENT_KEY and PRISM_ESCROW are required, or pass a PrismAgent");
  }
  return new PrismAgent({ privateKey, escrow });
}

/**
 * Prism actions for AgentKit. Prism pays with its own wallet on Robinhood
 * Chain, so the wallet provider AgentKit is configured with is untouched.
 */
export class PrismActionProvider extends ActionProvider {
  #agent;
  #leases = new Map();

  constructor(agent) {
    super("prism", []);
    this.#agent = agent ?? fromEnvironment();
  }

  supportsNetwork() {
    return true;
  }

  getActions() {
    return [
      {
        name: "prism_wallet",
        description: "Report the Prism wallet address and its USDG and gas balances.",
        schema: noArgs,
        invoke: async () => {
          const { address, usdg: balance, eth } = await this.#agent.balances();
          return `${address}\n${usdg(balance)}\n${(Number(eth) / 1e18).toFixed(6)} ETH for gas`;
        },
      },
      {
        name: "prism_list_gpus",
        description:
          "List GPUs available to rent right now, with model, memory, price per hour, and trust class. On an 'open' supplier the host operator can read anything the workload touches.",
        schema: noArgs,
        invoke: async () => {
          const offers = await this.#agent.offers();
          if (!offers.length) return "No GPUs are available right now.";
          return offers
            .map(
              (offer) =>
                `${offer.gpu.model} · ${offer.gpu.vram_mib} MiB · ${perHour(offer.rate_per_second)} · ${offer.trust_class ?? "open"}`,
            )
            .join("\n");
        },
      },
      {
        name: "prism_lease_and_run",
        description:
          "Rent a GPU, run one command on it over SSH, and keep the lease open for follow-up commands. Funds an onchain escrow.",
        schema: leaseAndRunArgs,
        invoke: async (args) => {
          const lease = await this.#agent.lease({
            image: args.image,
            durationSeconds: args.durationSeconds,
            minVramMib: args.minVramMib,
            maxDeposit: Math.round(args.maxUsdg * MICROS_PER_USDG),
            minTrustClass: args.minTrustClass,
          });
          this.#leases.set(lease.leaseId, lease);
          const result = await this.#agent.run(lease, args.command);
          return [
            `lease ${lease.leaseId} funded onchain: ${lease.fundingHash}`,
            `exit ${result.code}`,
            result.stdout.trim(),
            result.stderr.trim(),
          ]
            .filter(Boolean)
            .join("\n");
        },
      },
      {
        name: "prism_run",
        description: "Run another command on a GPU already leased in this session.",
        schema: runArgs,
        invoke: async (args) => {
          const lease = this.#leases.get(args.leaseId);
          if (!lease) return `lease ${args.leaseId} is not open in this session`;
          const result = await this.#agent.run(lease, args.command);
          return [`exit ${result.code}`, result.stdout.trim(), result.stderr.trim()].filter(Boolean).join("\n");
        },
      },
      {
        name: "prism_end_lease",
        description:
          "Release a lease. Billing stops at the release; settlement charges the seconds it was open and returns the rest of the deposit.",
        schema: endLeaseArgs,
        invoke: async (args) => {
          const lease = this.#leases.get(args.leaseId);
          if (!lease) return `lease ${args.leaseId} is not open in this session`;
          this.#leases.delete(args.leaseId);
          const out = await this.#agent.endLease(lease);
          if (out?.release === "failed") {
            return `lease ${args.leaseId} could not be released: ${out.error}. Its access key is gone but the meter may still be running; check receipts for the settled charge.`;
          }
          return `released lease ${args.leaseId}; billing stopped here and the unused deposit returns after settlement`;
        },
      },
    ];
  }
}

export function prismActionProvider(agent) {
  return new PrismActionProvider(agent);
}
