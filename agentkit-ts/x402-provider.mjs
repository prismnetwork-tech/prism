// Prism's pay-per-call surface as AgentKit actions. Unlike the leasing provider
// in ./provider.mjs, which holds its own funded wallet, everything here is paid
// from the wallet AgentKit already gave the agent: USDC on Base, over x402.
// There is no account to open and no API key to hold. The agent reads the price
// off the 402, signs an authorization, and gets the result in the same request.
import { ActionProvider } from "@coinbase/agentkit";
import { x402Client, wrapFetchWithPayment, decodePaymentResponseHeader } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { z } from "zod";

export const DEFAULT_API_BASE = "https://api.prismnetwork.tech";
export const DEFAULT_MAX_PAYMENT_USDC = 1;

const USDC_DECIMALS = 6;

const noArgs = z.object({});

const inferenceArgs = z.object({
  prompt: z.string().min(1).describe("The prompt to send to the model"),
  model: z
    .string()
    .optional()
    .describe("Model to run, e.g. 'llama3.2:3b'. Defaults to the cheapest model Prism serves"),
  maxTokens: z
    .number()
    .int()
    .positive()
    .max(1024)
    .optional()
    .describe("Cap on generated tokens. The price scales with this cap, so keep it tight"),
});

const batchArgs = z.object({
  prompts: z.array(z.string().min(1)).min(1).describe("Independent prompts, answered in order"),
  model: z.string().optional().describe("Model to run for every prompt"),
  maxTokens: z.number().int().positive().max(1024).optional().describe("Per-prompt token cap"),
});

const commandArgs = z.object({
  command: z.string().min(1).describe("Shell command to run on the GPU box, e.g. 'nvidia-smi'"),
});

const jobArgs = z.object({
  jobId: z.string().min(1).describe("Job id returned by prism_run_gpu_command"),
  token: z.string().min(1).describe("Bearer token returned by prism_run_gpu_command"),
});

function describe(error) {
  if (error instanceof Error) return error.message || String(error);
  const text = String(error);
  if (text !== "[object Object]") return text;
  try {
    return JSON.stringify(error);
  } catch {
    return "Unknown error";
  }
}

// A gateway behind a proxy can answer with HTML on a bad day. Reading text
// first means the agent sees the page rather than a JSON parse error.
async function readJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return { detail: text.slice(0, 500) };
  }
}

export class PrismX402ActionProvider extends ActionProvider {
  #apiBase;
  #maxPaymentAtomic;

  constructor({ apiBase = DEFAULT_API_BASE, maxPaymentUsdc = DEFAULT_MAX_PAYMENT_USDC } = {}) {
    super("prism-x402", []);
    this.#apiBase = apiBase.replace(/\/+$/, "");
    this.#maxPaymentAtomic = BigInt(Math.floor(maxPaymentUsdc * 10 ** USDC_DECIMALS));
  }

  supportsNetwork(network) {
    return network?.protocolFamily === "evm";
  }

  getActions(walletProvider) {
    return [
      {
        name: "prism_get_models",
        description:
          "List the models Prism serves, what each costs, and whether a GPU is warm right now. " +
          "Free, no payment. Call this before the paid actions when you do not know which models exist. " +
          "Prices are in micro-USD: 1,000,000 micros is 1 USDC. A state of 'cold' or 'warming' means " +
          "the next paid call may come back unbilled while a GPU is leased and the model is pulled.",
        schema: noArgs,
        invoke: async () => {
          try {
            const response = await fetch(`${this.#apiBase}/inference/v1/models`);
            if (!response.ok) return `Prism answered ${response.status} listing models.`;
            return JSON.stringify(await response.json());
          } catch (error) {
            return `Error listing Prism models: ${describe(error)}`;
          }
        },
      },
      {
        name: "prism_run_inference",
        description:
          "Run one LLM generation on a GPU rented from Prism, paid with USDC on Base from this wallet. " +
          "No account and no API key. Inputs: prompt (required); model, e.g. 'llama3.2:3b'; maxTokens, " +
          "a cap on generated tokens. The price scales with the cap, so ask for the smallest one that " +
          "fits the answer. Costs a few tenths of a cent. Returns the text, token usage, the GPU lease " +
          "that served it, and the settlement transaction. If no GPU is warm the call returns " +
          "charged: false with a wait in seconds and nothing is billed; tell the user how long to wait " +
          "rather than retrying in a tight loop.",
        schema: inferenceArgs,
        invoke: (args) =>
          this.#pay(walletProvider, "/inference/v1/inference", {
            prompt: args.prompt,
            ...(args.model ? { model: args.model } : {}),
            ...(args.maxTokens ? { options: { num_predict: args.maxTokens } } : {}),
          }),
      },
      {
        name: "prism_run_batch",
        description:
          "Run many independent prompts in one paid call, spread across every GPU Prism currently holds. " +
          "Use this instead of calling prism_run_inference in a loop whenever you have more than one prompt: " +
          "it finishes faster and settles as one payment instead of many. Inputs: prompts (required), model, " +
          "maxTokens per prompt. The price scales with the cap and the number of prompts. The response carries " +
          "a Merkle receipt over the whole set, so every answer comes with its own commitment hash and an audit " +
          "path that checks against the batch root without revealing the others.",
        schema: batchArgs,
        invoke: (args) =>
          this.#pay(walletProvider, "/inference/v1/batch", {
            prompts: args.prompts,
            ...(args.model ? { model: args.model } : {}),
            ...(args.maxTokens ? { options: { num_predict: args.maxTokens } } : {}),
          }),
      },
      {
        name: "prism_run_gpu_command",
        description:
          "Lease a GPU and run one shell command on it, for example 'nvidia-smi' or a short benchmark. " +
          "Costs a fixed 0.03 USDC on Base. The command is queued, so this returns a job id and a token: " +
          "pass both to prism_get_gpu_job to read the output. Payment is only taken once the job has " +
          "succeeded, so a job that fails costs nothing. For plain text generation prism_run_inference " +
          "is cheaper and answers directly.",
        schema: commandArgs,
        invoke: (args) => this.#pay(walletProvider, "/x402/run", { command: args.command }),
      },
      {
        name: "prism_get_gpu_job",
        description:
          "Read the status and output of a GPU command started with prism_run_gpu_command. Free; the " +
          "command was already paid for. A job moves through queued and running before it finishes, so " +
          "wait a few seconds between polls.",
        schema: jobArgs,
        invoke: async (args) => {
          try {
            const response = await fetch(
              `${this.#apiBase}/x402/jobs/${encodeURIComponent(args.jobId)}`,
              { headers: { authorization: `Bearer ${args.token}` } },
            );
            const payload = await readJson(response);
            if (!response.ok) {
              return `Prism answered ${response.status} for job ${args.jobId}: ${JSON.stringify(payload)}`;
            }
            return JSON.stringify(payload);
          } catch (error) {
            return `Error reading Prism job ${args.jobId}: ${describe(error)}`;
          }
        },
      },
    ];
  }

  async #pay(walletProvider, path, body) {
    try {
      const pay = wrapFetchWithPayment(fetch, this.#client(walletProvider));
      const response = await pay(`${this.#apiBase}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });

      const payload = await readJson(response);

      // A cold pool is not a failure and is not billed. Saying so plainly stops
      // an agent retrying in a tight loop or reporting an outage to its user.
      if (response.status === 503) {
        return JSON.stringify({
          charged: false,
          retryAfterSeconds: payload.retry_after_seconds ?? null,
          detail: payload.detail ?? "No GPU is warm yet. Nothing was charged; try again shortly.",
        });
      }

      if (!response.ok) {
        return `Prism answered ${response.status} for ${path}: ${JSON.stringify(payload)}`;
      }

      const settlement =
        response.headers.get("payment-response") ?? response.headers.get("x-payment-response");
      return JSON.stringify({
        ...payload,
        settlement: settlement ? decodePaymentResponseHeader(settlement) : null,
      });
    } catch (error) {
      return `Error calling Prism ${path}: ${describe(error)}`;
    }
  }

  #client(walletProvider) {
    const account = walletProvider.toSigner();
    const signer = {
      ...account,
      readContract: (args) => walletProvider.readContract(args),
    };

    const client = new x402Client();
    client.registerPolicy(this.#spendCap());
    registerExactEvmScheme(client, { signer });
    return client;
  }

  // Prism prices by the token cap requested, so a large cap on a large batch is
  // the one way an agent can spend more than it meant to. Dropping the option
  // here means the wallet is never asked to sign it in the first place.
  #spendCap() {
    const cap = this.#maxPaymentAtomic;
    return (_version, requirements) =>
      requirements.filter((requirement) => {
        const raw = requirement.amount ?? requirement.maxAmountRequired;
        if (raw === undefined) return false;
        try {
          return BigInt(raw) <= cap;
        } catch {
          return false;
        }
      });
  }

  // The cap is a private closure; tests need a handle on it without reaching
  // through the x402 client.
  _spendCapForTest() {
    return this.#spendCap();
  }
}

export function prismX402ActionProvider(config) {
  return new PrismX402ActionProvider(config);
}
