// The discovery document agents read to find out what this origin sells.
//
// Built rather than checked in, so the prices in it are the prices the 402 will
// actually quote. A static file drifts the first time pricing changes, and the
// scanners treat runtime 402 behaviour as authoritative, so a document that
// disagrees with the endpoint is worse than no document.
//
// Prices here are decimal USD; the runtime 402 carries token atomic units. Both
// stablecoins are six decimals, so the conversion is a divide by 1e6.

import { jobInput, jobOutput } from "@prismnetwork/x402/schemas";

const usd = (micros) => (Number(micros) / 1e6).toFixed(6);

export const inferenceInput = (models) => ({
  type: "object",
  properties: {
    model: { type: "string", enum: models, description: "Which model answers." },
    prompt: { type: "string", minLength: 1, description: "The prompt, up to 32 KiB." },
    options: {
      type: "object",
      description: "Generation options. The price scales with the output cap.",
      properties: {
        num_predict: {
          type: "integer",
          minimum: 1,
          maximum: 1024,
          description: "Maximum output tokens. Lower is cheaper.",
        },
      },
    },
  },
  required: ["model", "prompt"],
});

export const inferenceOutput = {
  type: "object",
  properties: {
    model: { type: "string" },
    response: { type: "string", description: "The generated text." },
    usage: {
      type: "object",
      properties: {
        prompt_tokens: { type: ["integer", "null"] },
        completion_tokens: { type: ["integer", "null"] },
        duration_ms: { type: ["integer", "null"] },
      },
    },
    lease_id: { type: ["integer", "null"], description: "The GPU lease that served it." },
  },
  required: ["model", "response"],
};


export function openApiDocument({ models, pricing, jobPriceMicros, contactEmail, siteUrl }) {
  const perModel = Object.entries(pricing)
    .map(([model, p]) => `${model} at $${usd(p.full_cap_micros)} for a full 1024-token answer`)
    .join(", ");

  return {
    openapi: "3.1.0",
    info: {
      title: "Prism Network",
      version: "1.0.0",
      description:
        "GPU compute and LLM inference, paid per request in USDC on Base or USDG on Robinhood Chain. " +
        "Every GPU lease underneath settles onchain with a public receipt.",
      "x-guidance":
        "Two things are for sale here. POST /inference/v1/inference runs one LLM generation on a " +
        `rented GPU and is the cheaper, faster choice for text: ${perModel}, and the price scales ` +
        "down with the output cap you ask for in options.num_predict. POST /x402/run rents a whole " +
        "GPU for one shell command and returns its output, which is what you want for anything that " +
        "is not a chat completion. Both answer an unpaid request with 402 and the exact price on " +
        "every network they accept. Pay in USDC on Base by signing an EIP-3009 authorization: you " +
        "need no gas, and nothing is charged unless the work succeeds. GET /inference/v1/models " +
        "lists models and current pricing for free.",
      contact: { email: contactEmail },
      license: { name: "Apache-2.0", url: "https://www.apache.org/licenses/LICENSE-2.0" },
    },
    servers: [{ url: siteUrl, description: "Prism Network production" }],
    paths: {
      "/inference/v1/inference": {
        post: {
          operationId: "generate",
          summary: "One LLM generation on a rented GPU",
          description:
            "Runs a single completion on a warm GPU lease. The price is the model's base plus its " +
            "per-token rate over the output cap requested, and an unpaid request quotes the exact " +
            "figure. Nothing is charged unless a generation is returned.",
          tags: ["Inference"],
          "x-payment-info": {
            price: {
              mode: "dynamic",
              currency: "USD",
              min: usd(Math.min(...Object.values(pricing).map((p) => Number(p.base_micros)))),
              max: usd(Math.max(...Object.values(pricing).map((p) => Number(p.full_cap_micros)))),
            },
            protocols: [{ x402: {} }],
          },
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: inferenceInput(models),
                example: { model: models[0], prompt: "Explain metered GPU compute in one sentence.", options: { num_predict: 64 } },
              },
            },
          },
          responses: {
            200: {
              description: "The generation, with token usage and the lease that served it.",
              content: {
                "application/json": {
                  schema: inferenceOutput,
                },
              },
            },
            402: { description: "Payment Required" },
            503: { description: "No GPU is warm yet. Retry after the seconds given; nothing was charged." },
          },
        },
      },
      "/inference/v1/models": {
        get: {
          operationId: "listModels",
          summary: "Models and current pricing",
          description: "What can be asked for and what each costs. Free.",
          tags: ["Inference"],
          // An empty security list is how a free route says so. Without it the
          // scanners probe this for a payment challenge, get a plain 200, and
          // report the whole origin as having an endpoint that failed to
          // register.
          security: [],
          responses: {
            200: {
              description: "Models, per-model pricing in token atomic units, and the gateway state.",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      models: { type: "array", items: { type: "string" } },
                      price_micros: { type: "string", description: "The highest full-cap price." },
                      pay_to: { type: "string" },
                      state: { type: "string", enum: ["cold", "warming", "warm"] },
                    },
                    required: ["models", "price_micros"],
                  },
                },
              },
            },
          },
        },
      },
      "/x402/run": {
        post: {
          operationId: "runOnGpu",
          summary: "Run one shell command on a rented GPU",
          description:
            "Leases a GPU, runs the command, returns a job id to poll. The payment is only taken " +
            "once the job has succeeded, so a failed job costs nothing and needs no refund.",
          tags: ["Compute"],
          "x-payment-info": {
            price: { mode: "fixed", currency: "USD", amount: usd(jobPriceMicros) },
            protocols: [{ x402: {} }],
          },
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: jobInput,
                example: { command: "nvidia-smi" },
              },
            },
          },
          responses: {
            202: {
              description: "Queued. Poll the job with its token.",
              content: {
                "application/json": {
                  schema: jobOutput,
                },
              },
            },
            402: { description: "Payment Required" },
          },
        },
      },
    },
  };
}
