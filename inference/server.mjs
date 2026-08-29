#!/usr/bin/env node
// Prism managed inference: a warm GPU lease running ollama behind an x402-paid
// HTTP surface. POST /v1/inference with no payment answers 402 with the USDG
// price; pay it on Robinhood Chain, sign the tx hash, retry with
// X-PAYMENT: base64({txHash, signature}), get the generation back.
//
// The gateway leases from the network like any other renter: it holds the
// operator's own funded wallet, pays per second into the same escrow, and its
// leases settle with the same public receipts.
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createPublicClient, getAddress, http, recoverMessageAddress } from "viem";
import { DEFAULT_IMAGE, PrismAgent, robinhoodChain, USDG } from "@prismnetwork/agent-sdk";
import { createExactEvm } from "@prismnetwork/x402/exact-evm";
import { createCdpFacilitator, routeByNetwork } from "@prismnetwork/x402/cdp-facilitator";
import { bazaar, detect } from "@prismnetwork/x402/codec";
import { base as baseChain } from "viem/chains";
import {
  createGateway,
  MAX_CONFIDENTIAL_BODY_BYTES,
  USDC_BASE,
  USDC_BASE_DOMAIN,
  USDG_ROBINHOOD_DOMAIN,
} from "./gateway.mjs";
import {
  batchExample,
  batchInput,
  batchInputExample,
  batchOutput,
  inferenceExample,
  inferenceInput,
  inferenceInputExample,
  inferenceOutput,
  openApiDocument,
} from "./openapi.mjs";
import { providerModels } from "./provider.mjs";

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const CONFIRMATIONS = 12;
const MAX_BODY_BYTES = 64 * 1024;
// A batch carries one prompt per item, so it needs room the single endpoint
// never does. Still bounded by the per-prompt and per-batch limits below it.
const MAX_BATCH_BODY_BYTES = 2 * 1024 * 1024;

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

// The confidential class is off unless an operator configures it. The upstream
// key is named by the config and read here; it never leaves this process, and
// nothing downstream of `createGateway` puts it in a response or a log line.
function confidentialConfig() {
  if (!process.env.INFERENCE_CONFIDENTIAL) return null;
  const cfg = JSON.parse(process.env.INFERENCE_CONFIDENTIAL);
  const keyEnv = cfg.key_env ?? "PHALA_API_KEY";
  const key = process.env[keyEnv];
  if (!key) throw new Error(`INFERENCE_CONFIDENTIAL names ${keyEnv} for its upstream key, but ${keyEnv} is not set`);
  return {
    upstream: cfg.upstream,
    legacyUpstream: cfg.legacy_upstream,
    key,
    dailyUsd: Number(process.env.INFERENCE_CONFIDENTIAL_DAILY_USD ?? cfg.daily_usd ?? 1),
    models: cfg.models,
  };
}

let config;
let agent;
try {
  config = {
    port: Number(process.env.INFERENCE_PORT ?? 8500),
    models: (process.env.INFERENCE_MODELS ?? "llama3.2:3b").split(",").map((m) => m.trim()).filter(Boolean),
    // Unset leaves the shipped rate card in place. Defaulting it here would
    // overwrite every model's base with the same number and quietly undo it.
    priceMicros: process.env.INFERENCE_PRICE_MICROS ? BigInt(process.env.INFERENCE_PRICE_MICROS) : null,
    pricing: process.env.INFERENCE_PRICING ? JSON.parse(process.env.INFERENCE_PRICING) : null,
    confidential: confidentialConfig(),
    payTo: getAddress(requireEnv("INFERENCE_PAY_TO")),
    durationSeconds: Number(process.env.INFERENCE_WARM_SECONDS ?? 1800),
    minVramMib: Number(process.env.INFERENCE_MIN_VRAM_MIB ?? 16000),
    idleMs: Number(process.env.INFERENCE_IDLE_SECONDS ?? 600) * 1000,
    tunnelPort: Number(process.env.INFERENCE_TUNNEL_PORT ?? 11435),
    // Every extra box in the pool is another prepaid lease running whether or
    // not anything asks for it, so the default is one and growing it is a
    // deliberate choice.
    poolMax: Number(process.env.INFERENCE_POOL_MAX ?? 1),
    maxBatchItems: Number(process.env.INFERENCE_BATCH_MAX_ITEMS ?? 64),
    itemsPerBox: Number(process.env.INFERENCE_BATCH_ITEMS_PER_BOX ?? 25),
    paymentsFile: process.env.INFERENCE_PAYMENTS_FILE ?? "./inference-consumed.log",
    // Base is offered only when there is somewhere to collect it. Omitting the
    // address leaves the endpoint exactly as it was.
    basePayTo: process.env.X402_BASE_PAY_TO ? getAddress(process.env.X402_BASE_PAY_TO) : null,
    // A list, tried in order, because money should not stop moving because one
    // free endpoint had a bad minute, and each of these has had one. Not
    // mainnet.base.org: a verification is four calls and it rate-limits a burst
    // that size. Not publicnode first either: it broadcasts fine but refuses to
    // read the receipt back.
    baseRpcUrl: (process.env.X402_BASE_RPC_URL ?? "https://base.drpc.org,https://1rpc.io/base")
      .split(",").map((u) => u.trim()).filter(Boolean),
  };
  if (config.basePayTo && !process.env.PRISM_X402_COLLECTOR_KEY) {
    throw new Error("X402_BASE_PAY_TO is set but PRISM_X402_COLLECTOR_KEY is not, so nothing can broadcast an authorization");
  }
  agent = new PrismAgent({
    privateKey: requireEnv("PRISM_AGENT_KEY"),
    escrow: requireEnv("PRISM_ESCROW"),
    apiBase: process.env.PRISM_API_BASE ?? "https://prismnetwork.tech",
    rpcUrl: process.env.PRISM_RPC_URL,
  });
} catch (err) {
  console.error(`inference config error: ${err.message}. Set PRISM_AGENT_KEY, PRISM_ESCROW, and INFERENCE_PAY_TO.`);
  process.exit(1);
}

const chain = createPublicClient({ chain: robinhoodChain, transport: http(process.env.PRISM_RPC_URL) });

function decodeTransfer(log) {
  if (log.topics[0] !== TRANSFER_TOPIC || log.topics.length < 3) return null;
  return { from: `0x${log.topics[1].slice(26)}`, to: `0x${log.topics[2].slice(26)}`, value: BigInt(log.data) };
}

// The caller signs the tx hash, and the Transfer's `from` must match that
// signer, so a front-runner cannot claim someone else's payment.
async function verify(txHash, signature, priceMicros) {
  let signer;
  try {
    signer = await recoverMessageAddress({ message: txHash, signature });
  } catch {
    return { ok: false, reason: "bad_signature" };
  }
  let receipt;
  try {
    receipt = await chain.getTransactionReceipt({ hash: txHash });
  } catch {
    return { ok: false, reason: "tx_not_found" };
  }
  if (receipt.status !== "success") return { ok: false, reason: "tx_reverted" };
  const head = await chain.getBlockNumber();
  if (head - receipt.blockNumber < BigInt(CONFIRMATIONS)) {
    return { ok: false, reason: "insufficient_confirmations" };
  }
  const paid = receipt.logs.some((log) => {
    if (log.address.toLowerCase() !== USDG.toLowerCase()) return false;
    const t = decodeTransfer(log);
    return (
      t &&
      t.to.toLowerCase() === config.payTo.toLowerCase() &&
      t.from.toLowerCase() === signer.toLowerCase() &&
      t.value >= priceMicros
    );
  });
  return paid ? { ok: true, payer: getAddress(signer) } : { ok: false, reason: "no_matching_payment" };
}

// ssh -N -L keeps the box's ollama reachable only from this process's host.
// The child is restarted by the next warmup rather than in place; a dead
// tunnel surfaces as a failed generation, which does not consume the payment.
function spawnTunnel(lease, slot) {
  const child = spawn("ssh", [
    "-i", lease.keyPath,
    "-p", String(lease.access.ssh_port),
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
    "-o", "ServerAliveInterval=15",
    "-o", "ExitOnForwardFailure=yes",
    "-N",
    "-L", `127.0.0.1:${config.tunnelPort + slot}:127.0.0.1:11434`,
    `${lease.access.ssh_user ?? "root"}@${lease.access.ssh_host}`,
  ]);
  child.on("error", (err) => console.error(`tunnel error: ${err.message}`));
  return { close: () => child.kill("SIGTERM") };
}

const fetchOllama = (slot, path, init) => fetch(`http://127.0.0.1:${config.tunnelPort + slot}${path}`, init);

// Robinhood Chain is always verifiable: the agent key that leases GPUs also
// holds the gas to broadcast an authorization there. Base is offered only when
// there is somewhere to collect it.
const exactNetworks = {
  "eip155:4663": {
    chain: robinhoodChain,
    rpcUrl: process.env.PRISM_RPC_URL,
    privateKey: process.env.PRISM_AGENT_KEY,
    assets: { [USDG]: USDG_ROBINHOOD_DOMAIN },
  },
  ...(config.basePayTo
    ? {
        "eip155:8453": {
          chain: baseChain,
          rpcUrl: config.baseRpcUrl,
          privateKey: process.env.PRISM_X402_COLLECTOR_KEY,
          assets: { [USDC_BASE]: USDC_BASE_DOMAIN },
        },
        base: {
          chain: baseChain,
          rpcUrl: config.baseRpcUrl,
          privateKey: process.env.PRISM_X402_COLLECTOR_KEY,
          assets: { [USDC_BASE]: USDC_BASE_DOMAIN },
        },
      }
    : {}),
};

const localExact = createExactEvm(exactNetworks);

// Base settles at Coinbase when a key is configured, because the Bazaar only
// indexes endpoints its own facilitator has settled for. Everything else, and
// Base itself when no key is set, stays on ours.
const inferenceSchemas = {
  input: inferenceInput(config.models),
  output: inferenceOutput,
  example: inferenceExample,
  inputExample: inferenceInputExample,
  method: "POST",
};

const batchSchemas = {
  input: batchInput(config.models),
  output: batchOutput,
  example: batchExample,
  inputExample: batchInputExample,
  method: "POST",
};

// The confidential route takes and returns the OpenAI chat-completions shape,
// so it describes itself rather than borrowing the ollama schemas.
const confidentialModels = Object.keys(config.confidential?.models ?? {});
const confidentialSchemas = config.confidential
  ? {
      method: "POST",
      input: {
        type: "object",
        required: ["model", "messages", "max_tokens"],
        properties: {
          model: { type: "string", enum: confidentialModels },
          messages: {
            type: "array",
            minItems: 1,
            items: {
              type: "object",
              required: ["role", "content"],
              properties: { role: { type: "string" }, content: { type: "string" } },
            },
          },
          max_tokens: {
            type: "integer",
            minimum: 1,
            maximum: 1024,
            description:
              "Output token cap; the price scales with it. Required, because the body is forwarded unchanged.",
          },
          temperature: { type: "number" },
          stream: {
            type: "boolean",
            description:
              "Return the answer as server-sent events, relayed frame by frame. The receipt covers " +
              "the whole stream, framing included.",
          },
        },
      },
      output: {
        type: "object",
        properties: {
          id: { type: "string" },
          model: { type: "string" },
          choices: {
            type: "array",
            items: {
              type: "object",
              properties: {
                index: { type: "integer" },
                message: {
                  type: "object",
                  properties: { role: { type: "string" }, content: { type: ["string", "null"] } },
                },
                finish_reason: { type: ["string", "null"] },
              },
            },
          },
          usage: {
            type: "object",
            properties: {
              prompt_tokens: { type: "integer" },
              completion_tokens: { type: "integer" },
              total_tokens: { type: "integer" },
            },
          },
        },
        required: ["choices"],
      },
      inputExample: {
        model: confidentialModels[0],
        messages: [{ role: "user", content: "Explain metered GPU compute in one sentence." }],
        max_tokens: 64,
      },
      example: {
        id: "chatcmpl-2f9c",
        model: confidentialModels[0],
        choices: [
          {
            index: 0,
            message: { role: "assistant", content: "Metered GPU compute bills by the second and settles onchain." },
            finish_reason: "stop",
          },
        ],
        usage: { prompt_tokens: 14, completion_tokens: 13, total_tokens: 27 },
      },
    }
  : null;

const cdp = process.env.CDP_API_KEY_ID && process.env.CDP_API_KEY_SECRET
  ? createCdpFacilitator({
      keyId: process.env.CDP_API_KEY_ID,
      keySecret: process.env.CDP_API_KEY_SECRET,
      networks: ["eip155:8453", "base"],
      // The Bazaar builds its entry from what the settle call carries rather
      // than by crawling us afterwards. `outputSchema` on the requirements is
      // the v1 spelling of the same description and rides along already; this
      // adds the v2 one, because indexed entries in the wild use both.
      describe: () => ({
        resource: `${process.env.PRISM_PUBLIC_ORIGIN ?? "https://api.prismnetwork.tech"}/inference/v1/inference`,
        description: "One LLM generation on a rented GPU, priced per request.",
        mimeType: "application/json",
        extensions: bazaar(inferenceSchemas),
      }),
    })
  : null;

const exact = cdp && localExact ? routeByNetwork(cdp, localExact) : localExact;

const gateway = createGateway({
  agent,
  models: config.models,
  payTo: config.payTo,
  basePayTo: config.basePayTo,
  exact,
  schemas: inferenceSchemas,
  batchSchemas,
  confidentialSchemas,
  priceMicros: config.priceMicros,
  pricing: config.pricing,
  confidential: config.confidential,
  image: process.env.PRISM_DEFAULT_IMAGE ?? DEFAULT_IMAGE,
  durationSeconds: config.durationSeconds,
  minVramMib: config.minVramMib,
  idleMs: config.idleMs,
  poolMax: config.poolMax,
  maxBatchItems: config.maxBatchItems,
  itemsPerBox: config.itemsPerBox,
  paymentsFile: config.paymentsFile,
  verify,
  spawnTunnel,
  fetchOllama,
});

setInterval(() => {
  gateway.maintain().catch((err) => console.error(`maintain failed: ${err.message}`));
}, 15_000).unref();

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${config.port}`);
  if (req.method === "GET" && url.pathname === "/healthz") {
    return json(res, 200, { status: "ok", ...gateway.state() });
  }
  if (req.method === "GET" && url.pathname === "/v1/models") {
    return json(res, 200, gateway.models());
  }
  if (req.method === "GET" && url.pathname === "/v1/stats") {
    return json(res, 200, gateway.stats());
  }
  // The confidential tier as an aggregator's provider monitor reads a
  // catalogue. Free, and assembled from live pricing and the live spend cap so
  // it says the same thing the 402 does.
  if (req.method === "GET" && url.pathname === "/v1/provider/models") {
    const catalogue = providerModels({
      confidential: gateway.confidential(),
      dailyUsd: gateway.stats().confidential_daily_cap_usd,
    });
    return json(res, 200, catalogue, { "cache-control": "public, max-age=300" });
  }
  // The canonical discovery contract. Built from live pricing for the same
  // reason as the manifest below: a document that disagrees with the endpoint
  // is worse than no document, because scanners treat the runtime 402 as
  // authoritative and list the mismatch as a failure.
  if (req.method === "GET" && url.pathname === "/openapi.json") {
    const m = gateway.models();
    return json(res, 200, openApiDocument({
      models: m.models,
      pricing: m.pricing,
      jobPriceMicros: Number(process.env.X402_PRICE_MICROS ?? 30000),
      contactEmail: process.env.PRISM_CONTACT_EMAIL ?? "contact@prismnetwork.tech",
      siteUrl: process.env.PRISM_PUBLIC_ORIGIN ?? "https://api.prismnetwork.tech",
    }), { "cache-control": "public, max-age=300" });
  }

  // The x402 discovery manifest indexers crawl. Served here so the prices in
  // it are the prices the 402 will actually quote.
  if (req.method === "GET" && url.pathname === "/.well-known/x402.json") {
    const m = gateway.models();
    const confidential = gateway.confidential();
    return json(res, 200, {
      x402Version: 1,
      name: "Prism Network managed inference",
      description:
        "Pay-per-generation LLM inference on rented GPUs. Pay in USDC on Base or USDG on Robinhood " +
        "Chain; an unpaid request answers 402 with the exact price on each. The serving lease " +
        "settles onchain with a public receipt." +
        (confidential
          ? " A confidential tier serves the same pay-per-request interface from a Phala GPU TEE, " +
            "with a signed receipt over the request and response bytes and optional end-to-end " +
            "encryption between the caller and the enclave."
          : ""),
      image: "https://prismnetwork.tech/brand/prism-mark-400.png",
      endpoints: [
        {
          path: "/inference/v1/inference",
          method: "POST",
          description:
            "One LLM generation. The price is the model's base plus its per-token rate over the " +
            "requested output cap, and the unpaid 402 quotes the exact figure for every network it " +
            "accepts. On Base, sign an EIP-3009 authorization for the quoted USDC amount and send " +
            "it in the payment header; you need no gas, because the authorization is broadcast for " +
            "you, and nothing is taken unless a generation is returned. A payment is consumed only " +
            "when a response is served, and a consumed one replays its own result.",
          price: `up to ${(Number(m.price_micros) / 1e6).toFixed(6)} USDC or USDG per generation, quoted per request`,
          accepts: gateway.requirements().accepts,
          inputSchema: {
            type: "object",
            required: ["model", "prompt"],
            properties: {
              model: { type: "string", enum: m.models },
              prompt: { type: "string", description: "Prompt to generate from (max 32 KiB)." },
              options: {
                type: "object",
                properties: {
                  num_predict: { type: "integer", minimum: 1, maximum: 1024, description: "Output token cap; the price scales with it." },
                },
              },
            },
          },
        },
        {
          path: "/inference/v1/batch",
          method: "POST",
          description:
            "Many independent prompts in one paid call. The price is the single-request price " +
            "times the number of prompts, and the unpaid 402 quotes the exact figure. Each prompt " +
            "runs whole on one rented GPU, and the gateway spreads them over every GPU it holds, " +
            "so a batch finishes in roughly the time the slowest box needs rather than the sum of " +
            "all of them. The response carries a Merkle receipt over the set: each item comes with " +
            "the digests it was committed under and an audit path, so any one answer can be proved " +
            "to belong to the batch without disclosing the others, and the receipt names the leases " +
            "that did the work, which settle on-chain with their own public receipts.",
          price: `the per-generation price times the number of prompts, quoted per request`,
          accepts: gateway.batchRequirements().accepts,
          inputSchema: batchInput(m.models),
        },
        ...(confidential ? confidentialEndpoints(confidential) : []),
        {
          path: "/inference/v1/models",
          method: "GET",
          description: "Models, per-model pricing, and the gateway's current state. Free.",
          price: "free",
        },
      ],
    });
  }
  // `slots` brings the whole pool up before the work arrives. A batch that
  // finds one box warm runs on one box, because a box leased after the prompts
  // are already moving arrives too late to take any of them.
  if (req.method === "POST" && url.pathname === "/v1/warm") {
    const asked = Number(url.searchParams.get("slots") ?? 1);
    const slots = Number.isFinite(asked) && asked > 0 ? Math.floor(asked) : 1;
    gateway.ensureWarm(slots).catch((err) => console.error(`warmup failed: ${err.message}`));
    return json(res, 202, gateway.state());
  }
  // Discovery probes come in on GET, and an endpoint that answers 404 to one
  // reads as broken rather than as paid. A GET never runs a generation whatever
  // it carries, because a safe method must stay safe; it only quotes.
  if (req.method === "GET" && url.pathname === "/v1/inference") {
    const out = await gateway.handleInference({}, undefined, detect(req.headers)?.version ?? 2);
    return json(res, out.status, out.body, out.headers);
  }
  if (req.method === "GET" && url.pathname === "/v1/batch") {
    const out = await gateway.handleBatch({}, undefined, detect(req.headers)?.version ?? 2);
    return json(res, out.status, out.body, out.headers);
  }
  if (req.method === "POST" && url.pathname === "/v1/batch") {
    let body;
    try {
      body = await readJson(req, MAX_BATCH_BODY_BYTES);
    } catch (err) {
      return json(res, err.code === "too_large" ? 413 : 400, { error: err.code ?? "invalid_json" });
    }
    const payment = detect(req.headers);
    const out = await gateway.handleBatch(body, payment?.header, payment?.version ?? null);
    return json(res, out.status, out.body, out.headers);
  }
  // The confidential class. The body goes upstream exactly as it arrived and
  // the response comes back exactly as it left the TEE, because the receipt is
  // signed over both sets of bytes.
  if (req.method === "GET" && url.pathname === "/v1/chat/completions") {
    const out = await gateway.handleConfidential(null, {}, undefined, detect(req.headers)?.version ?? 2);
    return relayed(res, out);
  }
  if (req.method === "POST" && url.pathname === "/v1/chat/completions") {
    let bytes;
    try {
      bytes = await readRaw(req, MAX_CONFIDENTIAL_BODY_BYTES);
    } catch (err) {
      return json(res, err.code === "too_large" ? 413 : 400, { error: err.code ?? "invalid_body" });
    }
    const payment = detect(req.headers);
    const out = await gateway.handleConfidential(bytes, req.headers, payment?.header, payment?.version ?? null);
    return relayed(res, out);
  }
  // The transparency endpoints, free and unauthenticated. Each one is a
  // pass-through: the documents are hashed and signature-checked by the caller,
  // so they are returned as the bytes the TEE served.
  if (req.method === "GET" && url.pathname === "/v1/attestation") {
    return relayed(res, await gateway.attestation(url.searchParams.get("nonce")));
  }
  if (req.method === "GET" && url.pathname === "/v1/gpu-evidence") {
    return relayed(res, await gateway.gpuEvidence(url.searchParams.get("model"), url.searchParams.get("keyset_digest")));
  }
  if (req.method === "GET" && url.pathname === "/v1/sessions") {
    return relayed(res, await gateway.sessions({
      model: url.searchParams.get("model"),
      upstreamName: url.searchParams.get("upstream_name"),
    }));
  }
  if (req.method === "GET" && url.pathname.startsWith("/v1/sessions/")) {
    return relayed(res, await gateway.session(segment(url.pathname, "/v1/sessions/")));
  }
  if (req.method === "GET" && url.pathname.startsWith("/v1/receipts/")) {
    return relayed(res, await gateway.receipt(segment(url.pathname, "/v1/receipts/")));
  }
  if (req.method === "POST" && url.pathname === "/v1/inference") {
    let body;
    try {
      body = await readJson(req);
    } catch (err) {
      return json(res, err.code === "too_large" ? 413 : 400, { error: err.code ?? "invalid_json" });
    }
    // Which version the caller speaks comes from which payment header they
    // sent. An unpaid request has neither, and answering v1 to those keeps
    // the reply readable to anything that just curls the endpoint.
    const payment = detect(req.headers);
    const out = await gateway.handleInference(body, payment?.header, payment?.version ?? null);
    return json(res, out.status, out.body, out.headers);
  }
  json(res, 404, { error: "not_found" });
});

/// The confidential tier's half of the discovery manifest. The free endpoints
/// are listed because they are what a caller needs to check the work: an agent
/// that cannot find the attestation or the receipt has bought an answer it has
/// to take on trust.
function confidentialEndpoints(confidential) {
  return [
    {
      path: "/inference/v1/chat/completions",
      method: "POST",
      description:
        "One chat completion served inside a Phala GPU TEE, in the OpenAI request and response " +
        "shape. The price is the model's base plus its per-token rate over the max_tokens you ask " +
        "for, and the unpaid 402 quotes the exact figure. The gateway forwards your request bytes " +
        "unchanged and returns the upstream bytes unchanged, so the receipt the enclave signs over " +
        "both covers exactly what you sent and exactly what you received; the id to fetch it comes " +
        "back in X-Receipt-Id. Send the five X-E2EE-* headers to encrypt message content to the " +
        "enclave's key, in which case the relay carries ciphertext. Set stream to true for " +
        "server-sent events: frames are relayed as the enclave produces them, the receipt covers " +
        "the whole stream including its framing, and the payment settles after the final frame, so " +
        "a streamed answer carries no PAYMENT-RESPONSE header. A payment is consumed only when a " +
        "complete response is served.",
      price: `up to ${(Number(confidential.price_micros) / 1e6).toFixed(6)} USDC or USDG per generation, quoted per request`,
      accepts: gateway.confidentialRequirements().accepts,
      inputSchema: confidentialSchemas.input,
    },
    {
      path: "/inference/v1/attestation",
      method: "GET",
      description:
        "The TEE's attestation report for a caller-chosen nonce of 64 lowercase hex characters: " +
        "the TDX quote, the measured compose, and the workload keyset the receipt signing keys and " +
        "encryption keys are drawn from. Free.",
      price: "free",
    },
    {
      path: "/inference/v1/receipts/{id}",
      method: "GET",
      description:
        "The signed receipt for one completion, by the id its response carried. It binds the hash " +
        "of the request bytes the enclave received, the hash of the response bytes it returned, and " +
        "the upstream GPU verification outcome. Fetch it promptly; upstream retention is short. Free.",
      price: "free",
    },
    {
      path: "/inference/v1/sessions",
      method: "GET",
      description:
        "The attested upstream sessions currently serving, with the evidence each receipt cites. " +
        "Add {id} to the path for one session's full record. Free.",
      price: "free",
    },
    {
      path: "/inference/v1/gpu-evidence",
      method: "GET",
      description:
        "The GPU attestation evidence for a model, in the shape NVIDIA's remote attestation service " +
        "takes as a request body, so a caller can have the GPU leg verified by NVIDIA directly " +
        "rather than by us. Free.",
      price: "free",
    },
  ];
}

function json(res, status, obj, extra = {}) {
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
    ...extra,
  });
  res.end(payload);
}

/// A relay answer is frames arriving from the enclave, bytes the gateway must
/// not touch, or a refusal it wrote itself.
function relayed(res, out) {
  if (out.stream) return streamed(res, out);
  if (!out.bytes) return json(res, out.status, out.body, out.headers);
  res.writeHead(out.status, {
    "content-type": "application/json",
    ...out.headers,
    "content-length": out.bytes.length,
  });
  res.end(out.bytes);
}

/// Frames go out as they arrive. Nothing here holds one back: no length to
/// buffer towards, and the header that stops the proxy in front of this one
/// collecting the answer and delivering it as a single late chunk. What the
/// caller is timed on is the first token, not the last.
async function streamed(res, out) {
  res.writeHead(out.status, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    "x-accel-buffering": "no",
    ...out.headers,
  });
  try {
    await pipeline(Readable.from(out.stream), res);
  } catch (err) {
    // The caller already holds a 200 and whatever frames landed, so the only
    // thing left to say is that the body is not all there. Ending the
    // connection without its terminating chunk is how HTTP says it.
    console.error(`confidential stream ended early: ${err.message}`);
    res.destroy();
  }
}

function segment(pathname, prefix) {
  const raw = pathname.slice(prefix.length);
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

async function readRaw(req, limit) {
  if (Number(req.headers["content-length"] ?? "0") > limit) {
    throw Object.assign(new Error("body too large"), { code: "too_large" });
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > limit) {
      req.destroy();
      throw Object.assign(new Error("body too large"), { code: "too_large" });
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJson(req, limit = MAX_BODY_BYTES) {
  const bytes = await readRaw(req, limit);
  if (!bytes.length) return {};
  try {
    return JSON.parse(bytes.toString());
  } catch {
    throw Object.assign(new Error("invalid json"), { code: "invalid_json" });
  }
}

// A cold-start request legitimately holds through minutes of provisioning.
server.requestTimeout = 600_000;
server.headersTimeout = 620_000;

// The resolved card, not the env var: what is quoted is what should be logged.
const rates = (pricing) =>
  Object.entries(pricing)
    .map(([m, p]) => `${m} ${p.base_micros}+${p.per_token_micros}/token`)
    .join(", ");
const card = rates(gateway.models().pricing);
const confidentialCard = gateway.confidential();

server.listen(config.port, () => {
  console.error(`prism inference gateway on :${config.port}, ${card} micros to ${config.payTo}`);
  if (confidentialCard) {
    console.error(
      `confidential relay to ${confidentialCard.upstream}: ${rates(confidentialCard.models)} micros, ` +
        `daily cap $${config.confidential.dailyUsd}`,
    );
  }
});
