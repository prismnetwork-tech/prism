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
import { createPublicClient, getAddress, http, recoverMessageAddress } from "viem";
import { DEFAULT_IMAGE, PrismAgent, robinhoodChain, USDG } from "@prismnetwork/agent-sdk";
import { createExactEvm } from "@prismnetwork/x402/exact-evm";
import { createCdpFacilitator, routeByNetwork } from "@prismnetwork/x402/cdp-facilitator";
import { bazaar, detect } from "@prismnetwork/x402/codec";
import { base as baseChain } from "viem/chains";
import { createGateway, USDC_BASE, USDC_BASE_DOMAIN, USDG_ROBINHOOD_DOMAIN } from "./gateway.mjs";
import { inferenceExample, inferenceInput, inferenceInputExample, inferenceOutput, openApiDocument } from "./openapi.mjs";

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const CONFIRMATIONS = 12;
const MAX_BODY_BYTES = 64 * 1024;

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

let config;
let agent;
try {
  config = {
    port: Number(process.env.INFERENCE_PORT ?? 8500),
    models: (process.env.INFERENCE_MODELS ?? "llama3.2:3b").split(",").map((m) => m.trim()).filter(Boolean),
    priceMicros: BigInt(process.env.INFERENCE_PRICE_MICROS ?? "10000"),
    pricing: process.env.INFERENCE_PRICING ? JSON.parse(process.env.INFERENCE_PRICING) : null,
    payTo: getAddress(requireEnv("INFERENCE_PAY_TO")),
    durationSeconds: Number(process.env.INFERENCE_WARM_SECONDS ?? 1800),
    minVramMib: Number(process.env.INFERENCE_MIN_VRAM_MIB ?? 16000),
    idleMs: Number(process.env.INFERENCE_IDLE_SECONDS ?? 600) * 1000,
    tunnelPort: Number(process.env.INFERENCE_TUNNEL_PORT ?? 11435),
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
function spawnTunnel(lease) {
  const child = spawn("ssh", [
    "-i", lease.keyPath,
    "-p", String(lease.access.ssh_port),
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
    "-o", "ServerAliveInterval=15",
    "-o", "ExitOnForwardFailure=yes",
    "-N",
    "-L", `127.0.0.1:${config.tunnelPort}:127.0.0.1:11434`,
    `${lease.access.ssh_user ?? "root"}@${lease.access.ssh_host}`,
  ]);
  child.on("error", (err) => console.error(`tunnel error: ${err.message}`));
  return { close: () => child.kill("SIGTERM") };
}

const fetchOllama = (path, init) => fetch(`http://127.0.0.1:${config.tunnelPort}${path}`, init);

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
  priceMicros: config.priceMicros,
  pricing: config.pricing,
  image: process.env.PRISM_DEFAULT_IMAGE ?? DEFAULT_IMAGE,
  durationSeconds: config.durationSeconds,
  minVramMib: config.minVramMib,
  idleMs: config.idleMs,
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
    return json(res, 200, {
      x402Version: 1,
      name: "Prism Network managed inference",
      description:
        "Pay-per-generation LLM inference on rented GPUs. Pay in USDC on Base or USDG on Robinhood " +
        "Chain; an unpaid request answers 402 with the exact price on each. The serving lease " +
        "settles onchain with a public receipt.",
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
          path: "/inference/v1/models",
          method: "GET",
          description: "Models, per-model pricing, and the gateway's current state. Free.",
          price: "free",
        },
      ],
    });
  }
  if (req.method === "POST" && url.pathname === "/v1/warm") {
    gateway.ensureWarm().catch((err) => console.error(`warmup failed: ${err.message}`));
    return json(res, 202, gateway.state());
  }
  // Discovery probes come in on GET, and an endpoint that answers 404 to one
  // reads as broken rather than as paid. A GET never runs a generation whatever
  // it carries, because a safe method must stay safe; it only quotes.
  if (req.method === "GET" && url.pathname === "/v1/inference") {
    const out = await gateway.handleInference({}, undefined, detect(req.headers)?.version ?? 2);
    return json(res, out.status, out.body, out.headers);
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

function json(res, status, obj, extra = {}) {
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
    ...extra,
  });
  res.end(payload);
}

async function readJson(req) {
  if (Number(req.headers["content-length"] ?? "0") > MAX_BODY_BYTES) {
    throw Object.assign(new Error("body too large"), { code: "too_large" });
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      req.destroy();
      throw Object.assign(new Error("body too large"), { code: "too_large" });
    }
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString());
  } catch {
    throw Object.assign(new Error("invalid json"), { code: "invalid_json" });
  }
}

// A cold-start request legitimately holds through minutes of provisioning.
server.requestTimeout = 600_000;
server.headersTimeout = 620_000;

server.listen(config.port, () =>
  console.error(
    `prism inference gateway on :${config.port}, models ${config.models.join(", ")}, ` +
      `${config.priceMicros} micros per generation to ${config.payTo}`,
  ),
);
