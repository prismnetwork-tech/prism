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
import { createGateway } from "./gateway.mjs";

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
    payTo: getAddress(requireEnv("INFERENCE_PAY_TO")),
    durationSeconds: Number(process.env.INFERENCE_WARM_SECONDS ?? 1800),
    minVramMib: Number(process.env.INFERENCE_MIN_VRAM_MIB ?? 16000),
    idleMs: Number(process.env.INFERENCE_IDLE_SECONDS ?? 600) * 1000,
    tunnelPort: Number(process.env.INFERENCE_TUNNEL_PORT ?? 11435),
    paymentsFile: process.env.INFERENCE_PAYMENTS_FILE ?? "./inference-consumed.log",
  };
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

const gateway = createGateway({
  agent,
  models: config.models,
  payTo: config.payTo,
  priceMicros: config.priceMicros,
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
  if (req.method === "POST" && url.pathname === "/v1/warm") {
    gateway.ensureWarm().catch((err) => console.error(`warmup failed: ${err.message}`));
    return json(res, 202, gateway.state());
  }
  if (req.method === "POST" && url.pathname === "/v1/inference") {
    let body;
    try {
      body = await readJson(req);
    } catch (err) {
      return json(res, err.code === "too_large" ? 413 : 400, { error: err.code ?? "invalid_json" });
    }
    const out = await gateway.handleInference(body, req.headers["x-payment"]);
    return json(res, out.status, out.body);
  }
  json(res, 404, { error: "not_found" });
});

function json(res, status, obj) {
  const payload = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(payload) });
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
