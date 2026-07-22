#!/usr/bin/env node
// Prism x402 one-shot compute — pay-per-job GPU execution over HTTP 402.
// POST /run with no payment -> 402 + payment requirements. Pay USDG on Robinhood
// Chain to payTo, retry with X-PAYMENT: <txHash>, get a job_id, poll GET /jobs/{id}.
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { createPublicClient, http, parseAbiItem } from "viem";
import { PrismAgent, robinhoodChain, USDG } from "@prism-network/agent-sdk";

const PORT = Number(process.env.X402_PORT ?? 8402);
const PRICE_MICROS = BigInt(process.env.X402_PRICE_MICROS ?? "300000"); // 0.30 USDG / job
const PAY_TO = requireEnv("X402_PAY_TO"); // address that collects payment (funds leases)
const IMAGE = process.env.PRISM_DEFAULT_IMAGE ??
  "docker.io/ollama/ollama@sha256:a61a8fd395dbb931cc8cb1b5da7a2510746575c87113fdc45b647ee59ef7f808";

const agent = new PrismAgent({
  privateKey: requireEnv("PRISM_AGENT_KEY"),
  escrow: requireEnv("PRISM_ESCROW"),
  apiBase: process.env.PRISM_API_BASE ?? "https://prismnetwork.tech",
  rpcUrl: process.env.PRISM_RPC_URL,
});
const publicClient = createPublicClient({ chain: robinhoodChain, transport: http(process.env.PRISM_RPC_URL) });
const transferEvent = parseAbiItem("event Transfer(address indexed from, address indexed to, uint256 value)");

const jobs = new Map();
const consumedPayments = new Set();

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

function paymentRequirements(resource) {
  return {
    x402Version: 1,
    accepts: [{
      scheme: "exact",
      network: `eip155:${robinhoodChain.id}`,
      asset: USDG,
      payTo: PAY_TO,
      maxAmountRequired: PRICE_MICROS.toString(),
      resource,
      description: "One GPU job on Prism Network",
      mimeType: "application/json",
    }],
  };
}

// Verify a USDG payment: receipt succeeded, a Transfer to payTo for >= price, unused.
async function verifyPayment(txHash) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) return { ok: false, reason: "bad_tx_hash" };
  if (consumedPayments.has(txHash.toLowerCase())) return { ok: false, reason: "payment_reused" };
  let receipt;
  try {
    receipt = await publicClient.getTransactionReceipt({ hash: txHash });
  } catch {
    return { ok: false, reason: "tx_not_found" };
  }
  if (receipt.status !== "success") return { ok: false, reason: "tx_reverted" };
  const paid = receipt.logs.some((log) => {
    if (log.address.toLowerCase() !== USDG.toLowerCase()) return false;
    try {
      const parsed = decodeTransfer(log);
      return parsed && parsed.to.toLowerCase() === PAY_TO.toLowerCase() && parsed.value >= PRICE_MICROS;
    } catch {
      return false;
    }
  });
  if (!paid) return { ok: false, reason: "no_matching_payment" };
  consumedPayments.add(txHash.toLowerCase());
  return { ok: true };
}

function decodeTransfer(log) {
  if (log.topics[0] !== "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef") return null;
  const to = `0x${log.topics[2].slice(26)}`;
  const value = BigInt(log.data);
  return { to, value };
}

async function runJob(jobId, command, minVramMib) {
  const record = jobs.get(jobId);
  let lease;
  try {
    lease = await agent.lease({ image: IMAGE, durationSeconds: 900, minVramMib: minVramMib ?? 16000 });
    record.status = "running";
    record.lease_id = lease.leaseId;
    const out = await agent.run(lease, command);
    record.status = "completed";
    record.exit_code = out.code;
    record.stdout = out.stdout;
    record.stderr = out.stderr;
  } catch (err) {
    record.status = "failed";
    record.error = String(err.message ?? err);
  } finally {
    if (lease) agent.endLease(lease);
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method === "GET" && url.pathname.startsWith("/jobs/")) {
    const job = jobs.get(url.pathname.slice(6));
    return job ? json(res, 200, job) : json(res, 404, { error: "job_not_found" });
  }
  if (req.method === "POST" && url.pathname === "/run") {
    const body = await readJson(req).catch(() => null);
    if (!body?.command) return json(res, 400, { error: "command_required" });
    const payment = req.headers["x-payment"];
    if (!payment) return json(res, 402, paymentRequirements("/run"));
    const check = await verifyPayment(String(payment));
    if (!check.ok) return json(res, 402, { ...paymentRequirements("/run"), error: check.reason });
    const jobId = randomUUID();
    jobs.set(jobId, { job_id: jobId, status: "queued", command: body.command });
    runJob(jobId, body.command, body.min_vram_mib);
    return json(res, 202, { job_id: jobId, status: "queued", poll: `/jobs/${jobId}` });
  }
  if (req.method === "GET" && url.pathname === "/healthz") return json(res, 200, { status: "ok" });
  json(res, 404, { error: "not_found" });
});

function json(res, status, obj) {
  const payload = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(payload) });
  res.end(payload);
}
async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
}

server.listen(PORT, () => console.error(`prism x402 server on :${PORT}, price ${PRICE_MICROS} micros -> ${PAY_TO}`));
