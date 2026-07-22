#!/usr/bin/env node
// Prism x402 one-shot compute: pay-per-job GPU execution over HTTP 402.
// POST /run with no payment -> 402 + payment requirements. Pay USDG on Robinhood
// Chain to payTo, sign the tx hash to prove you sent it, retry with
// X-PAYMENT: base64({txHash, signature}), get a job_id + token, poll GET /jobs/{id}.
import { randomUUID } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createPublicClient, getAddress, http, recoverMessageAddress } from "viem";
import { DEFAULT_IMAGE, PrismAgent, robinhoodChain, USDG } from "@prism-network/agent-sdk";

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const CONFIRMATIONS = 12;
const MAX_BODY_BYTES = 16 * 1_024;
const JOB_RETENTION_MS = 60 * 60 * 1_000;

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

let agent;
let publicClient;
let config;
try {
  config = {
    port: Number(process.env.X402_PORT ?? 8402),
    priceMicros: BigInt(process.env.X402_PRICE_MICROS ?? "300000"),
    payTo: getAddress(requireEnv("X402_PAY_TO")),
    durationSeconds: Number(process.env.X402_DURATION_SECONDS ?? 900),
    minVramMib: Number(process.env.X402_MIN_VRAM_MIB ?? 16000),
    paymentsFile: process.env.X402_PAYMENTS_FILE ?? "./x402-consumed.log",
  };
  agent = new PrismAgent({
    privateKey: requireEnv("PRISM_AGENT_KEY"),
    escrow: requireEnv("PRISM_ESCROW"),
    apiBase: process.env.PRISM_API_BASE ?? "https://prismnetwork.tech",
    rpcUrl: process.env.PRISM_RPC_URL,
  });
  publicClient = createPublicClient({ chain: robinhoodChain, transport: http(process.env.PRISM_RPC_URL) });
} catch (err) {
  console.error(`x402 config error: ${err.message}. Set PRISM_AGENT_KEY, PRISM_ESCROW, and X402_PAY_TO.`);
  process.exit(1);
}

const jobs = new Map();
const consumed = loadConsumed(config.paymentsFile);

function loadConsumed(file) {
  const set = new Set();
  if (existsSync(file)) {
    for (const line of readFileSync(file, "utf8").split("\n")) {
      const h = line.trim().toLowerCase();
      if (h) set.add(h);
    }
  }
  return set;
}

// Reserve synchronously before any await so two concurrent requests with the
// same tx hash can't both pass. Persisted only after the payment fully verifies.
function reservePayment(txHash) {
  const h = txHash.toLowerCase();
  if (consumed.has(h)) return false;
  consumed.add(h);
  return true;
}
function commitPayment(txHash) {
  try {
    appendFileSync(config.paymentsFile, `${txHash.toLowerCase()}\n`);
  } catch (err) {
    console.error(`failed to persist consumed payment: ${err.message}`);
  }
}
function releasePayment(txHash) {
  consumed.delete(txHash.toLowerCase());
}

function paymentRequirements(resource) {
  return {
    x402Version: 1,
    accepts: [{
      scheme: "exact",
      network: `eip155:${robinhoodChain.id}`,
      asset: USDG,
      payTo: config.payTo,
      maxAmountRequired: config.priceMicros.toString(),
      resource,
      description:
        "One GPU job. Pay maxAmountRequired USDG to payTo, then retry with header " +
        "X-PAYMENT: base64({txHash, signature}) where signature is a personal_sign of the tx hash.",
      mimeType: "application/json",
    }],
  };
}

function decodeTransfer(log) {
  if (log.topics[0] !== TRANSFER_TOPIC || log.topics.length < 3) return null;
  return {
    from: `0x${log.topics[1].slice(26)}`,
    to: `0x${log.topics[2].slice(26)}`,
    value: BigInt(log.data),
  };
}

// Verify an on-chain USDG payment bound to the caller: the caller signs the tx
// hash, and the Transfer's `from` must match that signer. This stops a front-runner
// from claiming someone else's payment tx hash.
async function verifyPayment(header) {
  let txHash;
  let signature;
  try {
    ({ txHash, signature } = JSON.parse(Buffer.from(header, "base64").toString("utf8")));
  } catch {
    return { ok: false, reason: "malformed_payment" };
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(txHash ?? "") || typeof signature !== "string") {
    return { ok: false, reason: "malformed_payment" };
  }
  if (!reservePayment(txHash)) return { ok: false, reason: "payment_reused" };
  try {
    let signer;
    try {
      signer = await recoverMessageAddress({ message: txHash, signature });
    } catch {
      releasePayment(txHash);
      return { ok: false, reason: "bad_signature" };
    }
    let receipt;
    try {
      receipt = await publicClient.getTransactionReceipt({ hash: txHash });
    } catch {
      releasePayment(txHash);
      return { ok: false, reason: "tx_not_found" };
    }
    if (receipt.status !== "success") {
      releasePayment(txHash);
      return { ok: false, reason: "tx_reverted" };
    }
    const head = await publicClient.getBlockNumber();
    if (head - receipt.blockNumber < BigInt(CONFIRMATIONS)) {
      releasePayment(txHash);
      return { ok: false, reason: "insufficient_confirmations" };
    }
    const paid = receipt.logs.some((log) => {
      if (log.address.toLowerCase() !== USDG.toLowerCase()) return false;
      const t = decodeTransfer(log);
      return (
        t &&
        t.to.toLowerCase() === config.payTo.toLowerCase() &&
        t.from.toLowerCase() === signer.toLowerCase() &&
        t.value >= config.priceMicros
      );
    });
    if (!paid) {
      releasePayment(txHash);
      return { ok: false, reason: "no_matching_payment" };
    }
    commitPayment(txHash);
    return { ok: true, payer: getAddress(signer) };
  } catch (err) {
    releasePayment(txHash);
    console.error(`payment verification error: ${err.message}`);
    return { ok: false, reason: "verification_error" };
  }
}

async function runJob(jobId, command, payer) {
  const record = jobs.get(jobId);
  let lease;
  try {
    record.status = "running";
    lease = await agent.lease({
      image: DEFAULT_IMAGE,
      durationSeconds: config.durationSeconds,
      minVramMib: config.minVramMib,
      maxDeposit: config.priceMicros,
    });
    record.lease_id = lease.leaseId;
    const out = await agent.run(lease, command);
    record.status = "completed";
    record.exit_code = out.code;
    record.stdout = out.stdout;
    record.stderr = out.stderr;
  } catch (err) {
    record.status = "failed";
    record.error = String(err.code ?? err.message ?? err);
    try {
      record.refund = await agent.transferUsdg(payer, config.priceMicros);
    } catch (refundErr) {
      record.refund_error = String(refundErr.message ?? refundErr);
    }
  } finally {
    if (lease) agent.endLease(lease);
    record.finished_at = Date.now();
  }
}

function evictExpiredJobs() {
  const cutoff = Date.now() - JOB_RETENTION_MS;
  for (const [id, job] of jobs) {
    if (job.finished_at && job.finished_at < cutoff) jobs.delete(id);
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${config.port}`);
  if (req.method === "GET" && url.pathname === "/healthz") return json(res, 200, { status: "ok" });

  if (req.method === "GET" && url.pathname.startsWith("/jobs/")) {
    const job = jobs.get(url.pathname.slice(6));
    if (!job) return json(res, 404, { error: "job_not_found" });
    const token = bearer(req) ?? url.searchParams.get("token");
    if (token !== job.token) return json(res, 401, { error: "invalid_job_token" });
    const { token: _t, ...view } = job;
    return json(res, 200, view);
  }

  if (req.method === "POST" && url.pathname === "/run") {
    let body;
    try {
      body = await readJson(req);
    } catch (err) {
      return json(res, err.code === "too_large" ? 413 : 400, { error: err.code ?? "invalid_json" });
    }
    if (!body?.command || typeof body.command !== "string") return json(res, 400, { error: "command_required" });
    const payment = req.headers["x-payment"];
    if (!payment) return json(res, 402, paymentRequirements("/run"));
    const check = await verifyPayment(String(payment));
    if (!check.ok) return json(res, 402, { ...paymentRequirements("/run"), error: check.reason });

    evictExpiredJobs();
    const jobId = randomUUID();
    const token = randomUUID();
    jobs.set(jobId, { job_id: jobId, status: "queued", token, payer: check.payer });
    runJob(jobId, body.command, check.payer);
    return json(res, 202, { job_id: jobId, status: "queued", token, poll: `/jobs/${jobId}` });
  }

  json(res, 404, { error: "not_found" });
});

function bearer(req) {
  const h = req.headers.authorization;
  return h?.toLowerCase().startsWith("bearer ") ? h.slice(7).trim() : null;
}

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

server.listen(config.port, () =>
  console.error(`prism x402 server on :${config.port}, price ${config.priceMicros} micros -> ${config.payTo}`),
);
