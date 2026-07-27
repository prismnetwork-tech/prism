#!/usr/bin/env node
// Prism x402 one-shot compute: pay-per-job GPU execution over HTTP 402.
// POST /run with no payment -> 402 + payment requirements. Pay a stablecoin on
// any offered network to its payTo, sign the tx hash to prove you sent it, retry
// with X-PAYMENT: base64({txHash, signature}), get a job_id + token, poll
// GET /jobs/{id}.
import { randomUUID } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { base } from "viem/chains";
import { createPublicClient, createWalletClient, erc20Abi, getAddress, http, recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { DEFAULT_IMAGE, PrismAgent, robinhoodChain, USDG } from "@prismnetwork/agent-sdk";

const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const CONFIRMATIONS = 12;
// Base finalises in two-second blocks, so twelve of them is twenty-four seconds
// of an agent's time. Fast chains earn a deeper wait, not a shorter one.
const BASE_CONFIRMATIONS = 30;
const MAX_BODY_BYTES = 16 * 1_024;
const JOB_RETENTION_MS = 60 * 60 * 1_000;

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

let agent;
let networks;
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
  // Every x402 client in the wild pays on Base or Solana. A Robinhood Chain
  // endpoint is unpayable by all of them, so the same job is offered on both and
  // the agent picks.
  networks = [
    {
      id: `eip155:${robinhoodChain.id}`,
      label: "USDG on Robinhood Chain",
      asset: USDG,
      payTo: config.payTo,
      confirmations: CONFIRMATIONS,
      client: createPublicClient({ chain: robinhoodChain, transport: http(process.env.PRISM_RPC_URL) }),
      refund: (to, amount) => agent.transferUsdg(to, amount),
    },
  ];
  if (process.env.X402_BASE_PAY_TO) {
    networks.push({
      id: `eip155:${base.id}`,
      label: "USDC on Base",
      asset: USDC_BASE,
      payTo: getAddress(process.env.X402_BASE_PAY_TO),
      confirmations: BASE_CONFIRMATIONS,
      client: createPublicClient({ chain: base, transport: http(process.env.X402_BASE_RPC_URL) }),
      // A payer who sent USDC on Base is owed USDC on Base. The server wallet is
      // the same key on both chains, so it needs a USDC and gas balance here too.
      refund: refundOnBase,
    });
  }
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
// Keyed by network so two chains cannot collide on a hash, however unlikely.
async function refundOnBase(to, amount) {
  const account = privateKeyToAccount(requireEnv("PRISM_AGENT_KEY"));
  const wallet = createWalletClient({ account, chain: base, transport: http(process.env.X402_BASE_RPC_URL) });
  return wallet.writeContract({
    address: USDC_BASE,
    abi: erc20Abi,
    functionName: "transfer",
    args: [to, amount],
  });
}

function paymentKey(networkId, txHash) {
  return `${networkId}:${txHash.toLowerCase()}`;
}
function reservePayment(key) {
  if (consumed.has(key)) return false;
  consumed.add(key);
  return true;
}
function commitPayment(key) {
  try {
    appendFileSync(config.paymentsFile, `${key}\n`);
  } catch (err) {
    console.error(`failed to persist consumed payment: ${err.message}`);
  }
}
function releasePayment(key) {
  consumed.delete(key);
}

function paymentRequirements(resource) {
  return {
    x402Version: 1,
    accepts: networks.map((network) => ({
      scheme: "exact",
      network: network.id,
      asset: network.asset,
      payTo: network.payTo,
      maxAmountRequired: config.priceMicros.toString(),
      resource,
      description:
        `One GPU job, paid in ${network.label}. Pay maxAmountRequired to payTo, then retry with ` +
        "header X-PAYMENT: base64({txHash, signature}) where signature is a personal_sign of the " +
        "tx hash. Include the network you paid on to skip the lookup on the others.",
      mimeType: "application/json",
    })),
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
  let declared;
  try {
    ({ txHash, signature, network: declared } = JSON.parse(Buffer.from(header, "base64").toString("utf8")));
  } catch {
    return { ok: false, reason: "malformed_payment" };
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(txHash ?? "") || typeof signature !== "string") {
    return { ok: false, reason: "malformed_payment" };
  }
  const candidates = declared ? networks.filter((n) => n.id === declared) : networks;
  if (!candidates.length) return { ok: false, reason: "unsupported_network" };

  let signer;
  try {
    signer = await recoverMessageAddress({ message: txHash, signature });
  } catch {
    return { ok: false, reason: "bad_signature" };
  }

  let reason = "tx_not_found";
  for (const network of candidates) {
    const key = paymentKey(network.id, txHash);
    if (!reservePayment(key)) return { ok: false, reason: "payment_reused" };
    const outcome = await settleOn(network, txHash, signer);
    if (outcome.ok) {
      commitPayment(key);
      return { ok: true, payer: getAddress(signer), network: network.id };
    }
    releasePayment(key);
    if (outcome.reason !== "tx_not_found") reason = outcome.reason;
  }
  return { ok: false, reason };
}

// A payment counts when the transaction is final on that network and moved at
// least the price in that network's asset, from the signer, to its payee.
async function settleOn(network, txHash, signer) {
  try {
    let receipt;
    try {
      receipt = await network.client.getTransactionReceipt({ hash: txHash });
    } catch {
      return { ok: false, reason: "tx_not_found" };
    }
    if (receipt.status !== "success") return { ok: false, reason: "tx_reverted" };
    const head = await network.client.getBlockNumber();
    if (head - receipt.blockNumber < BigInt(network.confirmations)) {
      return { ok: false, reason: "insufficient_confirmations" };
    }
    const paid = receipt.logs.some((log) => {
      if (log.address.toLowerCase() !== network.asset.toLowerCase()) return false;
      const t = decodeTransfer(log);
      return (
        t &&
        t.to.toLowerCase() === network.payTo.toLowerCase() &&
        t.from.toLowerCase() === signer.toLowerCase() &&
        t.value >= config.priceMicros
      );
    });
    return paid ? { ok: true } : { ok: false, reason: "no_matching_payment" };
  } catch (err) {
    console.error(`payment verification error on ${network.id}: ${err.message}`);
    return { ok: false, reason: "verification_error" };
  }
}

async function runJob(jobId, command, payer, networkId) {
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
    const network = networks.find((candidate) => candidate.id === networkId);
    try {
      record.refund = await network.refund(payer, config.priceMicros);
    } catch (refundErr) {
      // The debt is real whether or not the transfer went through, so it is
      // recorded on the job rather than swallowed into a log line.
      record.refund_error = String(refundErr.message ?? refundErr);
      record.refund_owed = { to: payer, amount: config.priceMicros.toString(), network: network.id };
      console.error(`refund of ${config.priceMicros} to ${payer} on ${network.id} failed`);
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
    jobs.set(jobId, { job_id: jobId, status: "queued", token, payer: check.payer, network: check.network });
    runJob(jobId, body.command, check.payer, check.network);
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
  console.error(
    `prism x402 server on :${config.port}, price ${config.priceMicros} micros, accepting ` +
      networks.map((network) => `${network.label} -> ${network.payTo}`).join(", "),
  ),
);
