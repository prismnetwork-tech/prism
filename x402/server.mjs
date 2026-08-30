#!/usr/bin/env node
// Prism x402 one-shot compute: pay-per-job GPU execution over HTTP 402, plus
// the facilitator interface for anyone who needs to settle on Base themselves.
//
// POST /run with no payment answers 402 with what it costs on each network.
// On Base you sign an EIP-3009 authorization and need no gas; the job is queued,
// and the authorization is only broadcast once the job has actually succeeded.
// A failed job therefore charges nothing and needs no refund.
//
// /verify, /settle and /supported are the facilitator half: the same verifier,
// offered to other people's endpoints, because the free public ones are
// testnet-only and the one that is not needs an API key.
import { randomUUID } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { base } from "viem/chains";
import { createPublicClient, createWalletClient, erc20Abi, getAddress, http, recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { DEFAULT_IMAGE, PrismAgent, robinhoodChain, USDG } from "@prismnetwork/agent-sdk";
import { jobExample, jobInput, jobInputExample, jobOutput } from "./schemas.mjs";
import { createExactEvm } from "./exact-evm.mjs";
import { createCdpFacilitator, routeByNetwork } from "./cdp-facilitator.mjs";
import { createFacilitator, createBudget } from "./facilitator.mjs";
import { authorized, listener } from "./listen.mjs";
import {
  bazaar,
  boundMessage,
  detect,
  hashRequest,
  parsePayment,
  paymentRequired,
  paymentResponse,
  requirementsFor,
  sameNetwork,
} from "./codec.mjs";

const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
// Base USDC reports this as its EIP-712 domain. The published spec example
// carries the testnet token's "USDC", and the domain feeds the signing hash, so
// copying it signs against nothing.
const USDC_BASE_DOMAIN = { name: "USD Coin", version: "2" };
/// Read off the contract: USDG's `name()` is "Global Dollar" and it exposes no
/// `version()`, so the version was recovered by reproducing the on-chain
/// DOMAIN_SEPARATOR. Signing against a guessed domain produces a well-formed
/// signature the token rejects.
const USDG_ROBINHOOD_DOMAIN = { name: "Global Dollar", version: "1" };

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const CONFIRMATIONS = 12;
// Base finalises in two-second blocks, so twelve of them is twenty-four seconds
// of an agent's time. Fast chains earn a deeper wait, not a shorter one.
const BASE_CONFIRMATIONS = 30;
const MAX_BODY_BYTES = 16 * 1_024;
const JOB_RETENTION_MS = 60 * 60 * 1_000;


/// Warn, loudly, when the endpoint is selling a job for less than the lease it
/// must fund. Not fatal: a rate rise should degrade into a clear message rather
/// than take the service down, and the per-job error names the same two knobs.
async function checkPriceCoversLease({ priceMicros, durationSeconds }) {
  const base = process.env.PRISM_API_BASE ?? "https://prismnetwork.tech";
  const res = await fetch(`${base}/api/offers`, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`offers responded ${res.status}`);
  const body = await res.json();
  const offers = Array.isArray(body) ? body : (body.offers ?? []);
  const rates = offers.map((o) => Number(o.rate_per_second)).filter((r) => Number.isFinite(r) && r > 0);
  if (rates.length === 0) throw new Error("no offers to price against");
  const dearest = Math.max(...rates);
  const needed = BigInt(Math.ceil(dearest * durationSeconds));
  if (needed > priceMicros) {
    console.error(
      `X402_PRICE_MICROS=${priceMicros} cannot fund a ${durationSeconds}s lease: ` +
        `the dearest offer needs ${needed}. Raise the price or lower the duration.`,
    );
  }
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

// Resolved before anything else: a listener that came up on the wrong address
// has already been reachable by the time a later line of config fails.
let listen;
try {
  listen = listener(process.env, "X402");
} catch (err) {
  console.error(`x402 config error: ${err.message}`);
  process.exit(1);
}

let agent;
let networks;
let config;
let facilitator = null;
try {
  config = {
    port: Number(process.env.X402_PORT ?? 8402),
    priceMicros: BigInt(process.env.X402_PRICE_MICROS ?? "300000"),
    payTo: getAddress(requireEnv("X402_PAY_TO")),
    durationSeconds: Number(process.env.X402_DURATION_SECONDS ?? 300),
    minVramMib: Number(process.env.X402_MIN_VRAM_MIB ?? 16000),
    paymentsFile: process.env.X402_PAYMENTS_FILE ?? "./x402-consumed.log",
  };
  agent = new PrismAgent({
    privateKey: requireEnv("PRISM_AGENT_KEY"),
    escrow: requireEnv("PRISM_ESCROW"),
    apiBase: process.env.PRISM_API_BASE ?? "https://prismnetwork.tech",
    rpcUrl: process.env.PRISM_RPC_URL,
  });
  // The price has to cover the deposit the lease needs, or every request fails
  // the same way once the job is already queued. Checked here against the rates
  // actually offered, because the two knobs are set independently and a price
  // that no longer covers the window is invisible until someone tries to buy.
  checkPriceCoversLease(config).catch((err) =>
    console.error(`price check skipped: ${err.message}`),
  );
  // The same job is offered on both rails and the agent picks. Robinhood used to
  // be the one no client would pay, which was our fault rather than theirs: the
  // offer named no EIP-712 domain, so a careful wallet refused it.
  networks = [
    {
      id: `eip155:${robinhoodChain.id}`,
      label: "USDG on Robinhood Chain",
      asset: USDG,
      payTo: config.payTo,
      confirmations: CONFIRMATIONS,
      client: createPublicClient({ chain: robinhoodChain, transport: http(process.env.PRISM_RPC_URL) }),
      // Robinhood was the unpayable rail because the offer carried no EIP-712
      // domain, and a careful client refuses that rather than guess one. USDG
      // implements the same EIP-3009 as USDC, so it is quoted with a domain and
      // an exact-scheme verifier, and a renter pays gaslessly with one
      // signature. The legacy transfer-then-sign flow still works.
      //
      // The domain and the verifier travel together: advertising the domain
      // without something to settle against invites a signature nothing here
      // can honour, which is the failure this whole change exists to remove.
      domain: USDG_ROBINHOOD_DOMAIN,
      exact: createExactEvm({
        [`eip155:${robinhoodChain.id}`]: {
          chain: robinhoodChain,
          // The env var is optional here, as it is for the read client above;
          // without it the chain's own published RPC is used.
          rpcUrl: process.env.PRISM_RPC_URL ?? robinhoodChain.rpcUrls.default.http[0],
          privateKey: requireEnv("PRISM_AGENT_KEY"),
          assets: { [USDG]: USDG_ROBINHOOD_DOMAIN },
        },
      }),
      refund: (to, amount) => agent.transferUsdg(to, amount),
    },
  ];
  if (process.env.X402_BASE_PAY_TO) {
    // A list, tried in order: one free endpoint having a bad minute must not
    // decide whether a payment settles.
    const baseRpc = (process.env.X402_BASE_RPC_URL ?? "https://base.drpc.org,https://1rpc.io/base")
      .split(",").map((u) => u.trim()).filter(Boolean);
    const settlementKey = process.env.PRISM_X402_COLLECTOR_KEY;
    if (!settlementKey) throw new Error("X402_BASE_PAY_TO needs PRISM_X402_COLLECTOR_KEY to broadcast with");
    const assets = { [USDC_BASE]: USDC_BASE_DOMAIN };
    const localBase = createExactEvm({
      [`eip155:${base.id}`]: { chain: base, rpcUrl: baseRpc, privateKey: settlementKey, assets },
      base: { chain: base, rpcUrl: baseRpc, privateKey: settlementKey, assets },
    });
    // Settling Base at Coinbase is what puts this endpoint in the Bazaar: their
    // indexer only sees payments their own facilitator settles. Without this the
    // jobs run, the money moves, and the endpoint stays invisible to every agent
    // searching the catalog. Falls back to settling here when no key is set.
    const cdpBase =
      process.env.CDP_API_KEY_ID && process.env.CDP_API_KEY_SECRET
        ? createCdpFacilitator({
            keyId: process.env.CDP_API_KEY_ID,
            keySecret: process.env.CDP_API_KEY_SECRET,
            networks: [`eip155:${base.id}`, "base"],
            describe: () => ({
              resource: `${process.env.PRISM_PUBLIC_ORIGIN ?? "https://api.prismnetwork.tech/x402"}/run`,
              description: "One shell command on a rented GPU, charged only if it succeeds.",
              mimeType: "application/json",
              extensions: bazaar({
                input: jobInput,
                output: jobOutput,
                example: jobExample,
                inputExample: jobInputExample,
                method: "POST",
              }),
            }),
          })
        : null;
    const exactBase = cdpBase ? routeByNetwork(cdpBase, localBase) : localBase;
    networks.push({
      id: `eip155:${base.id}`,
      label: "USDC on Base",
      asset: USDC_BASE,
      payTo: getAddress(process.env.X402_BASE_PAY_TO),
      confirmations: BASE_CONFIRMATIONS,
      client: createPublicClient({ chain: base, transport: http(baseRpc[0]) }),
      domain: USDC_BASE_DOMAIN,
      exact: exactBase,
      // Only the legacy pay-first scheme can leave a debt. Under the exact
      // scheme nothing is taken until the job succeeds, so there is nothing to
      // give back.
      refund: refundOnBase,
    });
    facilitator = createFacilitator({
      exact: exactBase,
      budget: createBudget({
        dailySettlements: Number(process.env.X402_FACILITATOR_DAILY ?? 2000),
        perPayerPerHour: Number(process.env.X402_FACILITATOR_PER_PAYER ?? 60),
      }),
      log: (line) => console.error(`facilitator: ${line}`),
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

const TX_HASH = /^0x[0-9a-f]{64}$/;

function paymentKey(networkId, txHash) {
  return `${networkId}:${txHash.toLowerCase()}`;
}
function reservePayment(key) {
  if (consumed.has(key)) return false;
  consumed.add(key);
  return true;
}
// The ledger is append-only and read back on restart, so the line is rebuilt
// here from its two parts rather than trusting a string assembled elsewhere.
function commitPayment(networkId, txHash) {
  const hash = String(txHash).toLowerCase();
  if (!TX_HASH.test(hash)) throw new Error("refusing to record a malformed transaction hash");
  const network = networks.find((candidate) => candidate.id === networkId);
  if (!network) throw new Error("refusing to record an unknown network");
  try {
    appendFileSync(config.paymentsFile, `${network.id}:${hash}\n`);
  } catch (err) {
    console.error(`failed to persist consumed payment: ${err.message}`);
  }
}
function releasePayment(key) {
  consumed.delete(key);
}

// A job may run for the whole lease, and the authorization has to stay valid
// until it finishes or there is nothing left to charge against.
const JOB_TIMEOUT_SECONDS = () => config.durationSeconds + 120;

function accepted(resource) {
  // Base first, matching the inference endpoint. Validators read accepts[0] as
  // the headline, and leading with a chain they do not index makes a payable
  // endpoint look unsupported.
  const ordered = [...networks].sort(
    (a, b) => Number(b.id === `eip155:${base.id}`) - Number(a.id === `eip155:${base.id}`),
  );
  return ordered.map((network) => ({
    scheme: "exact",
    network: network.id,
    asset: network.asset,
    payTo: network.payTo,
    amount: config.priceMicros.toString(),
    resource,
    description: network.exact
      ? `One GPU job, paid in ${network.label}. Sign an EIP-3009 transferWithAuthorization for ` +
        "the amount and send it as the payment header; you need no gas. The job is queued " +
        "immediately and the payment is only taken once it has succeeded, so a failed job " +
        `costs nothing. Sign it valid for at least ${JOB_TIMEOUT_SECONDS()} seconds.`
      : `One GPU job, paid in ${network.label}. Pay the amount to payTo, then retry with ` +
        "header X-PAYMENT: base64({txHash, signature}), where signature is a personal_sign over " +
        "three lines: prism-x402:v2, the lowercased tx hash, and the sha256 hex of the command " +
        "you are sending. A payment buys the one command it names and nothing else.",
    mimeType: "application/json",
    maxTimeoutSeconds: JOB_TIMEOUT_SECONDS(),
    ...(network.domain ? { extra: { ...network.domain, assetTransferMethod: "eip3009" } } : {}),
  }));
}

function paymentRequirements(path, version = 2, error = null) {
  const origin = process.env.PRISM_PUBLIC_ORIGIN ?? "https://api.prismnetwork.tech/x402";
  return paymentRequired(version, {
    error,
    accepts: accepted(path),
    resource: {
      url: `${origin}${path}`,
      description: "One shell command on a rented GPU, charged only if it succeeds.",
      mimeType: "application/json",
    },
    schemas: { input: jobInput, output: jobOutput, example: jobExample, inputExample: jobInputExample, method: "POST" },
  });
}

function decodeTransfer(log) {
  if (log.topics[0] !== TRANSFER_TOPIC || log.topics.length < 3) return null;
  return {
    from: `0x${log.topics[1].slice(26)}`,
    to: `0x${log.topics[2].slice(26)}`,
    value: BigInt(log.data),
  };
}

// The exact scheme: the payer has signed an authorization and nothing has moved.
// Verification is read-only, and the broadcast waits until the job has run, so a
// job that fails leaves the payer untouched and needs no refund at all.
async function verifyAuthorization(parsed, resource) {
  const want = accepted(resource).find((entry) => sameNetwork(entry.network, parsed.accepted?.network));
  if (!want) return { ok: false, reason: "invalid_network" };
  const network = networks.find((n) => sameNetwork(n.id, want.network));
  if (!network?.exact) return { ok: false, reason: "invalid_scheme" };

  const authorization = parsed.payload?.authorization;
  const from = authorization?.from;
  const nonce = authorization?.nonce;
  if (typeof from !== "string" || typeof nonce !== "string") return { ok: false, reason: "invalid_payload" };
  const key = `${network.id}:${from}:${nonce}`.toLowerCase();
  if (!reservePayment(key)) return { ok: false, reason: "payment_reused" };

  const verdict = await network.exact.verify(parsed, want);
  if (!verdict.isValid) {
    releasePayment(key);
    return { ok: false, reason: verdict.invalidReason };
  }
  return {
    ok: true,
    payer: verdict.payer,
    network: network.id,
    key,
    // Held on the job and called only if the work succeeds.
    settle: () => network.exact.settle(parsed, want),
  };
}

// A migration escape hatch: older clients signed the transaction alone, which
// is the replay the binding below closes. Not safe to leave on.
const ALLOW_UNBOUND = process.env.PRISM_X402_ALLOW_UNBOUND_PAYMENT === "1";

// Verify an on-chain USDG payment bound to the caller: the caller signs the tx
// hash together with the request it buys, and the Transfer's `from` must match
// that signer. The hash stops a front-runner from claiming someone else's
// payment; the request stops anyone who read the header from spending it on a
// command of their own.
async function verifyPayment(header, requestHash) {
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

  // One signature recovers a different address under each message, so which
  // form the payer used is decided by the transfer on chain rather than here.
  const messages = ALLOW_UNBOUND
    ? [boundMessage(txHash, requestHash), txHash]
    : [boundMessage(txHash, requestHash)];
  const signers = [];
  for (const message of messages) {
    try {
      signers.push(await recoverMessageAddress({ message, signature }));
    } catch {
      // Nothing recovers from a signature that is not 65 bytes, under any message.
    }
  }
  if (!signers.length) return { ok: false, reason: "bad_signature" };

  let reason = "tx_not_found";
  for (const network of candidates) {
    const key = paymentKey(network.id, txHash);
    if (!reservePayment(key)) return { ok: false, reason: "payment_reused" };
    const outcome = await settleOn(network, txHash, signers);
    if (outcome.ok) {
      commitPayment(network.id, txHash);
      return { ok: true, payer: getAddress(outcome.payer), network: network.id };
    }
    releasePayment(key);
    if (outcome.reason !== "tx_not_found") reason = outcome.reason;
  }
  return { ok: false, reason };
}

// A payment counts when the transaction is final on that network and moved at
// least the price in that network's asset, from one of the signers, to its payee.
async function settleOn(network, txHash, signers) {
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
    const payer = signers.find((signer) =>
      receipt.logs.some((log) => {
        if (log.address.toLowerCase() !== network.asset.toLowerCase()) return false;
        const t = decodeTransfer(log);
        return (
          t &&
          t.to.toLowerCase() === network.payTo.toLowerCase() &&
          t.from.toLowerCase() === signer.toLowerCase() &&
          t.value >= config.priceMicros
        );
      }),
    );
    return payer ? { ok: true, payer } : { ok: false, reason: "no_matching_payment" };
  } catch (err) {
    console.error(`payment verification error on ${network.id}: ${err.message}`);
    return { ok: false, reason: "verification_error" };
  }
}

async function runJob(jobId, command, payer, networkId, payment) {
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
    // `cost_exceeds_max` means this endpoint is selling a job for less than the
    // lease it has to fund, so every request fails the same way and the code
    // alone does not say by how much. Carrying the two numbers turns a config
    // mistake that looks like a job failure into one that reads as a price
    // that is too low for the configured duration.
    if (err.code === "cost_exceeds_max" && err.body) {
      record.detail = `the lease needs ${err.body.required} but this endpoint collects ${err.body.max}; raise X402_PRICE_MICROS or lower X402_DURATION_SECONDS`;
    }
    if (payment?.settle) {
      // Nothing was ever taken, so there is nothing to give back. The
      // authorization is released so the caller can spend it on a retry.
      releasePayment(payment.key);
      record.charged = false;
      record.note = "not charged: the authorization was never broadcast";
    } else {
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
    }
  } finally {
    if (lease) agent.endLease(lease);
    record.finished_at = Date.now();
  }

  // Charged last, and only for work that succeeded.
  if (record.status === "completed" && payment?.settle) {
    try {
      const settlement = await payment.settle();
      record.charged = settlement.success;
      record.settlement = {
        network: settlement.network,
        transaction: settlement.transaction || null,
        ...(settlement.success ? {} : { error: settlement.errorReason }),
      };
      if (settlement.settled === false) releasePayment(payment.key);
      if (!settlement.success) {
        console.error(`job ${jobId} served but not charged: ${settlement.errorReason} detail=${settlement.detail ?? "none"}`);
      }
    } catch (err) {
      // The broadcast may have landed, so the authorization is not released:
      // treating it as unspent could charge the payer twice.
      record.charged = null;
      record.settlement = { error: "settlement_unconfirmed" };
      console.error(`job ${jobId} settlement threw: ${err.message}`);
    }
  } else if (record.status === "completed" && !payment?.settle) {
    record.charged = true;
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
  // Only off loopback, and then on every route including /healthz: the
  // facilitator broadcasts transactions and a job carries its own output, so
  // there is no route here worth answering for a stranger who found the port.
  const auth = authorized(req, listen.token);
  if (auth !== "ok") {
    return json(res, 401, {
      error: "unauthorized",
      detail:
        auth === "missing"
          ? "this listener is not on loopback, so every request needs an Authorization: Bearer header"
          : "the bearer token does not match",
    });
  }
  if (req.method === "GET" && url.pathname === "/healthz") return json(res, 200, { status: "ok" });

  // The facilitator interface, for endpoints that are not ours.
  if (facilitator && ["/verify", "/settle", "/supported"].includes(url.pathname)) {
    let body = null;
    if (req.method === "POST") {
      try {
        ({ body } = await readJson(req));
      } catch (err) {
        return json(res, err.code === "too_large" ? 413 : 400, { error: err.code ?? "invalid_json" });
      }
    }
    const out = await facilitator.handle(req.method, url.pathname, body);
    if (out) return json(res, out.status, out.body);
    return json(res, 405, { error: "method_not_allowed" });
  }

  if (req.method === "GET" && url.pathname.startsWith("/jobs/")) {
    const job = jobs.get(url.pathname.slice(6));
    if (!job) return json(res, 404, { error: "job_not_found" });
    // The query string first, because a listener token has already claimed the
    // Authorization header.
    const token = url.searchParams.get("token") ?? bearer(req);
    if (token !== job.token) return json(res, 401, { error: "invalid_job_token" });
    const { token: _t, ...view } = job;
    return json(res, 200, view);
  }

  // A discovery probe asks with GET. Answering 404 makes a paid endpoint look
  // broken to every crawler that finds it; answering the challenge costs
  // nothing and runs no job, because a safe method must stay safe.
  if (req.method === "GET" && url.pathname === "/run") {
    const version = detect(req.headers)?.version ?? 2;
    const required = paymentRequirements("/run", version);
    return json(res, 402, required.body, required.headers);
  }
  if (req.method === "POST" && url.pathname === "/run") {
    let read;
    try {
      read = await readJson(req);
    } catch (err) {
      return json(res, err.code === "too_large" ? 413 : 400, { error: err.code ?? "invalid_json" });
    }
    const payment = detect(req.headers);
    // v2 unless the caller showed us they speak v1.
    const version = payment?.version ?? 2;
    // The price comes before the complaint. A discovery probe sends no command,
    // and answering "command_required" instead of the 402 leaves the endpoint
    // undiscoverable; the command is checked once someone has paid to run one.
    if (!payment) {
      const required = paymentRequirements("/run", version);
      return json(res, 402, required.body, required.headers);
    }
    if (!read.body?.command || typeof read.body.command !== "string") {
      return json(res, 400, { error: "command_required" });
    }
    const parsed = parsePayment(payment.header);
    // The bytes that arrived, not the command read out of them. Every client
    // signs what it is about to send, and a digest taken over a field the
    // server picked out would leave the two computing different hashes of the
    // same request.
    const requestHash = hashRequest(read.bytes);
    const check = parsed?.payload?.authorization
      ? await verifyAuthorization(parsed, "/run")
      : await verifyPayment(String(payment.header), requestHash);
    if (!check.ok) {
      const refused = paymentRequirements("/run", version, check.reason);
      return json(res, 402, refused.body, refused.headers);
    }

    evictExpiredJobs();
    const jobId = randomUUID();
    const token = randomUUID();
    jobs.set(jobId, { job_id: jobId, status: "queued", token, payer: check.payer, network: check.network });
    runJob(jobId, read.body.command, check.payer, check.network, check);
    return json(res, 202, { job_id: jobId, status: "queued", token, poll: `/jobs/${jobId}` });
  }

  json(res, 404, { error: "not_found" });
});

function bearer(req) {
  const h = req.headers.authorization;
  return h?.toLowerCase().startsWith("bearer ") ? h.slice(7).trim() : null;
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

// The bytes come back with the parsed body because the payment is signed over
// them: re-serializing here would hash something the caller never sent.
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
  const bytes = Buffer.concat(chunks);
  if (!bytes.length) return { body: {}, bytes };
  try {
    return { body: JSON.parse(bytes.toString()), bytes };
  } catch {
    throw Object.assign(new Error("invalid json"), { code: "invalid_json" });
  }
}

server.listen(config.port, listen.host, () => {
  console.error(
    `prism x402 server on ${listen.host}:${config.port}, price ${config.priceMicros} micros, accepting ` +
      networks.map((network) => `${network.label} -> ${network.payTo}`).join(", "),
  );
  console.error(
    listen.token
      ? "callers must send a bearer token, /healthz included"
      : "no token: any local caller can spend and read jobs",
  );
});
