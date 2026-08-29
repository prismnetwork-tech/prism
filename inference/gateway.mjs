// The managed-inference core: a warm GPU lease running ollama, fronted by an
// x402-paid HTTP surface. One paid request, one generation, no SSH or lease
// lifecycle on the caller's side.
//
// Everything with a side effect arrives through `deps`, so the whole state
// machine is testable with fakes: `agent` (the Prism SDK surface it uses),
// `spawnTunnel` (ssh -L to the box's ollama), `fetchOllama`, and `verify`
// (on-chain payment verification).
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { parsePayment, paymentRequired, paymentResponse, requirementsFor, sameNetwork } from "@prismnetwork/x402/codec";
import { batchReceipt, digest } from "./receipt.mjs";

// The shipped rate card, in USDG micros, derived from what a generation costs
// to serve.
//
// `base` recovers the warm window. A window is an 1800s lease at 222 micros/s,
// the escrow settles on the seconds the node ran and there is no early exit, so
// all 399,600 of those micros are spent whether anyone calls or not. Each base
// is set so about an eighth of what a window can serve pays for the window.
//
// `perToken` covers the lease time the tokens themselves burn. Measured end to
// end under ollama on a 273 GB/s workstation, llama3.2:3b runs at 89 tok/s and
// llama3.1:8b at 43, which is 2.5 and 5.1 micros of lease per token. Every card
// the network offers has more bandwidth than that, so treat those as the
// ceiling on cost. The 1:2 ratio between the models is the ratio of their
// measured throughput.
export const DEFAULT_PRICING = {
  "llama3.2:3b": { base: 3_000, perToken: 3 },
  "llama3.1:8b": { base: 6_000, perToken: 6 },
};
export const MAX_PROMPT_BYTES = 32 * 1024;
export const MAX_PREDICT_TOKENS = 1_024;
export const MAX_BATCH_ITEMS = 64;

// The confidential class is not served on our own GPUs: the gateway relays a
// paid request to Phala's attested TEE gateway and hands the bytes back
// untouched. The rate card therefore covers what the upstream charges rather
// than what a lease burns, and it is set at roughly eight times the upstream
// catalog price at the caps below.
//
// gemma-4-26b lists at $0.15/M input and $0.70/M output, qwen3.6-35b at $0.30
// and $1.50. A request is bounded by a 32 KiB body and a stated `max_tokens`
// of at most 1024, so the worst upstream cost per call is about 1,950 micros
// for gemma and 4,000 for qwen.
export const DEFAULT_CONFIDENTIAL_PRICING = {
  "phala/gemma-4-26b-a4b-uncensored": { base: 10_000, perToken: 5 },
  "phala/qwen3.6-35b-a3b-uncensored": { base: 20_000, perToken: 10 },
};
export const CONFIDENTIAL_UPSTREAM = "https://tee.redpill.ai/v1";
// The GPU evidence the NVIDIA attestation service wants as its request body is
// only published by the general host, not the confidential-only one.
export const CONFIDENTIAL_LEGACY_UPSTREAM = "https://api.redpill.ai/v1";

/// How many times to ask the upstream for GPU evidence from a named instance.
/// It picks per request across a handful of instances, so a few tries reaches
/// any one of them; the cap is what stops a vanished instance spinning here.
export const GPU_EVIDENCE_ATTEMPTS = 8;

/// How long an instance's evidence stays usable, and how many instances are
/// worth holding. Fifteen minutes covers the drift without approaching the
/// NVIDIA attestation token's own validity.
export const GPU_EVIDENCE_TTL_MS = 15 * 60_000;
export const GPU_EVIDENCE_HELD = 16;
const KEYSET_DIGEST = /^sha256:[0-9a-f]{64}$/;

/// Which instance a relayed evidence response came from. The relay passes the
/// upstream's bytes through untouched, so the digest has to be read back out of
/// them rather than off a parsed body that does not exist.
function servedKeyset(relayed) {
  if (relayed?.status !== 200 || !relayed.bytes) return null;
  try {
    const digest = JSON.parse(Buffer.from(relayed.bytes).toString("utf8"))?.workload_keyset_digest;
    return typeof digest === "string" ? digest : null;
  } catch {
    return null;
  }
}
export const MAX_CONFIDENTIAL_BODY_BYTES = 32 * 1024;

// A request's price is the model's base plus its per-token rate over the
// output cap the caller asked for. The full-cap price is what /v1/models
// advertises, so a client that pays it without asking for a request-specific
// quote always clears verification.
export function priceFor(pricing, model, requestedTokens) {
  const p = pricing[model];
  const perToken = p.perToken ?? p.per_token ?? 0;
  const cap = Number.isInteger(requestedTokens) && requestedTokens > 0
    ? Math.min(requestedTokens, MAX_PREDICT_TOKENS)
    : MAX_PREDICT_TOKENS;
  return { cap, micros: BigInt(p.base) + BigInt(perToken) * BigInt(cap) };
}

const TX_HASH = /^0x[0-9a-f]{64}$/i;

// A consumed payment is keyed by whatever makes it unique. The legacy scheme
// pays first, so its key is the transaction hash. The exact scheme authorizes
// first, so its key is the payer and the authorization nonce, which is also
// what the token contract itself refuses to reuse.
const PAYMENT_KEY = /^(0x[0-9a-f]{64}|0x[0-9a-f]{40}:0x[0-9a-f]{64})$/i;

const ROUTES = {
  single: {
    path: "/v1/inference",
    unit: "One generation",
    where: "on Prism GPUs",
    rail: ", which is where the serving leases settle",
    resource: "One LLM generation on a rented GPU, priced per request.",
  },
  batch: {
    path: "/v1/batch",
    unit: "A batch of independent generations",
    where: "on Prism GPUs",
    rail: ", which is where the serving leases settle",
    resource:
      "Many independent prompts in one paid call, spread across the rented GPUs the gateway " +
      "holds, returned with a Merkle receipt over the set.",
  },
  confidential: {
    path: "/v1/chat/completions",
    unit: "One confidential generation",
    where: "in a Phala GPU TEE",
    resource:
      "One OpenAI-shaped chat completion served inside a Phala GPU TEE, priced per request. " +
      "The gateway relays the request bytes and returns the response bytes unchanged, and the " +
      "TEE signs a receipt over both.",
  },
};

// Sent up to the TEE when the caller encrypts. The gateway does not read or
// produce them; it carries whichever ones arrive, and the upstream rejects a
// partial set.
const E2EE_REQUEST_HEADERS = [
  "x-e2ee-version",
  "x-client-pub-key",
  "x-model-pub-key",
  "x-e2ee-nonce",
  "x-e2ee-timestamp",
];
// What a caller needs off the response to fetch and verify its receipt.
const RELAY_RESPONSE_HEADERS = [
  "x-receipt-id",
  "x-aci-version",
  "x-aci-keyset-digest",
  "x-e2ee-applied",
  "x-e2ee-version",
  "x-e2ee-algo",
];

const HEX_64 = /^[0-9a-f]{64}$/;
const RECEIPT_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const UPSTREAM_NAME = /^[A-Za-z0-9._:/-]{1,128}$/;

/// A confidential model nobody costed is priced as the most expensive one that
/// was, for the same reason the ollama card does it: guessing low loses money
/// on every call.
const PRICIEST_CONFIDENTIAL = Object.values(DEFAULT_CONFIDENTIAL_PRICING).reduce((a, b) =>
  a.base + a.perToken * MAX_PREDICT_TOKENS >= b.base + b.perToken * MAX_PREDICT_TOKENS ? a : b,
);

function confidentialCard(cfg) {
  const entries = Object.entries(cfg.models ?? {});
  if (!entries.length) throw new Error("the confidential class needs at least one model");
  const pricing = {};
  for (const [model, over] of entries) {
    const card = DEFAULT_CONFIDENTIAL_PRICING[model] ?? PRICIEST_CONFIDENTIAL;
    const base = Number(over?.base_micros ?? over?.base ?? card.base);
    const perToken = Number(over?.per_token_micros ?? over?.per_token ?? over?.perToken ?? card.perToken);
    if (!Number.isFinite(base) || base < 0 || !Number.isFinite(perToken) || perToken < 0) {
      throw new Error(`confidential pricing for ${model} must be non-negative numbers`);
    }
    pricing[model] = { base, perToken };
  }
  if (!cfg.key) throw new Error("the confidential class needs an upstream API key");
  const dailyUsd = Number(cfg.dailyUsd ?? 1);
  if (!Number.isFinite(dailyUsd) || dailyUsd <= 0) {
    throw new Error("the confidential daily spend cap must be a positive number of dollars");
  }
  return {
    upstream: String(cfg.upstream ?? CONFIDENTIAL_UPSTREAM).replace(/\/$/, ""),
    legacyUpstream: String(cfg.legacyUpstream ?? CONFIDENTIAL_LEGACY_UPSTREAM).replace(/\/$/, ""),
    key: cfg.key,
    dailyUsd,
    pricing,
  };
}

/// Reads the two fields the gateway is allowed to look at. The buffer this was
/// parsed from is what gets forwarded, so nothing here can reshape the request.
function peek(bytes) {
  try {
    const value = JSON.parse(bytes.toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

function readUsage(bytes) {
  const body = peek(bytes);
  const usage = body?.usage;
  if (!usage || typeof usage !== "object") return {};
  const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  return {
    prompt_tokens: num(usage.prompt_tokens),
    completion_tokens: num(usage.completion_tokens),
    cost: num(usage.cost),
  };
}

/// What a stream says about itself, read back out of the bytes that were sent.
/// `usage` rides a data frame rather than the body, and only when the caller
/// asked the upstream for it; `[DONE]` is the only thing in the stream that
/// says the answer is whole.
function readStream(bytes) {
  let usage = {};
  let done = false;
  for (const line of bytes.toString("utf8").split("\n")) {
    if (!line.startsWith("data:")) continue;
    const frame = line.slice(5).trim();
    if (frame === "[DONE]") {
      done = true;
      continue;
    }
    if (!frame) continue;
    const found = readUsage(Buffer.from(frame));
    if (found.prompt_tokens != null || found.completion_tokens != null || found.cost != null) usage = found;
  }
  return { usage, done };
}

/// The one thing the relay ever adds to a body, and only to a stream that
/// stopped before its terminator: an OpenAI-shaped error frame, because a
/// status already sent cannot be taken back and silence reads as a short
/// answer rather than a broken one.
const STREAM_TRUNCATED = Buffer.from(
  `data: ${JSON.stringify({
    error: {
      type: "upstream_unavailable",
      code: "stream_truncated",
      message:
        "the enclave stopped before the stream ended; the payment was not consumed, so the same " +
        "payment header buys the retry",
    },
  })}\n\n`,
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/// An error worth acting on. The SDK carries the reason in `body.cause` and the
/// message is only the status and the code, so a bare message reads as
/// "chain_error" for faults that have nothing to do with each other.
export function describe(err) {
  const cause = err?.body?.cause ?? err?.cause;
  const detail = typeof cause === "string" ? cause : cause?.message;
  return detail ? `${err.message}: ${detail}` : String(err?.message ?? err);
}
/// Distinguishes "the wait elapsed" from "warming finished, with or without an
/// error", which null and an Error already cover.
const TIMED_OUT = Symbol("timed out");

export const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
export const USDG_ROBINHOOD = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";

/// Base USDC reports this as its EIP-712 domain, and the domain feeds the
/// signing hash. The published spec example carries the testnet token's
/// "USDC", which signs against nothing here.
export const USDC_BASE_DOMAIN = { name: "USD Coin", version: "2" };
/// Read off the contract, not guessed: USDG's `name()` is "Global Dollar" and it
/// exposes no `version()`, so the version was recovered by reproducing the
/// on-chain DOMAIN_SEPARATOR. A client that signs against the wrong domain
/// produces a well-formed signature the token rejects.
export const USDG_ROBINHOOD_DOMAIN = { name: "Global Dollar", version: "1" };

export function loadConsumed(file) {
  const set = new Set();
  if (file && existsSync(file)) {
    for (const line of readFileSync(file, "utf8").split("\n")) {
      const h = line.trim().toLowerCase();
      if (h) set.add(h);
    }
  }
  return set;
}

export function createGateway({
  agent,
  models,
  payTo,
  basePayTo = null,
  exact = null,
  originUrl = "https://api.prismnetwork.tech/inference",
  // Carried in every 402 so an agent that arrives cold learns the price and how
  // to call the endpoint from one response, without fetching anything else.
  schemas = null,
  // The batch takes a different body, and an indexer that reads the single
  // request's schema off a batch 402 publishes a call that cannot work.
  batchSchemas = null,
  confidentialSchemas = null,
  // Null leaves the confidential class off entirely, which is what an operator
  // without an upstream key gets: the routes answer 404 rather than half-work.
  confidential = null,
  maxConfidentialBytes = MAX_CONFIDENTIAL_BODY_BYTES,
  // A generation in a TEE is not faster than one on a lease, and the relay
  // holds the connection for the whole of it.
  confidentialTimeoutMs = 180_000,
  relayTimeoutMs = 30_000,
  // The free relay endpoints cost us an upstream request each. Enough headroom
  // for an agent verifying every call it makes, not enough to be a proxy.
  relayPerMinute = 120,
  // Sets the base for every model when given, so an operator can move the
  // whole card without listing it. Null leaves the shipped card alone.
  priceMicros = null,
  pricing: pricingIn = null,
  image,
  durationSeconds = 1800,
  minVramMib = 16000,
  idleMs = 600_000,
  coolDownMs = 240_000,
  warmTimeoutMs = 480_000,
  generateTimeoutMs = 120_000,
  // Long enough to catch a box whose tunnel is already coming up, short enough
  // that no reasonable client gives up first.
  readyWaitMs = 12_000,
  // What to tell a caller to wait. Warming means a lease is already in flight,
  // which still has to clear confirmations, boot the box and pull the model:
  // minutes, not seconds. Cold means none of that has started yet. The old
  // flat 90s was shorter than the work takes, so agents honoured it, gave up,
  // and reported the endpoint as broken.
  retryAfterMs = 300_000,
  coldRetryAfterMs = 600_000,
  // How many boxes the gateway may hold at once. One by default: a second box
  // is a second prepaid lease, so growing the pool is a cost the operator opts
  // into rather than something a single caller can trigger.
  poolMax = 1,
  maxBatchItems = MAX_BATCH_ITEMS,
  // A batch has to be worth a second lease before it gets one. Below this many
  // prompts per box the batch runs on the capacity already warm.
  itemsPerBox = 25,
  batchTimeoutMs = 600_000,
  paymentsFile = null,
  verify,
  spawnTunnel,
  fetchOllama,
  fetchUpstream = fetch,
  log = (line) => console.error(line),
  now = () => Date.now(),
}) {
  if (!models?.length) throw new Error("at least one model is required");
  const pricing = {};
  for (const m of models) {
    const p = pricingIn?.[m] ?? {};
    // A model nobody costed is priced as the largest one that was measured.
    // Guessing low there loses money on every call it serves.
    const card = DEFAULT_PRICING[m] ?? DEFAULT_PRICING["llama3.1:8b"];
    pricing[m] = {
      base: Number(p.base ?? priceMicros ?? card.base),
      perToken: Number(p.per_token ?? p.perToken ?? card.perToken),
    };
    if (!Number.isFinite(pricing[m].base) || pricing[m].base < 0 || !Number.isFinite(pricing[m].perToken) || pricing[m].perToken < 0) {
      throw new Error(`pricing for ${m} must be non-negative numbers`);
    }
  }
  const fullCap = (m) => priceFor(pricing, m, null).micros;
  const maxPriceMicros = models.map(fullCap).reduce((a, b) => (a > b ? a : b));
  const conf = confidential ? confidentialCard(confidential) : null;
  const confModels = conf ? Object.keys(conf.pricing) : [];
  const confFullCap = (m) => priceFor(conf.pricing, m, null).micros;
  const maxConfidentialMicros = conf
    ? confModels.map(confFullCap).reduce((a, b) => (a > b ? a : b))
    : 0n;
  // Paths as a caller sees them. The gateway is mounted under a prefix in
  // production, and an agent handed "/v1/attestation" from behind it fetches
  // the wrong host's root.
  const prefix = (() => {
    try {
      return new URL(originUrl).pathname.replace(/\/$/, "");
    } catch {
      return "";
    }
  })();
  const publicPath = (p) => `${prefix}${p}`;
  const stats = {
    since: now(), generations: 0, tokens_in: 0, tokens_out: 0,
    revenue_micros: 0n, leases_warmed: 0,
    // A generation served whose settlement then failed. Nonzero means either
    // an rpc problem or someone racing the broadcast, and both are worth seeing.
    unsettled: 0, unsettled_micros: 0n,
    // Broadcast, but the receipt could not be read. Neither revenue nor loss
    // until someone checks the chain.
    unconfirmed: 0,
    batches: 0, batch_items: 0,
    // The confidential class is bought from upstream rather than served, so
    // what it costs is tracked next to what it earns.
    confidential_generations: 0, confidential_tokens_in: 0, confidential_tokens_out: 0,
    confidential_cost_usd: 0,
  };
  // Reset on the UTC day boundary, which is what the cap is stated in. `usd`
  // carries settled cost plus what in-flight requests have reserved.
  const spend = { day: null, usd: 0 };
  let costUnreported = false;

  const consumed = loadConsumed(paymentsFile);
  // A client that paid and then lost the connection must be able to fetch what
  // it paid for: a consumed tx hash answers with its own result, not a refusal.
  const served = new Map();
  const SERVED_CAP = 200;
  // One slot per box the gateway is allowed to hold at once. A slot owns its
  // own lease and its own tunnel, and the slot number is what tells the tunnel
  // which local port to bind, so two boxes never contend for one.
  const pool = Array.from({ length: Math.max(1, Math.floor(poolMax)) }, (_, slot) => ({
    slot, phase: "cold", lease: null, tunnel: null, expiresAt: 0, lastUsed: 0, inFlight: 0,
  }));
  const warming = new Map();
  let coolUntil = 0;
  // What the failed warmup was, kept for as long as the hold-off it started.
  // Every caller that arrives inside that window is answered from here, and a
  // fault nobody wrote down cannot be told apart from a queue.
  let coolCause = null;

  function reservePayment(key) {
    if (consumed.has(key)) return false;
    consumed.add(key);
    return true;
  }
  function releasePayment(key) {
    consumed.delete(key);
  }
  // Append-only and rebuilt on restart; the line is reassembled from validated
  // parts rather than trusting a string built elsewhere.
  function commitPayment(txHash) {
    const hash = String(txHash).toLowerCase();
    if (!PAYMENT_KEY.test(hash)) throw new Error("refusing to record a malformed payment key");
    if (!paymentsFile) return;
    try {
      appendFileSync(paymentsFile, `${hash}\n`);
    } catch (err) {
      log(`failed to persist consumed payment: ${err.message}`);
    }
  }

  /// Holds warming off for a while and records what stopped it. `capacity`
  /// separates the network having no machine to give us, which is a queue, from
  /// a machine we hold and cannot use, which is a fault: the pool is equally
  /// unable to serve either way, but only one of them is ours to fix and only
  /// one of them should read as an outage to anything watching.
  function holdOff(err, capacity) {
    coolUntil = now() + coolDownMs;
    coolCause = { why: String(err?.message ?? err), capacity };
    return Object.assign(err, { capacity });
  }

  async function warmUp(box) {
    box.phase = "warming";
    let lease;
    try {
      lease = await agent.lease({ image, durationSeconds, minVramMib });
    } catch (err) {
      // Nothing was funded when the match itself fails, but hammering the
      // network with fresh quote attempts helps nobody. The SDK reports a chain
      // fault as a status and a code and puts what actually went wrong in the
      // body, so the log takes the whole of it: a caller inside the hold-off is
      // told the short reason and nothing else is recoverable from outside.
      log(`warmup failed while leasing: ${describe(err)}`);
      box.phase = "cold";
      throw holdOff(err, true);
    }
    try {
      // The supplier replaces the image entrypoint with its own SSH bootstrap,
      // so the daemon the image would have started never runs. Start it here
      // and leave it running for the tunnel.
      const pulls = [
        "pgrep -x ollama >/dev/null || (nohup ollama serve >/tmp/ollama.log 2>&1 & sleep 5)",
        ...models.map((m) => `ollama pull ${m}`),
      ].join(" && ");
      const out = await agent.run(lease, pulls, { timeoutMs: warmTimeoutMs });
      if (out.code !== 0) {
        throw new Error(`model pull exit ${out.code}: ${(out.stderr || out.stdout).slice(-300)}`);
      }
      const tunnel = await spawnTunnel(lease, box.slot);
      // The tunnel is up when ollama answers through it.
      const deadline = now() + 60_000;
      for (;;) {
        try {
          const res = await fetchOllama(box.slot, "/api/tags", { method: "GET" });
          if (res.ok) break;
        } catch {
          /* not up yet */
        }
        if (now() > deadline) {
          tunnel.close();
          throw new Error("ollama did not answer through the tunnel");
        }
        await new Promise((r) => setTimeout(r, 2_000));
      }
      box.lease = lease;
      box.tunnel = tunnel;
      box.expiresAt = Date.parse(lease.access?.expires_at ?? "") || now() + durationSeconds * 1000;
      box.lastUsed = now();
      box.phase = "warm";
      stats.leases_warmed += 1;
      log(`warm: slot ${box.slot}, lease ${lease.leaseId}, models ${models.join(", ")}`);
    } catch (err) {
      // The lease is paid for either way; drop only what this process holds,
      // and hold off before leasing again: every failed warmup costs a full
      // lease, so a persistent fault must not chain them.
      agent.endLease(lease);
      box.phase = "cold";
      // A lease was paid for and is being dropped, so this is the expensive
      // failure and the one worth naming precisely.
      log(`warmup failed after lease ${lease.leaseId}: ${describe(err)}`);
      throw holdOff(err, false);
    }
  }

  const warmBoxes = () => pool.filter((b) => b.phase === "warm");

  function startWarm(box) {
    const existing = warming.get(box.slot);
    if (existing) return existing;
    const attempt = warmUp(box).finally(() => warming.delete(box.slot));
    warming.set(box.slot, attempt);
    return attempt;
  }

  /// Bring the pool toward `target` warm boxes and hand back what is already in
  /// flight. A cooldown blocks starting new ones but never the boxes already
  /// warm, so a batch keeps running on the capacity it has.
  function grow(target) {
    const want = Math.min(Math.max(target, 1), pool.length);
    if (now() >= coolUntil) {
      for (const box of pool) {
        if (warmBoxes().length + warming.size >= want) break;
        if (box.phase === "cold") startWarm(box);
      }
    }
    return [...warming.values()];
  }

  /// Resolves once the pool has somewhere to run a generation.
  function ensureWarm(target = 1) {
    const pending = grow(target);
    if (warmBoxes().length) return Promise.resolve();
    if (!pending.length) {
      // A hold-off answers with whatever started it, so a fault stays a fault
      // for as long as it is keeping the pool down rather than reading as a
      // queue from the second caller on.
      if (now() < coolUntil) {
        const seconds = Math.ceil((coolUntil - now()) / 1000);
        return Promise.reject(
          Object.assign(
            new Error(`warmup is cooling down after ${coolCause.why}; retry in ${seconds}s`),
            { capacity: coolCause.capacity },
          ),
        );
      }
      // Every slot is spoken for, which is the pool being full rather than
      // anything having gone wrong.
      return Promise.reject(Object.assign(new Error("no slot is free to warm"), { capacity: true }));
    }
    // Any one of them is enough, and the aggregate error hides the cause.
    return Promise.any(pending).then(
      () => undefined,
      (err) => {
        throw err?.errors?.[0] ?? err;
      },
    );
  }

  function drain(box, reason) {
    if (box.tunnel) box.tunnel.close();
    if (box.lease) agent.endLease(box.lease);
    log(`drained slot ${box.slot} (${reason})`);
    box.phase = "cold";
    box.lease = null;
    box.tunnel = null;
    box.expiresAt = 0;
    box.inFlight = 0;
  }

  /// The box with the least on it. Leases are prepaid for a fixed window, so
  /// spreading work over the boxes we already hold costs nothing extra.
  function pick() {
    let best = null;
    for (const box of pool) {
      if (box.phase !== "warm") continue;
      if (!best || box.inFlight < best.inFlight) best = box;
    }
    return best;
  }

  /// One word for a pool: warm if anything can serve now, warming if a box is
  /// on its way, cold otherwise.
  function phase() {
    if (warmBoxes().length) return "warm";
    if (warming.size) return "warming";
    return "cold";
  }

  // `/v1/models` reports the same state for free, so a caller that wants to
  // avoid paying into a cold start can check there first.
  function retryAfterFor(state) {
    return Math.ceil((state === "cold" ? coldRetryAfterMs : retryAfterMs) / 1000);
  }

  /// The pool has nowhere to run this yet: no box is up, or the network had
  /// none to give. Nothing has broken and nothing was charged, so it answers
  /// like a rate limit rather than like a fault. Aggregators score an endpoint
  /// on how often it returns 5xx and exempt 429 for exactly this case, and a
  /// queue counted as downtime costs the pool the traffic that would have
  /// warmed it.
  function busy(error, detail) {
    const seconds = retryAfterFor(phase());
    return {
      status: 429,
      headers: { "retry-after": String(seconds) },
      body: {
        error,
        detail,
        state: phase(),
        retry_after_seconds: seconds,
        retry: "nothing was charged; send the same payment header again.",
      },
    };
  }

  /// Something the gateway holds could not do the work: a box that took a
  /// generation and failed it, or a lease that was paid for and never came up.
  /// Nothing was charged here either, but a fault answered as a queue is an
  /// outage nobody is told about: the endpoint keeps saying "come back later"
  /// while every request fails and every hold-off buys another GPU to abandon.
  function broken(error, detail) {
    return {
      status: 503,
      body: {
        error,
        detail,
        state: phase(),
        retry: "nothing was charged; retry with the same payment header",
      },
    };
  }

  function drainAll(reason) {
    for (const box of pool) if (box.phase === "warm") drain(box, reason);
  }

  // Called on an interval by the server (and directly by tests): let an idle
  // box lapse, renew a busy one before its lease expires.
  async function maintain() {
    let renew = 0;
    for (const box of pool) {
      if (box.phase !== "warm") continue;
      if (now() > box.expiresAt) {
        drain(box, "lease expired");
        continue;
      }
      if (now() <= box.expiresAt - 120_000) continue;
      if (now() - box.lastUsed > idleMs) {
        drain(box, "idle at renewal time");
        continue;
      }
      drain(box, "renewing");
      renew += 1;
    }
    // A renewal is a fresh lease on a fresh slot, so it goes through the same
    // path as any other warmup rather than reusing the drained one in place.
    // Every box that was busy enough to renew is worth replacing, not just one.
    if (renew) {
      await ensureWarm(warmBoxes().length + renew).catch((err) => log(`renewal failed: ${err.message}`));
    }
  }

  /// Both stablecoins carry six decimals, so one price in micros is the price
  /// on either rail with no conversion.
  function schemasFor(route) {
    if (route === ROUTES.batch) return batchSchemas ?? schemas;
    if (route === ROUTES.confidential) return confidentialSchemas;
    return schemas;
  }

  function accepted(amount, route = ROUTES.single) {
    const shape = schemasFor(route);
    const list = [];
    if (basePayTo) {
      list.push({
        scheme: "exact",
        network: "eip155:8453",
        asset: USDC_BASE,
        payTo: basePayTo,
        amount: amount.toString(),
        resource: `${originUrl}${route.path}`,
        description:
          `${route.unit} ${route.where}, paid in USDC on Base. Sign an EIP-3009 ` +
          "transferWithAuthorization for the quoted amount and send it as the payment header. " +
          "You need no gas: the authorization is broadcast for you.",
        mimeType: "application/json",
        maxTimeoutSeconds: 60,
        ...(shape ? { outputSchema: shape } : {}),
        extra: { ...USDC_BASE_DOMAIN, assetTransferMethod: "eip3009" },
      });
    }
    list.push({
      scheme: "exact",
      network: "eip155:4663",
      asset: USDG_ROBINHOOD,
      payTo,
      amount: amount.toString(),
      resource: `${originUrl}${route.path}`,
      description:
        `${route.unit} ${route.where}, paid in USDG on Robinhood Chain${route.rail ?? ""}. ` +
        "Sign an EIP-3009 transferWithAuthorization for the quoted amount " +
        "and send it as the payment header; you need no gas, because the authorization is " +
        "broadcast for you. The older flow, a direct transfer plus a signed tx hash, still works.",
      mimeType: "application/json",
      maxTimeoutSeconds: 60,
      ...(shape ? { outputSchema: shape } : {}),
      // Without the EIP-712 domain a strict client cannot sign an authorization
      // it can trust, and the careful ones refuse rather than read the domain
      // off-chain and risk signing the wrong one.
      extra: { ...USDG_ROBINHOOD_DOMAIN, assetTransferMethod: "eip3009" },
    });
    return list;
  }

  /// `version` selects the wire shape: v1 wants `maxAmountRequired` and a chain
  /// name, v2 wants `amount` and CAIP-2. The prices and networks are the same
  /// either way.
  function requirements(state, quote = null, version = 2, error = null, route = ROUTES.single) {
    const amount =
      quote?.micros ?? (route === ROUTES.confidential ? maxConfidentialMicros : maxPriceMicros);
    return paymentRequired(version, {
      error,
      accepts: accepted(amount, route),
      resource: {
        url: `${originUrl}${route.path}`,
        description: route.resource,
        mimeType: "application/json",
      },
      schemas: schemasFor(route),
      // Ours, not the protocol's: the box state and the quote this price came
      // from, which a human reading the 402 wants and a parser ignores.
      extra: {
        state,
        ...(quote
          ? {
              quote: {
                model: quote.model,
                output_cap: quote.cap,
                price_micros: amount.toString(),
                ...(quote.count ? { count: quote.count } : {}),
              },
            }
          : {}),
      },
    });
  }

  /// The exact scheme: the payer signed an authorization but nothing has moved
  /// yet, so verification is read-only and the broadcast happens only once a
  /// generation exists to pay for. A failed generation therefore costs the
  /// payer nothing and needs no refund, which the legacy scheme cannot offer.
  async function checkAuthorization(parsed, quotedMicros, route) {
    const authorization = parsed.payload?.authorization;
    const from = authorization?.from;
    const nonce = authorization?.nonce;
    if (typeof from !== "string" || typeof nonce !== "string") {
      return { ok: false, reason: "invalid_payload" };
    }
    const key = `${from}:${nonce}`.toLowerCase();
    if (!PAYMENT_KEY.test(key)) return { ok: false, reason: "invalid_payload" };

    // The requirement we quoted, not the one the client echoed back: a payer
    // who rewrites the amount or the recipient must fail, and comparing their
    // copy against itself would always pass.
    // Compared canonically: a client that read a v1 quote echoes back "base"
    // while this list holds "eip155:8453", and they are the same chain.
    const want = accepted(quotedMicros, route).find(
      (entry) => sameNetwork(entry.network, parsed.accepted?.network),
    );
    if (!want) return { ok: false, reason: "invalid_network" };

    if (!reservePayment(key)) {
      const replay = served.get(key);
      return { ok: false, reason: "payment_reused", ...(replay ? { replay } : {}) };
    }

    const verdict = await exact.verify(parsed, want);
    if (!verdict.isValid) {
      releasePayment(key);
      return { ok: false, reason: verdict.invalidReason };
    }

    return {
      ok: true,
      payer: verdict.payer,
      settle: async () => exact.settle(parsed, want),
      commit: (result) => {
        commitPayment(key);
        served.set(key, result);
        if (served.size > SERVED_CAP) served.delete(served.keys().next().value);
      },
      release: () => releasePayment(key),
    };
  }

  async function checkPayment(header, quotedMicros, route = ROUTES.single) {
    const parsed = parsePayment(header);
    if (!parsed) return { ok: false, reason: "invalid_payload" };
    // An authorization means the exact scheme; a bare tx hash is the legacy
    // one, kept working for a release so anything already integrated survives.
    if (parsed.payload?.authorization) {
      if (!exact) return { ok: false, reason: "invalid_scheme" };
      return checkAuthorization(parsed, quotedMicros, route);
    }
    const { txHash, signature } = parsed.raw ?? {};
    if (!TX_HASH.test(txHash ?? "") || typeof signature !== "string") {
      return { ok: false, reason: "malformed_payment" };
    }
    const key = txHash.toLowerCase();
    if (!reservePayment(key)) {
      const replay = served.get(key);
      if (replay) return { ok: false, reason: "payment_reused", replay };
      return { ok: false, reason: "payment_reused" };
    }
    const outcome = await verify(txHash, signature, quotedMicros);
    if (!outcome.ok) {
      releasePayment(key);
      return outcome;
    }
    return {
      ok: true,
      payer: outcome.payer,
      // A payment is spent when a response was served, so a failed generation
      // leaves the tx valid for the retry.
      commit: (result) => {
        commitPayment(key);
        served.set(key, result);
        if (served.size > SERVED_CAP) served.delete(served.keys().next().value);
      },
      release: () => releasePayment(key),
    };
  }

  async function generate(body, cap, box) {
    const options = { ...(body.options ?? {}), num_predict: cap };
    box.inFlight += 1;
    box.lastUsed = now();
    let out;
    try {
      const res = await fetchOllama(box.slot, "/api/generate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: body.model, prompt: body.prompt, stream: false, options }),
        signal: AbortSignal.timeout(generateTimeoutMs),
      });
      if (!res.ok) throw new Error(`ollama answered ${res.status}`);
      out = await res.json();
    } finally {
      box.inFlight -= 1;
      box.lastUsed = now();
    }
    stats.generations += 1;
    stats.tokens_in += out.prompt_eval_count ?? 0;
    stats.tokens_out += out.eval_count ?? 0;
    return {
      model: body.model,
      response: out.response,
      usage: {
        prompt_tokens: out.prompt_eval_count ?? null,
        completion_tokens: out.eval_count ?? null,
        duration_ms: out.total_duration ? Math.round(out.total_duration / 1e6) : null,
      },
      lease_id: box.lease?.leaseId ?? null,
    };
  }

  /// Under the exact scheme nothing has moved until this call, so the money is
  /// taken only once there is something to hand back. The exposure is the
  /// reverse window: a payer who empties their wallet between verification and
  /// this broadcast gets one generation free. That is bounded by a single
  /// request's price, needs a deliberate race, and is cheaper to absorb than a
  /// refund path that can fail on its own.
  ///
  /// Null when there is nothing to broadcast, which is the legacy scheme, where
  /// the money moved before the request arrived.
  async function settlePayment(payment, micros, what = "") {
    if (!payment.settle) return null;
    let settlement;
    try {
      settlement = await payment.settle();
    } catch (err) {
      // The broadcast may well have gone through, so this cannot throw out of
      // here: the caller has already paid for work that is already done, and a
      // 500 would hand them nothing for it.
      log(`settlement threw after serving${what}: ${err.message}`);
      settlement = { success: false, settled: null, errorReason: "settlement_unconfirmed", payer: payment.payer };
    }
    if (settlement.success) return settlement;
    // `settled === null` means the money may have moved and we could not read
    // whether it did, which is not the same as being unpaid. Counting it as
    // revenue would overstate; counting it as a loss would understate. It is
    // recorded apart from both.
    if (settlement.settled === null) {
      stats.unconfirmed += 1;
      log(`settlement unconfirmed${what}: tx=${settlement.transaction ?? "none"} payer=${payment.payer} detail=${settlement.detail ?? "none"}`);
    } else {
      stats.unsettled += 1;
      stats.unsettled_micros += micros;
      log(`settlement failed after serving${what}: ${settlement.errorReason ?? "unknown"} payer=${payment.payer} detail=${settlement.detail ?? "none"}`);
    }
    return settlement;
  }

  async function handleInference(body, paymentHeader, paymentVersion = null) {
    // v2 unless the caller showed us they speak v1. The scanners and the
    // agent tooling read v2 only, and an unpaid probe tells us nothing about
    // itself, so the newer shape is the right thing to volunteer.
    const version = paymentVersion ?? 2;
    const known = typeof body?.model === "string" && models.includes(body.model);

    // An unpaid request is answered with the price whatever else is wrong with
    // it. A discovery probe sends an empty body on purpose, and answering "your
    // request is malformed" instead of "here is what this costs" leaves the
    // endpoint undiscoverable and unlistable. Quote the specific price when the
    // request is complete enough to price, and the full-cap price otherwise,
    // which clears any request.
    if (!paymentHeader) {
      const quote = known
        ? { model: body.model, ...priceFor(pricing, body.model, Number(body.options?.num_predict)) }
        : null;
      const required = requirements(phase(), quote, version);
      return { status: 402, body: required.body, headers: required.headers };
    }

    // Past here the caller has paid, so a bad request is worth refusing in
    // detail, and refusing it before anything is charged or leased.
    if (!known) {
      return { status: 400, body: { error: "unknown_model", models } };
    }
    if (typeof body.prompt !== "string" || body.prompt.trim() === "") {
      return { status: 400, body: { error: "prompt_required" } };
    }
    if (Buffer.byteLength(body.prompt, "utf8") > MAX_PROMPT_BYTES) {
      return { status: 413, body: { error: "prompt_too_large", max_bytes: MAX_PROMPT_BYTES } };
    }
    const { cap, micros } = priceFor(pricing, body.model, Number(body.options?.num_predict));
    const quote = { model: body.model, cap, micros };
    const payment = await checkPayment(String(paymentHeader), micros, ROUTES.single);
    if (!payment.ok) {
      // A payment already spent on the confidential relay replays there, as
      // raw bytes, and has no JSON result to hand back here.
      if (payment.replay && !payment.replay.relay) {
        return { status: 200, body: { ...payment.replay, replayed: true } };
      }
      // A refused payment is still a 402, and a v2 client reads the terms from
      // the header rather than the body, so it has to carry them here too.
      const refused = requirements(phase(), quote, version, payment.reason);
      return { status: 402, body: refused.body, headers: refused.headers };
    }
    // Warming leases a GPU and pulls models, which takes minutes. Holding the
    // connection through that reads as a hang and times the caller out well
    // before it finishes, so wait only long enough to catch a box that is
    // nearly up and otherwise answer straight away with when to come back.
    const warming = ensureWarm().then(() => null, (err) => err);
    const failure = await Promise.race([warming, sleep(readyWaitMs).then(() => TIMED_OUT)]);
    if (failure === TIMED_OUT) {
      payment.release();
      return busy("warming_up", "A GPU is being leased and the models are being pulled.");
    }
    // Either the warmup failed outright, or the box that was up lapsed between
    // the wait and the pick. The work never started either way, so nothing was
    // charged; what the warmup failed at is what decides whether this is the
    // pool queueing or the pool being down.
    const target = failure ? null : pick();
    if (!target) {
      payment.release();
      const why = failure
        ? String(failure.message ?? failure)
        : "the warm box went away before the request reached it";
      log(`inference has nowhere to run: ${why}`);
      return failure && !failure.capacity
        ? broken("inference_unavailable", why)
        : busy("inference_unavailable", why);
    }
    let result;
    try {
      result = await generate(body, cap, target);
    } catch (err) {
      // A box took the work and could not do it. That is a fault rather than a
      // queue, and it keeps the status a fault gets.
      payment.release();
      log(`inference failed: ${err.message}`);
      return broken("inference_unavailable", String(err.message ?? err));
    }

    const settlement = await settlePayment(payment, micros);
    payment.commit(result);
    if (!settlement || settlement.success) stats.revenue_micros += micros;
    return {
      status: 200,
      body: result,
      headers: settlement ? paymentResponse(version, settlement).headers : {},
    };
  }

  const batchRequirements = (state, quote = null, version = 2, error = null) =>
    requirements(state, quote, version, error, ROUTES.batch);

  /// Every prompt in a batch runs whole on one box, exactly as a single request
  /// does. What the batch adds is that the prompts go out to every box the
  /// gateway holds at once, and that boxes still warming join the work as they
  /// come up rather than after the batch has finished without them.
  async function runBatch({ model, prompts, cap, options }) {
    const results = new Array(prompts.length);
    const queue = prompts.map((prompt, index) => ({ index, prompt, attempts: 0 }));
    const pending = new Set();
    const deadline = now() + batchTimeoutMs;
    let failure = null;

    while (!failure && (queue.length || pending.size)) {
      while (queue.length) {
        const box = pick();
        // One generation per box at a time: a second concurrent request on the
        // same GPU queues inside ollama and buys nothing.
        if (!box || box.inFlight > 0) break;
        const job = queue.shift();
        // The entry, not the promise, is what identifies a running item: two
        // items finishing in the same tick both have to be collected, and a
        // race only ever hands back one of them.
        const entry = {};
        entry.promise = generate({ model, prompt: job.prompt, options }, cap, box).then(
          (result) => ({ entry, job, box, result }),
          (err) => ({ entry, job, box, err }),
        );
        pending.add(entry);
      }

      if (!pending.size) {
        // Nothing warm to hand the rest of the batch to. Worth waiting only
        // while a box is actually on its way up.
        if (!warming.size || now() > deadline) {
          // Marked, because running out of GPU partway is the same shortage as
          // never having one and the caller is owed the same answer.
          failure = Object.assign(
            new Error(
              warming.size ? "the batch ran out of time waiting for a GPU" : "no GPU was available to finish the batch",
            ),
            { capacity: true },
          );
          break;
        }
        await sleep(250);
        continue;
      }

      const outcome = await Promise.race([...pending].map((entry) => entry.promise));
      pending.delete(outcome.entry);
      if (!outcome.err) {
        results[outcome.job.index] = { ...outcome.result, index: outcome.job.index };
        continue;
      }
      // A box that fails one prompt is usually about to fail the rest, so the
      // retry goes to whichever box is free next, not back to the same one.
      log(`batch item ${outcome.job.index} failed on lease ${outcome.box.lease?.leaseId ?? "?"}: ${outcome.err.message}`);
      if (outcome.job.attempts >= 1) {
        failure = outcome.err;
        break;
      }
      queue.unshift({ ...outcome.job, attempts: outcome.job.attempts + 1 });
    }

    // Anything still running was paid for by the same payment as the rest, and
    // the batch is all-or-nothing, so its result is discarded rather than
    // returned half-formed.
    if (failure) {
      await Promise.allSettled([...pending].map((entry) => entry.promise));
      throw failure;
    }
    return results;
  }

  async function handleBatch(body, paymentHeader, paymentVersion = null) {
    const version = paymentVersion ?? 2;
    const known = typeof body?.model === "string" && models.includes(body.model);
    const prompts = Array.isArray(body?.prompts) ? body.prompts : null;
    const priced = known && prompts?.length ? priceFor(pricing, body.model, Number(body.options?.num_predict)) : null;
    const count = prompts?.length ?? 0;

    if (!paymentHeader) {
      const quote = priced
        ? { model: body.model, cap: priced.cap, micros: priced.micros * BigInt(count), count }
        : null;
      const required = batchRequirements(phase(), quote, version);
      return { status: 402, body: required.body, headers: required.headers };
    }

    if (!known) return { status: 400, body: { error: "unknown_model", models } };
    if (!prompts?.length) {
      return { status: 400, body: { error: "prompts_required", detail: "send a non-empty array of prompts" } };
    }
    if (prompts.length > maxBatchItems) {
      return { status: 400, body: { error: "batch_too_large", max_items: maxBatchItems } };
    }
    if (prompts.some((prompt) => typeof prompt !== "string" || prompt.trim() === "")) {
      return { status: 400, body: { error: "prompt_required", detail: "every prompt must be a non-empty string" } };
    }
    if (prompts.some((prompt) => Buffer.byteLength(prompt, "utf8") > MAX_PROMPT_BYTES)) {
      return { status: 413, body: { error: "prompt_too_large", max_bytes: MAX_PROMPT_BYTES } };
    }

    const { cap, micros: unit } = priceFor(pricing, body.model, Number(body.options?.num_predict));
    const micros = unit * BigInt(prompts.length);
    const quote = { model: body.model, cap, micros, count: prompts.length };
    const payment = await checkPayment(String(paymentHeader), micros, ROUTES.batch);
    if (!payment.ok) {
      if (payment.replay && !payment.replay.relay) {
        return { status: 200, body: { ...payment.replay, replayed: true } };
      }
      const refused = batchRequirements(phase(), quote, version, payment.reason);
      return { status: 402, body: refused.body, headers: refused.headers };
    }

    // Enough boxes for the work, capped by what the operator allows. A batch
    // small enough to run on one box never leases a second.
    const wanted = Math.min(pool.length, Math.max(1, Math.ceil(prompts.length / itemsPerBox)));
    const warmingUp = ensureWarm(wanted).then(() => null, (err) => err);
    const failure = await Promise.race([warmingUp, sleep(readyWaitMs).then(() => TIMED_OUT)]);
    if (failure === TIMED_OUT) {
      payment.release();
      return busy("warming_up", "GPUs are being leased and the models are being pulled.");
    }
    if (failure) {
      payment.release();
      const why = String(failure.message ?? failure);
      log(`batch has nowhere to run: ${why}`);
      return failure.capacity ? busy("batch_unavailable", why) : broken("batch_unavailable", why);
    }

    let items;
    try {
      items = await runBatch({ model: body.model, prompts, cap, options: body.options });
    } catch (err) {
      payment.release();
      log(`batch failed: ${err.message}`);
      const why = String(err.message ?? err);
      return err.capacity ? busy("batch_unavailable", why) : broken("batch_unavailable", why);
    }

    const settlement = await settlePayment(payment, micros, " a batch");
    const result = assembleBatch({ items, prompts, model: body.model, payment, micros, settlement });
    stats.batches += 1;
    stats.batch_items += items.length;
    if (!settlement || settlement.success) stats.revenue_micros += micros;
    payment.commit(result);
    return {
      status: 200,
      body: result,
      headers: settlement ? paymentResponse(version, settlement).headers : {},
    };
  }

  /// The response and its receipt. `commitment` is the exact object the leaf
  /// hash is taken over, so verifying an item is a matter of hashing what you
  /// were handed and walking the path to the root.
  function assembleBatch({ items, prompts, model, payment, micros, settlement }) {
    const commitments = items.map((item, index) => ({
      index,
      model,
      prompt: digest(prompts[index]),
      response: digest(item.response ?? ""),
      prompt_tokens: item.usage?.prompt_tokens ?? null,
      completion_tokens: item.usage?.completion_tokens ?? null,
      lease_id: item.lease_id ?? null,
    }));
    const { receipt, proofs } = batchReceipt({
      items: commitments,
      model,
      payer: payment.payer ?? null,
      paidMicros: micros,
      settlement: settlement?.success ? settlement : null,
      issuedAt: now(),
    });
    return {
      model,
      count: items.length,
      items: items.map((item, index) => ({
        index,
        response: item.response,
        usage: item.usage,
        lease_id: item.lease_id,
        commitment: commitments[index],
        merkle_proof: proofs[index],
      })),
      usage: {
        prompt_tokens: items.reduce((n, i) => n + (i.usage?.prompt_tokens ?? 0), 0),
        completion_tokens: items.reduce((n, i) => n + (i.usage?.completion_tokens ?? 0), 0),
      },
      receipt,
    };
  }

  // The confidential class. Nothing below leases, generates, or reshapes a
  // body: the gateway takes payment, forwards the caller's bytes to Phala's
  // attested gateway, and hands back what came out. Byte transparency is the
  // whole point, because the TEE signs a receipt over the request bytes it
  // received and the response bytes it returned, and a relay that re-serialized
  // either one would break every hash the caller checks.

  const spendToday = () => {
    const day = new Date(now()).toISOString().slice(0, 10);
    if (spend.day !== day) {
      spend.day = day;
      spend.usd = 0;
    }
    return spend.usd;
  };

  /// What a request is assumed to cost us until the upstream says otherwise.
  /// The rate card sits well above the upstream catalog price at these caps, so
  /// a figure modelled from it overstates the cost rather than understating it.
  const modelledUsd = (micros) => Number(micros) / 1e6;

  /// The cap is decided on committed plus in-flight: a request holds its
  /// modelled cost from before the round trip until the upstream has either
  /// served it or not. Reserving before the call is what stops concurrent
  /// requests from all reading the same pre-call total and all going through.
  function reserveSpend(usd) {
    if (spendToday() + usd > conf.dailyUsd) return false;
    spend.usd += usd;
    return true;
  }

  /// Gives a reservation back and books what the request actually cost, which
  /// is nothing when the upstream served nothing.
  function settleSpend(reserved, actual = 0) {
    spendToday();
    spend.usd = Math.max(0, spend.usd - reserved + actual);
  }

  const relayCalls = [];
  function relayAllowed() {
    const cutoff = now() - 60_000;
    while (relayCalls.length && relayCalls[0] <= cutoff) relayCalls.shift();
    if (relayCalls.length >= relayPerMinute) return false;
    relayCalls.push(now());
    return true;
  }

  function headersUp(headers) {
    const out = {};
    for (const [name, value] of Object.entries(headers ?? {})) {
      const key = name.toLowerCase();
      if (E2EE_REQUEST_HEADERS.includes(key) && typeof value === "string") out[key] = value;
    }
    return out;
  }

  const sse = (headers) => (headers.get("content-type") ?? "").includes("text/event-stream");

  function headersDown(headers) {
    const out = { "content-type": headers.get("content-type") ?? "application/json" };
    for (const name of RELAY_RESPONSE_HEADERS) {
      const value = headers.get(name);
      if (value != null) out[name] = value;
    }
    return out;
  }

  /// Reads an upstream response whole. The bytes are what the caller gets and
  /// what the receipt is signed over, so they are never decoded and re-encoded.
  async function readUpstream(res) {
    return { status: res.status, headers: headersDown(res.headers), bytes: Buffer.from(await res.arrayBuffer()) };
  }

  /// Reads a streamed upstream response, handing each chunk on as it lands and
  /// keeping a copy of it. The copy is not something the caller waits behind:
  /// it is what the enclave signed its receipt over, what the usage frame is
  /// read out of, and what a reconnecting client replays, and `max_tokens`
  /// bounds it at the same size a buffered answer would have been anyway.
  ///
  /// The read runs on its own rather than on whoever is consuming it. A caller
  /// that hangs up halfway through has still bought a whole generation, so the
  /// rest of it is read, paid for, and kept for the reconnect to replay.
  function pumpUpstream(body) {
    const chunks = [];
    let wake = null;
    let ended = false;
    let failure = null;
    const drained = (async () => {
      try {
        for await (const chunk of body) {
          chunks.push(Buffer.from(chunk));
          wake?.();
        }
      } catch (err) {
        failure = err;
      }
      ended = true;
      wake?.();
    })();
    return {
      chunks,
      drained,
      failure: () => failure,
      async *arriving() {
        for (let sent = 0; ;) {
          while (sent < chunks.length) yield chunks[sent++];
          if (ended) return;
          await new Promise((resolve) => {
            wake = resolve;
          });
        }
      },
    };
  }

  const disabled = () => ({ status: 404, body: { error: "confidential_disabled" } });

  /// A free pass-through to one of the TEE's transparency endpoints. The
  /// upstream bearer stays here; what the caller gets back is the document.
  async function relayGet(path, { auth = false, label } = {}) {
    if (!relayAllowed()) {
      return { status: 429, headers: { "retry-after": "60" }, body: { error: "rate_limited" } };
    }
    try {
      const res = await fetchUpstream(`${conf.upstream}${path}`, {
        method: "GET",
        headers: {
          accept: "application/json",
          ...(auth ? { authorization: `Bearer ${conf.key}` } : {}),
        },
        signal: AbortSignal.timeout(relayTimeoutMs),
      });
      return await readUpstream(res);
    } catch (err) {
      log(`${label} relay failed: ${err.message}`);
      return { status: 503, body: { error: "upstream_unavailable" } };
    }
  }

  async function attestation(nonce) {
    if (!conf) return disabled();
    if (typeof nonce !== "string" || !HEX_64.test(nonce)) {
      return {
        status: 400,
        body: {
          error: "invalid_nonce",
          detail: "nonce must be 64 lowercase hex characters, freshly chosen by the caller",
        },
      };
    }
    return relayGet(`/aci/attestation?nonce=${nonce}`, { label: "attestation" });
  }

  // Receipts are owned upstream by whoever paid for the completion, and that is
  // this gateway's bearer. Relaying them under our own key is what makes a
  // receipt reachable for the agent that bought the generation.
  async function receipt(id) {
    if (!conf) return disabled();
    if (typeof id !== "string" || !RECEIPT_ID.test(id)) {
      return { status: 400, body: { error: "invalid_receipt_id" } };
    }
    return relayGet(`/aci/receipts/${encodeURIComponent(id)}`, { auth: true, label: "receipt" });
  }

  async function session(id) {
    if (!conf) return disabled();
    if (typeof id !== "string" || !HEX_64.test(id)) {
      return { status: 400, body: { error: "invalid_session_id" } };
    }
    return relayGet(`/aci/sessions/${id}`, { label: "session" });
  }

  async function sessions({ model = null, upstreamName = null } = {}) {
    if (!conf) return disabled();
    if (model != null && !conf.pricing[model]) {
      return { status: 400, body: { error: "unknown_model", models: confModels } };
    }
    if (upstreamName != null && !UPSTREAM_NAME.test(upstreamName)) {
      return { status: 400, body: { error: "invalid_upstream_name" } };
    }
    const query = new URLSearchParams();
    if (model) query.set("model", model);
    if (upstreamName) query.set("upstream_name", upstreamName);
    const suffix = query.size ? `?${query}` : "";
    return relayGet(`/aci/sessions${suffix}`, { label: "sessions" });
  }

  /// The GPU leg. This body is what NVIDIA's attestation service wants posted
  /// to it, and only the general host publishes it, so it does not go through
  /// `relayGet`.
  /// The model is served by several instances of one workload, and the upstream
  /// answers this route from whichever one it picks, so evidence fetched blind
  /// describes a sibling of the instance that served a given completion about
  /// two times in three. Everything below RTMR3 matches in that case, which is
  /// precisely why it cannot be waved through: RTMR3 carries the instance, and
  /// binding the GPU leg to the serving TD is the whole point of the check.
  ///
  /// `keysetDigest` lets a caller name the instance it needs. The upstream is
  /// asked again until one answers with that key set, which works because the
  /// choice is per request. The last answer is returned either way; deciding
  /// whether it binds belongs to the verifier, not here.
  // One GPU evidence answer per instance, keyed by the key set that gave it.
  const remember = new Map();

  async function gpuEvidence(model, keysetDigest = null) {
    if (!conf) return disabled();
    if (typeof model !== "string" || !conf.pricing[model]) {
      return { status: 400, body: { error: "unknown_model", models: confModels } };
    }
    if (keysetDigest != null && !KEYSET_DIGEST.test(keysetDigest)) {
      return { status: 400, body: { error: "invalid_keyset_digest" } };
    }
    if (!relayAllowed()) {
      return { status: 429, headers: { "retry-after": "60" }, body: { error: "rate_limited" } };
    }
    // Which instances the upstream offers drifts over minutes, so the retries
    // below miss in bursts: inside one of those windows every attempt reaches
    // the wrong set however many are made. Evidence is a standing artifact
    // about an instance rather than an answer to this request, so the way out
    // is to keep what previous requests saw. Every answer is kept under the
    // instance that gave it, and a few minutes of traffic accumulates one per
    // instance, after which the drift stops mattering.
    const held = keysetDigest ? remember.get(keysetDigest) : null;
    if (held && now() - held.at < GPU_EVIDENCE_TTL_MS) return held.relayed;

    const attempts = keysetDigest ? GPU_EVIDENCE_ATTEMPTS : 1;
    let last = null;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        const res = await fetchUpstream(
          `${conf.legacyUpstream}/attestation/report?model=${encodeURIComponent(model)}`,
          { method: "GET", headers: { accept: "application/json" }, signal: AbortSignal.timeout(relayTimeoutMs) },
        );
        last = await readUpstream(res);
      } catch (err) {
        log(`gpu evidence relay failed: ${err.message}`);
        return last ?? { status: 503, body: { error: "upstream_unavailable" } };
      }
      const reached = servedKeyset(last);
      if (reached) keep(reached, last);
      if (!keysetDigest || reached === keysetDigest) return last;
    }
    log(`gpu evidence: ${attempts} attempts did not reach key set ${keysetDigest}`);
    return last;
  }

  /// Hold one answer per instance, dropping whatever was seen longest ago once
  /// there are more than a fleet's worth. The TTL is well inside the NVIDIA
  /// token's life, so nothing served from here is evidence the verifier would
  /// have rejected had it fetched the same thing itself.
  function keep(digest, relayed) {
    if (remember.has(digest)) remember.delete(digest);
    remember.set(digest, { at: now(), relayed });
    while (remember.size > GPU_EVIDENCE_HELD) remember.delete(remember.keys().next().value);
  }

  /// What a served confidential generation costs, earns and is logged as. None
  /// of it depends on whether the answer arrived whole or in frames, so both
  /// paths book it here, and both take the money last.
  ///
  /// Everything up to the broadcast runs before the first await, so a caller
  /// that already holds the answer can be let go the moment this is called: the
  /// payment is recorded as spent and the bytes are held for a replay before
  /// the chain is touched, and only the settlement outcome arrives later.
  async function bookConfidential({ model, usage, modelled, micros, payment, relay, note = "" }) {
    // What the upstream says it charged replaces the reservation. When it says
    // nothing, the modelled figure stands as the charge.
    const cost = usage.cost ?? modelled;
    settleSpend(modelled, cost);
    stats.confidential_cost_usd += cost;
    if (usage.cost == null && !costUnreported) {
      costUnreported = true;
      log(
        "confidential upstream reported no usage.cost; the modelled price of each request " +
          "is charged against the daily cap until it does",
      );
    }
    stats.confidential_generations += 1;
    stats.confidential_tokens_in += usage.prompt_tokens ?? 0;
    stats.confidential_tokens_out += usage.completion_tokens ?? 0;
    // Model, usage, cost, receipt id. Message content never reaches a log line,
    // and under e2ee it never reaches this process in the clear at all.
    log(
      `confidential ${model}${note} in=${usage.prompt_tokens ?? "?"} out=${usage.completion_tokens ?? "?"} ` +
        `cost=${usage.cost ?? `~${modelled.toFixed(6)}`} receipt=${relay.headers["x-receipt-id"] ?? "none"}`,
    );

    payment.commit({ relay });
    const settlement = await settlePayment(payment, micros, " a confidential request");
    if (!settlement || settlement.success) stats.revenue_micros += micros;
    return settlement;
  }

  /// Books a finished stream and says whether it was one. `[DONE]` is the only
  /// thing that makes a stream the answer, so it is the only thing asked here:
  /// a connection that drops after the terminator delivered the whole of what
  /// the enclave signed, and a caller told otherwise would be handed an error
  /// frame after the frame it stops reading at, over bytes it already paid for
  /// and can still verify. An answer that stopped short is charged for neither.
  ///
  /// The verdict is the caller's to have straight away. The booking behind it
  /// is not: it reaches the chain, and by the time it starts the caller holds
  /// every frame, so it is left running rather than waited on.
  function finishStream(status, headers, answer, failure, ctx) {
    if (!answer.done) {
      ctx.payment.release();
      settleSpend(ctx.modelled);
      log(
        `confidential stream for ${ctx.model} stopped after ${answer.bytes.length} bytes: ` +
          `${failure?.message ?? "the upstream closed without a terminator"}`,
      );
      return false;
    }
    bookConfidential({
      ...ctx,
      usage: answer.usage,
      relay: { status, headers, bytes: answer.bytes },
      // A drop after the terminator changes nothing about what was served, but
      // it is the difference between a clean close and a reset on the wire.
      note: failure ? " stream (dropped after the terminator)" : " stream",
    }).catch((err) => log(`confidential stream bookkeeping failed for ${ctx.model}: ${err.message}`));
    return true;
  }

  /// A streamed answer, from the moment the enclave commits to serving one.
  ///
  /// Settlement stays where the buffered path puts it, after the last byte and
  /// never before, so a stream that dies halfway costs its caller nothing. What
  /// that costs is the PAYMENT-RESPONSE header, which reports a broadcast that
  /// has not happened when the head is written. A streamed answer carries none,
  /// and the settlement is where every other one is, on the chain the
  /// authorization named. Moving the broadcast ahead of the first frame would
  /// buy the header back at the cost of charging for answers that never
  /// finished, and it would put a chain round trip in front of the first token.
  ///
  /// What a caller sees when the enclave stops mid-stream: the 200 and the
  /// frames already sent stand, because a status cannot be withdrawn once it is
  /// on the wire, and the relay closes with an error frame naming the
  /// truncation and the payment it did not take. That frame is the only thing
  /// the relay ever adds to a body, and it can only reach a stream that never
  /// carried its terminator, whose receipt hash the caller had already lost.
  ///
  /// Nothing else is allowed to hold the body open. Whether the terminator
  /// arrived is known the moment the last byte does, and that is the only thing
  /// still to be decided; the broadcast that follows takes seconds the caller
  /// would spend waiting on a response it has already read in full.
  function relayStream(res, ctx) {
    const headers = headersDown(res.headers);
    const upstream = pumpUpstream(res.body);
    let read = null;
    // The bytes as they went out, which is what the enclave signed its receipt
    // over. Read once the stream has ended, and only then.
    const answer = () => {
      if (!read) {
        const bytes = Buffer.concat(upstream.chunks);
        read = { bytes, ...readStream(bytes) };
      }
      return read;
    };
    const whole = upstream.drained
      .then(() => finishStream(res.status, headers, answer(), upstream.failure(), ctx))
      .catch((err) => {
        // An error frame appended to an answer that may well be whole is the
        // worse of the two mistakes available here.
        log(`confidential stream could not be closed out for ${ctx.model}: ${err.message}`);
        return true;
      });
    return {
      status: res.status,
      headers,
      stream: (async function* () {
        yield* upstream.arriving();
        if (!(await whole)) yield STREAM_TRUNCATED;
      })(),
    };
  }

  async function handleConfidential(raw, headers = {}, paymentHeader, paymentVersion = null) {
    const version = paymentVersion ?? 2;
    if (!conf) return disabled();
    const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw ?? "");
    const body = bytes.length && bytes.length <= maxConfidentialBytes ? peek(bytes) : null;
    const model = typeof body?.model === "string" ? body.model : null;
    const known = model != null && conf.pricing[model] != null;
    // The only other field the gateway reads. A cap it cannot rewrite is a cap
    // the caller has to state.
    const asked = Number.isInteger(body?.max_tokens) ? body.max_tokens : null;

    if (!paymentHeader) {
      const quote = known ? { model, ...priceFor(conf.pricing, model, asked) } : null;
      const required = requirements("relay", quote, version, null, ROUTES.confidential);
      return { status: 402, body: required.body, headers: required.headers };
    }

    if (!bytes.length) return { status: 400, body: { error: "body_required" } };
    if (bytes.length > maxConfidentialBytes) {
      return { status: 413, body: { error: "body_too_large", max_bytes: maxConfidentialBytes } };
    }
    if (!body) return { status: 400, body: { error: "invalid_json" } };
    if (!known) return { status: 400, body: { error: "unknown_model", models: confModels } };
    if (!Array.isArray(body.messages) || body.messages.length === 0) {
      return { status: 400, body: { error: "messages_required" } };
    }
    if (body.n != null && body.n !== 1) {
      return { status: 400, body: { error: "n_unsupported", detail: "one completion per paid request" } };
    }
    // The body goes upstream untouched, so an unbounded or oversized cap cannot
    // be clamped on the way. It is refused instead, before anything is charged.
    if (asked == null || asked < 1 || asked > MAX_PREDICT_TOKENS) {
      return {
        status: 400,
        body: {
          error: "max_tokens_required",
          max: MAX_PREDICT_TOKENS,
          detail: `send an integer max_tokens between 1 and ${MAX_PREDICT_TOKENS}; the price is quoted on it`,
        },
      };
    }

    const { cap, micros } = priceFor(conf.pricing, model, asked);
    const modelled = modelledUsd(micros);
    // The day's budget is a limit the operator set, not a fault, so it answers
    // the way any other exhausted allowance does.
    if (!reserveSpend(modelled)) {
      return {
        status: 429,
        headers: { "retry-after": "3600" },
        body: {
          error: "spend_cap_reached",
          detail: "the confidential relay has reached its daily upstream spend cap",
          retry_after_seconds: 3600,
          retry: "nothing was charged; the cap resets at 00:00 UTC",
        },
      };
    }

    const payment = await checkPayment(String(paymentHeader), micros, ROUTES.confidential);
    if (!payment.ok) {
      settleSpend(modelled);
      const replay = payment.replay?.relay;
      if (replay) {
        return { status: replay.status, bytes: replay.bytes, headers: { ...replay.headers, "x-prism-replayed": "true" } };
      }
      const refused = requirements("relay", { model, cap, micros }, version, payment.reason, ROUTES.confidential);
      return { status: 402, body: refused.body, headers: refused.headers };
    }

    // The caller's own body is what asks for a stream; all the relay adds is
    // the accept header that goes with the ask.
    const wantsStream = Boolean(body.stream);
    let upstream;
    try {
      const res = await fetchUpstream(`${conf.upstream}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: wantsStream ? "text/event-stream" : "application/json",
          authorization: `Bearer ${conf.key}`,
          ...headersUp(headers),
        },
        body: bytes,
        signal: AbortSignal.timeout(confidentialTimeoutMs),
      });
      // Asking for a stream is not being given one. Until the enclave has
      // answered with frames, nothing has been served and everything below
      // still applies: a refusal is read whole and answered with a status the
      // caller can act on.
      if (wantsStream && res.ok && res.body && sse(res.headers)) {
        return relayStream(res, { model, modelled, micros, payment });
      }
      upstream = await readUpstream(res);
    } catch (err) {
      payment.release();
      settleSpend(modelled);
      log(`confidential relay failed for ${model}: ${err.message}`);
      return {
        status: 503,
        body: {
          error: "upstream_unavailable",
          detail: String(err.message ?? err),
          retry: "the payment was not consumed; retry with the same payment header",
        },
      };
    }

    if (upstream.status < 200 || upstream.status >= 300) {
      payment.release();
      settleSpend(modelled);
      log(`confidential upstream answered ${upstream.status} for ${model}`);
      // Exhausted quota, a rate limit, or a fault upstream: none of it is the
      // caller's to fix, and none of it took their money.
      if (upstream.status >= 500 || upstream.status === 403 || upstream.status === 429) {
        return {
          status: 503,
          body: {
            error: "upstream_unavailable",
            upstream_status: upstream.status,
            retry: "the payment was not consumed; retry with the same payment header",
          },
        };
      }
      // A rejected request is worth quoting back, bounded, because the caller
      // is the only one who can correct it.
      return {
        status: 400,
        body: {
          error: "upstream_rejected",
          upstream_status: upstream.status,
          detail: upstream.bytes.toString("utf8").slice(0, 500),
          retry: "the payment was not consumed; fix the request and retry with the same payment header",
        },
      };
    }

    const settlement = await bookConfidential({
      model,
      usage: readUsage(upstream.bytes),
      modelled,
      micros,
      payment,
      relay: { status: upstream.status, headers: upstream.headers, bytes: upstream.bytes },
    });
    return {
      status: upstream.status,
      bytes: upstream.bytes,
      headers: {
        ...upstream.headers,
        ...(settlement ? paymentResponse(version, settlement).headers : {}),
      },
    };
  }

  function confidentialView() {
    if (!conf) return {};
    return {
      confidential: {
        endpoint: publicPath(ROUTES.confidential.path),
        attestation: publicPath("/v1/attestation"),
        receipts: publicPath("/v1/receipts/{id}"),
        sessions: publicPath("/v1/sessions"),
        gpu_evidence: publicPath("/v1/gpu-evidence"),
        upstream: conf.upstream,
        price_micros: maxConfidentialMicros.toString(),
        max_tokens: MAX_PREDICT_TOKENS,
        max_body_bytes: maxConfidentialBytes,
        models: Object.fromEntries(
          confModels.map((m) => [m, {
            base_micros: conf.pricing[m].base,
            per_token_micros: conf.pricing[m].perToken,
            full_cap_micros: confFullCap(m).toString(),
            confidential: true,
            // The GPU model is not ours to assert: the verified NVIDIA claim is
            // the only place one is named.
            tee: "intel-tdx + nvidia",
            provider: "phala",
            e2ee: true,
            attestation: publicPath("/v1/attestation"),
          }]),
        ),
      },
    };
  }

  return {
    state: () => {
      const first = warmBoxes()[0] ?? null;
      return {
        phase: phase(),
        lease_id: first?.lease?.leaseId ?? null,
        expires_at: first?.expiresAt || null,
        ...poolView(),
      };
    },
    models: () => ({
      models,
      // The highest full-cap price: paying it clears any request. Per-model
      // detail sits alongside for clients that quote per request.
      price_micros: maxPriceMicros.toString(),
      pricing: Object.fromEntries(
        models.map((m) => [m, {
          base_micros: pricing[m].base,
          per_token_micros: pricing[m].perToken,
          full_cap_micros: fullCap(m).toString(),
        }]),
      ),
      pay_to: payTo,
      ...confidentialView(),
      ...boxView(),
    }),
    stats: () => ({
      since: new Date(stats.since).toISOString(),
      generations: stats.generations,
      tokens_in: stats.tokens_in,
      tokens_out: stats.tokens_out,
      revenue_micros: stats.revenue_micros.toString(),
      leases_warmed: stats.leases_warmed,
      // Served but not paid for. Worth watching: a rising count is either an
      // rpc fault or someone racing the broadcast.
      unsettled: stats.unsettled,
      unsettled_micros: stats.unsettled_micros.toString(),
      unconfirmed: stats.unconfirmed,
      batches: stats.batches,
      batch_items: stats.batch_items,
      ...(conf
        ? {
            confidential_generations: stats.confidential_generations,
            confidential_tokens_in: stats.confidential_tokens_in,
            confidential_tokens_out: stats.confidential_tokens_out,
            confidential_cost_usd: Number(stats.confidential_cost_usd.toFixed(6)),
            confidential_spend_today_usd: Number(spendToday().toFixed(6)),
            confidential_daily_cap_usd: conf.dailyUsd,
          }
        : {}),
      ...boxView(),
    }),
    ensureWarm,
    maintain,
    drainAll,
    handleInference,
    handleBatch,
    handleConfidential,
    attestation,
    receipt,
    session,
    sessions,
    gpuEvidence,
    confidential: () => confidentialView().confidential ?? null,
    requirements: () => requirements(phase()).body,
    batchRequirements: () => batchRequirements(phase()).body,
    confidentialRequirements: () => requirements("relay", null, 2, null, ROUTES.confidential).body,
  };

  /// One line for the whole pool, so a caller reading `/v1/models` learns how
  /// much of the network is behind the endpoint right now.
  function poolView() {
    const warm = warmBoxes();
    return {
      pool: {
        warm: warm.length,
        max: pool.length,
        in_flight: pool.reduce((n, b) => n + b.inFlight, 0),
        lease_ids: warm.map((b) => b.lease?.leaseId ?? null).filter((id) => id != null),
      },
    };
  }

  function boxView() {
    const first = warmBoxes()[0] ?? null;
    return { state: phase(), lease_id: first?.lease?.leaseId ?? null, ...poolView() };
  }
}
