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

export const DEFAULT_PRICE_MICROS = 10_000n;
export const MAX_PROMPT_BYTES = 32 * 1024;
export const MAX_PREDICT_TOKENS = 1_024;
export const MAX_BATCH_ITEMS = 64;

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
    resource: "One LLM generation on a rented GPU, priced per request.",
  },
  batch: {
    path: "/v1/batch",
    unit: "A batch of independent generations",
    resource:
      "Many independent prompts in one paid call, spread across the rented GPUs the gateway " +
      "holds, returned with a Merkle receipt over the set.",
  },
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
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
  priceMicros = DEFAULT_PRICE_MICROS,
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
  retryAfterMs = 90_000,
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
  log = (line) => console.error(line),
  now = () => Date.now(),
}) {
  if (!models?.length) throw new Error("at least one model is required");
  const pricing = {};
  for (const m of models) {
    const p = pricingIn?.[m] ?? {};
    pricing[m] = { base: Number(p.base ?? priceMicros), perToken: Number(p.per_token ?? p.perToken ?? 0) };
    if (!Number.isFinite(pricing[m].base) || pricing[m].base < 0 || !Number.isFinite(pricing[m].perToken) || pricing[m].perToken < 0) {
      throw new Error(`pricing for ${m} must be non-negative numbers`);
    }
  }
  const fullCap = (m) => priceFor(pricing, m, null).micros;
  const maxPriceMicros = models.map(fullCap).reduce((a, b) => (a > b ? a : b));
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
  };

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

  async function warmUp(box) {
    box.phase = "warming";
    let lease;
    try {
      lease = await agent.lease({ image, durationSeconds, minVramMib });
    } catch (err) {
      // Nothing was funded when the match itself fails, but hammering the
      // network with fresh quote attempts helps nobody. Say why: every later
      // caller is told only that a cooldown is running, so a cause that is not
      // written down here cannot be recovered from outside at all.
      log(`warmup failed while leasing: ${err.message}`);
      box.phase = "cold";
      coolUntil = now() + coolDownMs;
      throw err;
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
      coolUntil = now() + coolDownMs;
      // A lease was paid for and is being dropped, so this is the expensive
      // failure and the one worth naming precisely.
      log(`warmup failed after lease ${lease.leaseId}: ${err.message}`);
      throw err;
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
      return Promise.reject(
        now() < coolUntil
          ? new Error(`warmup is cooling down after a failure; retry in ${Math.ceil((coolUntil - now()) / 1000)}s`)
          : new Error("no slot is free to warm"),
      );
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
  const schemasFor = (route) => (route === ROUTES.batch ? batchSchemas ?? schemas : schemas);

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
          `${route.unit} on Prism GPUs, paid in USDC on Base. Sign an EIP-3009 ` +
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
        `${route.unit} on Prism GPUs, paid in USDG on Robinhood Chain, which is where the ` +
        "serving leases settle. Sign an EIP-3009 transferWithAuthorization for the quoted amount " +
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
    const amount = quote?.micros ?? maxPriceMicros;
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
      if (payment.replay) return { status: 200, body: { ...payment.replay, replayed: true } };
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
      return {
        status: 503,
        headers: { "retry-after": String(Math.ceil(retryAfterMs / 1000)) },
        body: {
          error: "warming_up",
          detail: "A GPU is being leased and the models are being pulled.",
          state: phase(),
          retry_after_seconds: Math.ceil(retryAfterMs / 1000),
          retry: "nothing was charged; send the same payment header again.",
        },
      };
    }
    let result;
    try {
      if (failure) throw failure;
      const target = pick();
      if (!target) throw new Error("the warm box went away before the request reached it");
      result = await generate(body, cap, target);
    } catch (err) {
      payment.release();
      log(`inference failed: ${err.message}`);
      return {
        status: 503,
        body: {
          error: "inference_unavailable",
          detail: String(err.message ?? err),
          state: phase(),
          retry: "the payment was not consumed; retry with the same payment header",
        },
      };
    }

    // Under the exact scheme nothing has moved until this call, so the money is
    // taken only once there is something to hand back. The exposure is the
    // reverse window: a payer who empties their wallet between verification and
    // this broadcast gets one generation free. That is bounded by a single
    // request's price, needs a deliberate race, and is cheaper to absorb than a
    // refund path that can fail on its own.
    let settlement = null;
    if (payment.settle) {
      try {
        settlement = await payment.settle();
      } catch (err) {
        // The broadcast may well have gone through, so this cannot throw out of
        // here: the caller has already paid for work that is already done, and
        // a 500 would hand them nothing for it.
        settlement = { success: false, settled: null, errorReason: "settlement_unconfirmed", payer: payment.payer };
        log(`settlement threw after serving: ${err.message}`);
      }
      if (!settlement.success) {
        // `settled === null` means the money may have moved and we could not
        // read whether it did, which is not the same as being unpaid. Counting
        // it as revenue would overstate; counting it as a loss would understate.
        // It is recorded apart from both.
        if (settlement.settled === null) {
          stats.unconfirmed += 1;
          log(`settlement unconfirmed: tx=${settlement.transaction ?? "none"} payer=${payment.payer} detail=${settlement.detail ?? "none"}`);
        } else {
          stats.unsettled += 1;
          stats.unsettled_micros += micros;
          log(`settlement failed after serving: ${settlement.errorReason ?? "unknown"} payer=${payment.payer} detail=${settlement.detail ?? "none"}`);
        }
        payment.commit(result);
        return { status: 200, body: result, headers: paymentResponse(version, settlement).headers };
      }
    }

    payment.commit(result);
    stats.revenue_micros += micros;
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
          failure = new Error(
            warming.size ? "the batch ran out of time waiting for a GPU" : "no GPU was available to finish the batch",
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
      if (payment.replay) return { status: 200, body: { ...payment.replay, replayed: true } };
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
      return {
        status: 503,
        headers: { "retry-after": String(Math.ceil(retryAfterMs / 1000)) },
        body: {
          error: "warming_up",
          detail: "GPUs are being leased and the models are being pulled.",
          state: phase(),
          retry_after_seconds: Math.ceil(retryAfterMs / 1000),
          retry: "nothing was charged; send the same payment header again.",
        },
      };
    }

    let items;
    try {
      if (failure) throw failure;
      items = await runBatch({ model: body.model, prompts, cap, options: body.options });
    } catch (err) {
      payment.release();
      log(`batch failed: ${err.message}`);
      return {
        status: 503,
        body: {
          error: "batch_unavailable",
          detail: String(err.message ?? err),
          state: phase(),
          retry: "nothing was charged; retry with the same payment header",
        },
      };
    }

    let settlement = null;
    if (payment.settle) {
      try {
        settlement = await payment.settle();
      } catch (err) {
        settlement = { success: false, settled: null, errorReason: "settlement_unconfirmed", payer: payment.payer };
        log(`settlement threw after serving a batch: ${err.message}`);
      }
      if (!settlement.success) {
        if (settlement.settled === null) {
          stats.unconfirmed += 1;
          log(`batch settlement unconfirmed: tx=${settlement.transaction ?? "none"} payer=${payment.payer}`);
        } else {
          stats.unsettled += 1;
          stats.unsettled_micros += micros;
          log(`batch settlement failed after serving: ${settlement.errorReason ?? "unknown"} payer=${payment.payer}`);
        }
      }
    }

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
      ...boxView(),
    }),
    ensureWarm,
    maintain,
    drainAll,
    handleInference,
    handleBatch,
    requirements: () => requirements(phase()).body,
    batchRequirements: () => batchRequirements(phase()).body,
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
