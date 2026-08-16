// The managed-inference core: a warm GPU lease running ollama, fronted by an
// x402-paid HTTP surface. One paid request, one generation, no SSH or lease
// lifecycle on the caller's side.
//
// Everything with a side effect arrives through `deps`, so the whole state
// machine is testable with fakes: `agent` (the Prism SDK surface it uses),
// `spawnTunnel` (ssh -L to the box's ollama), `fetchOllama`, and `verify`
// (on-chain payment verification).
import { appendFileSync, existsSync, readFileSync } from "node:fs";

export const DEFAULT_PRICE_MICROS = 10_000n;
export const MAX_PROMPT_BYTES = 32 * 1024;
export const MAX_PREDICT_TOKENS = 1_024;

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
  priceMicros = DEFAULT_PRICE_MICROS,
  pricing: pricingIn = null,
  image,
  durationSeconds = 1800,
  minVramMib = 16000,
  idleMs = 600_000,
  coolDownMs = 240_000,
  warmTimeoutMs = 480_000,
  generateTimeoutMs = 120_000,
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
  const stats = { since: now(), generations: 0, tokens_in: 0, tokens_out: 0, revenue_micros: 0n, leases_warmed: 0 };

  const consumed = loadConsumed(paymentsFile);
  // A client that paid and then lost the connection must be able to fetch what
  // it paid for: a consumed tx hash answers with its own result, not a refusal.
  const served = new Map();
  const SERVED_CAP = 200;
  const box = { phase: "cold", lease: null, tunnel: null, expiresAt: 0, lastUsed: 0 };
  let warming = null;
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
    if (!TX_HASH.test(hash)) throw new Error("refusing to record a malformed transaction hash");
    if (!paymentsFile) return;
    try {
      appendFileSync(paymentsFile, `${hash}\n`);
    } catch (err) {
      log(`failed to persist consumed payment: ${err.message}`);
    }
  }

  async function warmUp() {
    box.phase = "warming";
    let lease;
    try {
      lease = await agent.lease({ image, durationSeconds, minVramMib });
    } catch (err) {
      // Nothing was funded when the match itself fails, but hammering the
      // network with fresh quote attempts helps nobody.
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
      const tunnel = await spawnTunnel(lease);
      // The tunnel is up when ollama answers through it.
      const deadline = now() + 60_000;
      for (;;) {
        try {
          const res = await fetchOllama("/api/tags", { method: "GET" });
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
      log(`warm: lease ${lease.leaseId}, models ${models.join(", ")}`);
    } catch (err) {
      // The lease is paid for either way; drop only what this process holds,
      // and hold off before leasing again: every failed warmup costs a full
      // lease, so a persistent fault must not chain them.
      agent.endLease(lease);
      box.phase = "cold";
      coolUntil = now() + coolDownMs;
      throw err;
    }
  }

  function ensureWarm() {
    if (box.phase === "warm") return Promise.resolve();
    if (now() < coolUntil) {
      return Promise.reject(
        new Error(`warmup is cooling down after a failure; retry in ${Math.ceil((coolUntil - now()) / 1000)}s`),
      );
    }
    if (!warming) {
      warming = warmUp().finally(() => {
        warming = null;
      });
    }
    return warming;
  }

  function drain(reason) {
    if (box.tunnel) box.tunnel.close();
    if (box.lease) agent.endLease(box.lease);
    log(`drained (${reason})`);
    box.phase = "cold";
    box.lease = null;
    box.tunnel = null;
    box.expiresAt = 0;
  }

  // Called on an interval by the server (and directly by tests): let an idle
  // box lapse, renew a busy one before its lease expires.
  async function maintain() {
    if (box.phase !== "warm") return;
    const idle = now() - box.lastUsed > idleMs;
    const nearExpiry = now() > box.expiresAt - 120_000;
    if (now() > box.expiresAt) return drain("lease expired");
    if (!nearExpiry) return;
    if (idle) return drain("idle at renewal time");
    drain("renewing");
    await ensureWarm().catch((err) => log(`renewal failed: ${err.message}`));
  }

  function requirements(state, quote = null) {
    const amount = quote?.micros ?? maxPriceMicros;
    return {
      x402Version: 1,
      state,
      ...(quote ? { quote: { model: quote.model, output_cap: quote.cap, price_micros: amount.toString() } } : {}),
      accepts: [
        {
          scheme: "exact",
          network: "eip155:4663",
          asset: "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168",
          payTo,
          maxAmountRequired: amount.toString(),
          resource: "/v1/inference",
          description:
            "One generation on a Prism GPU, paid in USDG on Robinhood Chain. The price covers the " +
            "requested output cap for the requested model. Pay maxAmountRequired to payTo, then retry " +
            "with header X-PAYMENT: base64({txHash, signature}) where signature is a personal_sign of " +
            "the tx hash.",
          mimeType: "application/json",
        },
      ],
    };
  }

  async function checkPayment(header, quotedMicros) {
    let txHash;
    let signature;
    try {
      ({ txHash, signature } = JSON.parse(Buffer.from(header, "base64").toString("utf8")));
    } catch {
      return { ok: false, reason: "malformed_payment" };
    }
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

  async function generate(body, cap) {
    const options = { ...(body.options ?? {}), num_predict: cap };
    const res = await fetchOllama("/api/generate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: body.model, prompt: body.prompt, stream: false, options }),
      signal: AbortSignal.timeout(generateTimeoutMs),
    });
    if (!res.ok) throw new Error(`ollama answered ${res.status}`);
    const out = await res.json();
    box.lastUsed = now();
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

  async function handleInference(body, paymentHeader) {
    if (typeof body?.model !== "string" || !models.includes(body.model)) {
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
    if (!paymentHeader) return { status: 402, body: requirements(box.phase, quote) };
    const payment = await checkPayment(String(paymentHeader), micros);
    if (!payment.ok) {
      if (payment.replay) return { status: 200, body: { ...payment.replay, replayed: true } };
      return { status: 402, body: { ...requirements(box.phase, quote), error: payment.reason } };
    }
    try {
      await ensureWarm();
      const result = await generate(body, cap);
      payment.commit(result);
      stats.revenue_micros += micros;
      return { status: 200, body: result };
    } catch (err) {
      payment.release();
      log(`inference failed: ${err.message}`);
      return {
        status: 503,
        body: {
          error: "inference_unavailable",
          detail: String(err.message ?? err),
          state: box.phase,
          retry: "the payment was not consumed; retry with the same X-PAYMENT header",
        },
      };
    }
  }

  return {
    state: () => ({ phase: box.phase, lease_id: box.lease?.leaseId ?? null, expires_at: box.expiresAt || null }),
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
      ...boxView(),
    }),
    ensureWarm,
    maintain,
    drain,
    handleInference,
    requirements: () => requirements(box.phase),
  };

  function boxView() {
    return { state: box.phase, lease_id: box.lease?.leaseId ?? null };
  }
}
