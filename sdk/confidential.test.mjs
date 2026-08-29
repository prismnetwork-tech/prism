import assert from "node:assert/strict";
import { createHash, createPublicKey } from "node:crypto";
import test from "node:test";

import { PrismAgent } from "./prism.mjs";
import { encryptChatRequest, privateKeyFromSeed, rawPublicKey, X25519_SUITE } from "./e2ee.mjs";
import { computeKeysetDigest, computeReportData, replayRtmr3, toHex } from "./vendor/aci-verifier/index.mjs";

const MODEL = "phala/gemma-4-26b-a4b-uncensored";
const PAY_TO = "0x1111111111111111111111111111111111111111";
const PRICE = "3560";
const SERVICE_SEED = Buffer.alloc(32, 3);
const servicePrivate = privateKeyFromSeed(SERVICE_SEED);
const SERVICE_PUBLIC = Buffer.from(rawPublicKey(createPublicKey(servicePrivate))).toString("hex");

// The workload this file's stub gateway claims to be, and the pin the client is
// given to hold it against.
const TEST_COMMIT = "a1".repeat(20);
const TEST_WORKLOAD = {
  launcherImage: `ghcr.io/example/launcher@sha256:${"5c".repeat(32)}`,
  repoUrl: "https://example.test/gateway.git",
  osImageHash: "3e".repeat(32),
  repoCommit: null,
};
const DSTACK_RUNTIME_EVENT = 0x08000001;

function dstackEvent(event, payloadHex) {
  const type = Buffer.alloc(4);
  type.writeUInt32LE(DSTACK_RUNTIME_EVENT);
  const body = Buffer.concat([type, Buffer.from(`:${event}:`, "utf8"), Buffer.from(payloadHex, "hex")]);
  return {
    imr: 3,
    event_type: DSTACK_RUNTIME_EVENT,
    digest: createHash("sha384").update(body).digest("hex"),
    event,
    event_payload: payloadHex,
  };
}

const composeFile = (launcher = TEST_WORKLOAD.launcherImage) =>
  JSON.stringify({
    docker_compose_file:
      `services:\n  launcher:\n    image: ${launcher}\n    environment:\n` +
      `      REPO_URL=${TEST_WORKLOAD.repoUrl}\n      REPO_COMMIT=${TEST_COMMIT}\n`,
  });

/// A report whose key set carries the x25519 key this file holds, with a boot
/// log that measures `compose`. The quote is shaped only where a verifier reads
/// it, so nothing here verifies to Intel's root.
async function attestationReport(nonce, compose = composeFile()) {
  const keyset = {
    subject: null,
    not_after: Math.floor(Date.now() / 1000) + 3600,
    receipt_signing_keys: [],
    e2ee_public_keys: [{ key_id: "e2ee-1", algo: X25519_SUITE, public_key: SERVICE_PUBLIC }],
  };
  const events = [
    dstackEvent("compose-hash", createHash("sha256").update(compose).digest("hex")),
    dstackEvent("os-image-hash", TEST_WORKLOAD.osImageHash),
    dstackEvent("system-ready", ""),
  ];
  const digest = await computeKeysetDigest(keyset);
  const quote = Buffer.alloc(632);
  Buffer.from(await replayRtmr3(events)).copy(quote, 520);
  Buffer.from(await computeReportData(digest, nonce), "hex").copy(quote, 568);
  return {
    api_version: "aci/1",
    workload_keyset_digest: digest,
    attestation: {
      tee_type: "tdx",
      workload_keyset: keyset,
      report_data: await computeReportData(digest, nonce),
      source_provenance: { repo_url: TEST_WORKLOAD.repoUrl, repo_commit: TEST_COMMIT },
      evidence: { quote: toHex(quote), event_log: JSON.stringify(events), app_compose: compose },
    },
  };
}

/// A gateway that quotes, takes one payment and answers. Records what it was
/// sent so a test can hold the client to the bytes it claims to have sent.
function stubGateway({ price = PRICE, quoteReport = null, answer = null, confidential = true } = {}) {
  const seen = { paid: null, headers: null, receipts: 0, quotes: 0 };
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const target = new URL(url);
    const json = (body, status = 200, headers = {}) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

    if (target.pathname.endsWith("/v1/models")) {
      // The shape the gateway serves: the open models keep the top-level
      // pricing map, the confidential class is its own card.
      return json({
        models: ["llama3.2:3b"],
        pay_to: PAY_TO,
        pricing: { "llama3.2:3b": { base_micros: 3000, per_token_micros: 3, full_cap_micros: "6072" } },
        ...(confidential
          ? {
              confidential: {
                endpoint: "/inference/v1/chat/completions",
                attestation: "/inference/v1/attestation",
                max_tokens: 1024,
                max_body_bytes: 32 * 1024,
                models: {
                  [MODEL]: {
                    base_micros: 1000,
                    per_token_micros: 5,
                    full_cap_micros: "6120",
                    confidential: true,
                    tee: "intel-tdx + nvidia",
                    provider: "phala",
                    e2ee: true,
                  },
                },
              },
            }
          : {}),
      });
    }
    if (target.pathname.endsWith("/v1/attestation")) {
      if (!quoteReport) throw new Error("this gateway serves no attestation");
      return json(await quoteReport(target.searchParams.get("nonce")));
    }
    if (target.pathname.endsWith("/v1/chat/completions")) {
      const payment = init.headers?.["x-payment"];
      if (!payment) {
        seen.quotes += 1;
        return json(
          {
            x402Version: 2,
            accepts: [
              { scheme: "exact", network: "eip155:4663", asset: "0x5fc5", payTo: PAY_TO, amount: price },
            ],
            state: "warm",
            quote: { model: MODEL, output_cap: 512, price_micros: price },
          },
          402,
        );
      }
      seen.paid = Buffer.from(init.body);
      seen.headers = init.headers;
      return new Response(answer ? answer(JSON.parse(seen.paid.toString("utf8"))) : '{"id":"chatcmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"about 4,200 USDG"}}],"usage":{"prompt_tokens":9,"completion_tokens":6}}', {
        status: 200,
        headers: { "content-type": "application/json", "x-receipt-id": "rcpt-1" },
      });
    }
    if (target.pathname.includes("/v1/receipts/")) {
      seen.receipts += 1;
      return json({ api_version: "aci/1", receipt_id: "rcpt-1", model: MODEL, event_log: [] });
    }
    throw new Error(`unexpected request ${url}`);
  };
  return { seen, restore: () => (globalThis.fetch = original) };
}

function stubAgent() {
  const agent = new PrismAgent({
    privateKey: `0x${"22".repeat(32)}`,
    escrow: "0x62C042265991bEa17B07229322A01850974626dA",
  });
  const transfers = [];
  agent.transferUsdg = async (to, micros) => {
    transfers.push({ to, micros });
    return `0x${"ab".repeat(32)}`;
  };
  agent.account = { ...agent.account, signMessage: async () => `0x${"cd".repeat(65)}` };
  return { agent, transfers };
}

test("a confidential generation quotes, pays once, and keeps the bytes it sent", async () => {
  const gateway = stubGateway();
  const { agent, transfers } = stubAgent();
  try {
    const run = await agent.confidentialInfer({
      prompt: "what is my position worth",
      e2ee: false,
      endpoint: "https://api.test/inference",
    });

    assert.equal(run.model, MODEL);
    assert.equal(run.content, "about 4,200 USDG");
    assert.equal(run.usage.completion_tokens, 6);
    assert.equal(run.receiptId, "rcpt-1");
    assert.equal(run.priceMicros, PRICE);
    assert.equal(run.priceUsdg, "0.003560");
    assert.deepEqual(transfers, [{ to: PAY_TO, micros: BigInt(PRICE) }]);
    // The receipt is fetched while the workload still holds it, not left for
    // whenever the caller gets round to verifying.
    assert.equal(gateway.seen.receipts, 1);
    assert.equal(run.receipt.receipt_id, "rcpt-1");
    // What the receipt commits to is what went over the wire, byte for byte.
    assert.equal(run.bytes.request.toString("utf8"), gateway.seen.paid.toString("utf8"));
    assert.deepEqual(JSON.parse(run.bytes.request.toString("utf8")), {
      model: MODEL,
      messages: [{ role: "user", content: "what is my position worth" }],
      max_tokens: 512,
    });
    assert.equal(typeof run.verify, "function");
  } finally {
    gateway.restore();
  }
});

test("a price above the cap is refused before any money moves", async () => {
  const gateway = stubGateway({ price: "500000" });
  const { agent, transfers } = stubAgent();
  try {
    await assert.rejects(
      () => agent.confidentialInfer({ prompt: "hi", e2ee: false, maxUsdg: 0.05, endpoint: "https://api.test/inference" }),
      (err) => err.code === "cost_exceeds_max",
    );
    assert.deepEqual(transfers, []);
  } finally {
    gateway.restore();
  }
});

test("an endpoint with no confidential model is refused", async () => {
  const gateway = stubGateway({ confidential: false });
  const { agent, transfers } = stubAgent();
  try {
    await assert.rejects(
      () => agent.confidentialInfer({ prompt: "hi", endpoint: "https://api.test/inference" }),
      (err) => err.code === "no_confidential_model",
    );
    assert.deepEqual(transfers, []);
  } finally {
    gateway.restore();
  }
});

test("a key set whose quote does not verify never receives the prompt", async () => {
  const gateway = stubGateway({ quoteReport: (nonce) => attestationReport(nonce) });
  const { agent, transfers } = stubAgent();
  try {
    await assert.rejects(
      () =>
        agent.confidentialInfer({
          prompt: "sensitive",
          expectedWorkload: TEST_WORKLOAD,
          endpoint: "https://api.test/inference",
        }),
      (err) => err.code === "quote_unverified",
    );
    assert.deepEqual(transfers, []);
    assert.equal(gateway.seen.paid, null);
  } finally {
    gateway.restore();
  }
});

test("an enclave running code the client does not pin never receives the prompt", async () => {
  const gateway = stubGateway({
    quoteReport: (nonce) => attestationReport(nonce, composeFile(`ghcr.io/attacker/launcher@sha256:${"7f".repeat(32)}`)),
  });
  const { agent, transfers } = stubAgent();
  try {
    await assert.rejects(
      () =>
        agent.confidentialInfer({
          prompt: "sensitive",
          expectedWorkload: TEST_WORKLOAD,
          endpoint: "https://api.test/inference",
        }),
      (err) => err.code === "attestation_unverified" && /runs no ghcr.io\/example\/launcher/.test(err.body.cause),
    );
    // Nothing was sealed, nothing was priced and nothing was paid: the refusal
    // happens before the prompt is encrypted to anyone's key.
    assert.deepEqual(transfers, []);
    assert.equal(gateway.seen.paid, null);
    assert.equal(gateway.seen.quotes, 0);
  } finally {
    gateway.restore();
  }
});

test("a compose that does not hash to its measurement never receives the prompt", async () => {
  const gateway = stubGateway({
    quoteReport: async (nonce) => {
      const report = await attestationReport(nonce);
      report.attestation.evidence.app_compose = composeFile().replace("services:", "services: # rewritten");
      return report;
    },
  });
  const { agent, transfers } = stubAgent();
  try {
    await assert.rejects(
      () =>
        agent.confidentialInfer({
          prompt: "sensitive",
          expectedWorkload: TEST_WORKLOAD,
          endpoint: "https://api.test/inference",
        }),
      (err) => err.code === "attestation_unverified" && /sha256\(app_compose\)/.test(err.body.cause),
    );
    assert.deepEqual(transfers, []);
    assert.equal(gateway.seen.quotes, 0);
  } finally {
    gateway.restore();
  }
});

/// A bare fetch stub for the paid-call tests, which need to answer one endpoint
/// with whatever the case is about rather than run a whole generation.
function stubFetch(handler) {
  const original = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, init = {}) => {
    seen.push({ url: String(url), body: init.body ? Buffer.from(init.body).toString("utf8") : null, headers: init.headers });
    return handler(seen.length, init);
  };
  return { seen, restore: () => (globalThis.fetch = original) };
}

const jsonResponse = (body, status, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

test("a spend cap is a refusal, not something to retry for ten minutes", async () => {
  const calls = stubFetch(() =>
    jsonResponse(
      {
        error: "spend_cap_reached",
        detail: "the confidential relay has reached its daily upstream spend cap",
        retry: "nothing was charged; the cap resets at 00:00 UTC",
      },
      503,
      { "retry-after": "3600" },
    ),
  );
  const { agent } = stubAgent();
  try {
    const started = Date.now();
    await assert.rejects(
      () =>
        agent.payAndPost({
          base: "https://api.test/inference",
          path: "/v1/chat/completions",
          price: 1000n,
          payTo: PAY_TO,
          body: { model: MODEL },
        }),
      (err) => err.code === "spend_cap_reached" && /the cap resets at 00:00 UTC/.test(err.body.cause),
    );
    // One attempt, no fifteen-second sleep, and the caller is told what the
    // endpoint said rather than watching it hang.
    assert.equal(calls.seen.length, 1);
    assert.ok(Date.now() - started < 5_000);
  } finally {
    calls.restore();
  }
});

test("an unavailable upstream is retried with the payment already made", async () => {
  const calls = stubFetch((n) =>
    n === 1
      ? jsonResponse({ error: "upstream_unavailable", retry: "the payment was not consumed" }, 503)
      : new Response('{"ok":true}', { status: 200, headers: { "content-type": "application/json" } }),
  );
  const { agent, transfers } = stubAgent();
  try {
    const served = await agent.payAndPost({
      base: "https://api.test/inference",
      path: "/v1/chat/completions",
      price: 1000n,
      payTo: PAY_TO,
      body: { model: MODEL },
      retryDelayMs: 1,
    });
    assert.equal(served.status, 200);
    assert.equal(calls.seen.length, 2);
    assert.equal(transfers.length, 1, "the same payment carried both attempts");
  } finally {
    calls.restore();
  }
});

test("a kept payment belongs to the request it paid for", async () => {
  const calls = stubFetch(() => jsonResponse({ error: "upstream_rejected", detail: "bad request" }, 400));
  const { agent, transfers } = stubAgent();
  try {
    const pay = (prompt) =>
      agent.payAndPost({
        base: "https://api.test/inference",
        path: "/v1/chat/completions",
        price: 1000n,
        payTo: PAY_TO,
        body: { model: MODEL, messages: [{ role: "user", content: prompt }] },
      });

    await assert.rejects(pay("first prompt"), (err) => err.code === "upstream_rejected");
    assert.equal(transfers.length, 1);
    // The signed header is exposed, because the transfer has settled and this
    // process is the only thing holding the thing that redeems it.
    await assert.rejects(pay("first prompt"), (err) => typeof err.body.payment_header === "string");
    assert.equal(transfers.length, 1, "the same request reuses the payment it already made");

    await assert.rejects(pay("a different prompt"), (err) => err.code === "upstream_rejected");
    assert.equal(transfers.length, 2, "a different request pays for itself");
  } finally {
    calls.restore();
  }
});

test("a payment the endpoint has already consumed stops being retried with", async () => {
  const calls = stubFetch(() => jsonResponse({ error: "payment_reused" }, 402));
  const { agent, transfers } = stubAgent();
  try {
    const pay = () =>
      agent.payAndPost({
        base: "https://api.test/inference",
        path: "/v1/chat/completions",
        price: 1000n,
        payTo: PAY_TO,
        body: { model: MODEL },
      });
    await assert.rejects(pay(), (err) => err.code === "payment_reused");
    await assert.rejects(pay(), (err) => err.code === "payment_reused");
    assert.equal(transfers.length, 2, "a consumed payment is not offered again");
    assert.equal(calls.seen.length, 2);
  } finally {
    calls.restore();
  }
});

test("a replayed answer is not this call's answer", async () => {
  const calls = stubFetch(() =>
    new Response('{"id":"chatcmpl-earlier"}', {
      status: 200,
      headers: { "content-type": "application/json", "x-prism-replayed": "true" },
    }),
  );
  const { agent } = stubAgent();
  try {
    await assert.rejects(
      () =>
        agent.payAndPost({
          base: "https://api.test/inference",
          path: "/v1/chat/completions",
          price: 1000n,
          payTo: PAY_TO,
          body: { model: MODEL },
        }),
      (err) => err.code === "payment_replayed",
    );
    assert.equal(calls.seen.length, 1);
  } finally {
    calls.restore();
  }
});

test("an encrypted request is sealed fresh for every attempt", async () => {
  const stamps = new Set();
  const calls = stubFetch((n, init) => {
    stamps.add(init.headers["X-E2EE-Nonce"]);
    return n < 3
      ? jsonResponse({ error: "upstream_unavailable" }, 503)
      : new Response('{"ok":true}', { status: 200, headers: { "content-type": "application/json" } });
  });
  const { agent, transfers } = stubAgent();
  const keyset = { e2ee_public_keys: [{ key_id: "e2ee-1", algo: X25519_SUITE, public_key: SERVICE_PUBLIC }] };
  const body = { model: MODEL, messages: [{ role: "user", content: "hi" }], max_tokens: 16 };
  try {
    const served = await agent.payAndPost({
      base: "https://api.test/inference",
      path: "/v1/chat/completions",
      price: 1000n,
      payTo: PAY_TO,
      seal: () => encryptChatRequest(body, keyset),
      fingerprint: Buffer.from(JSON.stringify(body), "utf8"),
      retryDelayMs: 1,
    });
    assert.equal(served.status, 200);
    assert.equal(calls.seen.length, 3);
    // A frozen timestamp cannot survive a retry budget longer than the service's
    // five-minute acceptance window, so each attempt is its own envelope.
    assert.equal(stamps.size, 3);
    assert.equal(transfers.length, 1);
    assert.notEqual(calls.seen[0].body, calls.seen[1].body);
  } finally {
    calls.restore();
  }
});
