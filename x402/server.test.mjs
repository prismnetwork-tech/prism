import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath } from "node:url";

const server = fileURLToPath(new URL("./server.mjs", import.meta.url));
const port = 18402;
const payTo = "0xEcaaE714912C38fA7e0dAF78afa7C54DbeD11039";

function start(extra) {
  return spawn(process.execPath, [server], {
    env: {
      ...process.env,
      PRISM_AGENT_KEY: `0x${"11".repeat(32)}`,
      PRISM_ESCROW: payTo,
      X402_PAY_TO: payTo,
      X402_BASE_PAY_TO: payTo,
      // Offering Base means being able to broadcast on it, so the server refuses
      // to boot with a payTo and no key to settle with.
      PRISM_X402_COLLECTOR_KEY: `0x${"22".repeat(32)}`,
      X402_PAYMENTS_FILE: join(mkdtempSync(join(tmpdir(), "x402-")), "consumed.log"),
      ...extra,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
}

const child = start({ X402_PORT: String(port) });
after(() => child.kill());

async function ready(on = port, headers = {}) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const res = await fetch(`http://127.0.0.1:${on}/healthz`, { headers });
      if (res.ok) return;
    } catch {
      // The server is still binding.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("x402 server did not start");
}

async function run(payment) {
  return fetch(`http://127.0.0.1:${port}/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(payment ? { "X-PAYMENT": payment } : {}) },
    body: JSON.stringify({ command: "nvidia-smi" }),
  });
}

function envelope(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64");
}

/// Every x402 client in the wild pays on Base. An endpoint that only quotes
/// Robinhood Chain cannot be paid by any of them.
test("an unpaid request is quoted on every configured network", async () => {
  await ready();
  const res = await run();
  assert.equal(res.status, 402);

  const body = await res.json();
  // A caller who has not shown us which version it speaks is answered in v2,
  // because that is what the scanners and agent tooling read.
  assert.equal(body.x402Version, 2);
  const byNetwork = Object.fromEntries(body.accepts.map((offer) => [offer.network, offer]));
  assert.deepEqual(Object.keys(byNetwork).sort(), ["eip155:4663", "eip155:8453"]);

  const base = byNetwork["eip155:8453"];
  assert.equal(base.asset, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
  assert.equal(base.extra.name, "USD Coin", "the signing domain must travel with the offer");
  assert.equal(byNetwork["eip155:4663"].asset, "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168");
  for (const offer of body.accepts) {
    assert.equal(offer.scheme, "exact");
    assert.equal(offer.payTo, payTo);
    assert.equal(offer.amount, "300000", "atomic units, not decimal dollars");
    // v2 entries carry payment terms only; anything describing the resource
    // moved up a level, and leaving it here fails their schema validation.
    assert.equal(offer.resource, undefined);
    assert.equal(offer.outputSchema, undefined);
  }

  // v2 puts the resource and the call shape at the top level instead.
  assert.equal(body.resource.url, "https://api.prismnetwork.tech/x402/run");
  assert.equal(body.resource.mimeType, "application/json");
  assert.ok(body.extensions.bazaar.schema.properties.input, "the 402 must say how to call the endpoint");
  assert.ok(body.extensions.bazaar.schema.properties.output);
});

test("a refused payment says which check refused it", async () => {
  await ready();

  const malformed = await run(Buffer.from("not-json").toString("base64"));
  assert.equal((await malformed.json()).error, "malformed_payment");

  const unsupported = await run(
    envelope({ txHash: `0x${"ab".repeat(32)}`, signature: "0x00", network: "eip155:1" }),
  );
  assert.equal((await unsupported.json()).error, "unsupported_network");

  const unsigned = await run(envelope({ txHash: `0x${"ab".repeat(32)}` }));
  assert.equal((await unsigned.json()).error, "malformed_payment");
});

test("a caller that speaks v1 is still answered in v1", async () => {
  await ready();
  const res = await fetch(`http://127.0.0.1:${port}/run`, {
    method: "POST",
    headers: { "content-type": "application/json", "X-PAYMENT": "bm90LXJlYWw=" },
    body: JSON.stringify({ command: "nvidia-smi" }),
  });
  assert.equal(res.status, 402);
  const body = await res.json();
  assert.equal(body.x402Version, 1);
  const names = body.accepts.map((o) => o.network).sort();
  assert.deepEqual(names, ["base", "eip155:4663"], "v1 names chains");
  assert.equal(body.accepts.find((o) => o.network === "base").maxAmountRequired, "300000");
});

test("a v2 caller is quoted in CAIP-2, and the facilitator reports what it can settle", async () => {
  await ready();
  const res = await fetch(`http://127.0.0.1:${port}/run`, {
    method: "POST",
    headers: { "content-type": "application/json", "PAYMENT-SIGNATURE": "bm90LXJlYWw=" },
    body: JSON.stringify({ command: "nvidia-smi" }),
  });
  assert.equal(res.status, 402);
  const body = await res.json();
  assert.equal(body.x402Version, 2);
  assert.ok(body.accepts.some((offer) => offer.network === "eip155:8453"));
  assert.ok(res.headers.get("payment-required"), "v2 carries the terms in a header");

  const supported = await (await fetch(`http://127.0.0.1:${port}/supported`)).json();
  assert.ok(supported.kinds.some((k) => k.network === "eip155:8453" && k.scheme === "exact"));
  assert.equal(typeof supported.daily_limit, "number");
});

test("the facilitator refuses a malformed settle without touching the chain", async () => {
  await ready();
  const res = await fetch(`http://127.0.0.1:${port}/settle`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ paymentPayload: { x402Version: 2 } }),
  });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).errorReason, "invalid_payment_requirements");
});

test("a discovery probe on GET is quoted, not 404ed", async () => {
  await ready();
  const res = await fetch(`http://127.0.0.1:${port}/run`);
  assert.equal(res.status, 402, "crawlers probe with GET and read a 404 as broken");
  const body = await res.json();
  assert.ok(body.accepts.length > 0);
  assert.ok(body.resource.url.endsWith("/run"));
});

test("GET never runs a job, whatever it carries", async () => {
  await ready();
  // A safe method stays safe: a payment header on a GET still only quotes.
  const res = await fetch(`http://127.0.0.1:${port}/run`, {
    headers: { "PAYMENT-SIGNATURE": "bm90LXJlYWw=" },
  });
  assert.equal(res.status, 402);
  assert.equal((await res.json()).job_id, undefined);
});

/// The gate is exercised on loopback with a token set rather than by opening a
/// port to the network, because the check is the same one either way and a test
/// that binds 0.0.0.0 is a test that hands the machine's LAN a GPU wallet.
const guardedPort = 18403;
const guardToken = "n".repeat(32);
const guarded = start({ X402_PORT: String(guardedPort), X402_TOKEN: guardToken });
after(() => guarded.kill());

test("a listener that would answer strangers refuses to start without a credential", async () => {
  const wide = start({ X402_PORT: "18404", X402_HOST: "0.0.0.0" });
  let said = "";
  wide.stderr.on("data", (chunk) => {
    said += chunk;
  });
  const code = await new Promise((resolve) => wide.on("exit", resolve));
  assert.equal(code, 1, "the server bound a public address instead of refusing");
  assert.match(said, /X402_HOST is 0\.0\.0\.0/);
  assert.match(said, /X402_TOKEN/, "the refusal has to name the variable that fixes it");
});

test("a configured token covers every route, /healthz included", async () => {
  await ready(guardedPort, { authorization: `Bearer ${guardToken}` });

  const anonymous = await fetch(`http://127.0.0.1:${guardedPort}/healthz`);
  assert.equal(anonymous.status, 401);
  assert.equal((await anonymous.json()).error, "unauthorized");

  const wrong = await fetch(`http://127.0.0.1:${guardedPort}/healthz`, {
    headers: { authorization: `Bearer ${"z".repeat(32)}` },
  });
  assert.equal(wrong.status, 401);

  // Not a 402: an unauthenticated caller is turned away before the endpoint
  // quotes it a price it would have no way to pay here.
  const unpaid = await fetch(`http://127.0.0.1:${guardedPort}/run`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ command: "nvidia-smi" }),
  });
  assert.equal(unpaid.status, 401);

  const quoted = await fetch(`http://127.0.0.1:${guardedPort}/run`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${guardToken}` },
    body: JSON.stringify({ command: "nvidia-smi" }),
  });
  assert.equal(quoted.status, 402);
});
