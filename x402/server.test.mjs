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

const child = spawn(process.execPath, [server], {
  env: {
    ...process.env,
    PRISM_AGENT_KEY: `0x${"11".repeat(32)}`,
    PRISM_ESCROW: payTo,
    X402_PAY_TO: payTo,
    X402_BASE_PAY_TO: payTo,
    X402_PORT: String(port),
    X402_PAYMENTS_FILE: join(mkdtempSync(join(tmpdir(), "x402-")), "consumed.log"),
  },
  stdio: ["ignore", "ignore", "pipe"],
});
after(() => child.kill());

async function ready() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/healthz`);
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
  assert.equal(body.x402Version, 1);
  const byNetwork = Object.fromEntries(body.accepts.map((offer) => [offer.network, offer]));
  assert.deepEqual(Object.keys(byNetwork).sort(), ["eip155:4663", "eip155:8453"]);

  assert.equal(byNetwork["eip155:8453"].asset, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
  assert.equal(byNetwork["eip155:4663"].asset, "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168");
  for (const offer of body.accepts) {
    assert.equal(offer.scheme, "exact");
    assert.equal(offer.payTo, payTo);
    assert.equal(offer.maxAmountRequired, "300000");
  }
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
