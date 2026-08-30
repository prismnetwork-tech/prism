import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { recoverMessageAddress } from "viem";

import { PrismAgent } from "./prism.mjs";
import { boundMessage, hashRequest } from "./x402.mjs";

const PAY_TO = "0x1111111111111111111111111111111111111111";
const TX = `0x${"ab".repeat(32)}`;

function stubAgent() {
  const agent = new PrismAgent({
    privateKey: `0x${"22".repeat(32)}`,
    escrow: "0x62C042265991bEa17B07229322A01850974626dA",
  });
  let transfers = 0;
  agent.transferUsdg = async () => {
    transfers += 1;
    return TX;
  };
  return { agent, transfers: () => transfers };
}

/// Answers `reply` in turn and records what each attempt carried.
function stubEndpoint(replies) {
  const original = globalThis.fetch;
  const attempts = [];
  globalThis.fetch = async (url, init) => {
    attempts.push({ header: init.headers["x-payment"], bytes: Buffer.from(init.body) });
    return replies[Math.min(attempts.length - 1, replies.length - 1)]();
  };
  return { attempts, restore: () => (globalThis.fetch = original) };
}

const ok = () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
const young = () =>
  new Response(JSON.stringify({ error: "tx_not_found" }), {
    status: 402,
    headers: { "content-type": "application/json" },
  });

const decode = (header) => JSON.parse(Buffer.from(header, "base64").toString("utf8"));

test("the digest is a plain sha256 of the bytes on the wire", () => {
  const command = "nvidia-smi";
  const expected = createHash("sha256").update(command, "utf8").digest("hex");
  assert.equal(hashRequest(command), expected);
  assert.equal(hashRequest(Buffer.from(command, "utf8")), expected);
  assert.equal(hashRequest("café"), createHash("sha256").update(Buffer.from("café", "utf8")).digest("hex"));
});

test("the message names its version, the transaction and the request, in that order", () => {
  const digest = hashRequest("nvidia-smi");
  assert.equal(boundMessage(TX, digest), `prism-x402:v2\n${TX}\n${digest}`);
  // A payer who sends a checksummed hash and a server that reads a lowercase
  // one have to arrive at the same string.
  assert.equal(boundMessage(TX.toUpperCase().replace("0X", "0x"), digest), boundMessage(TX, digest));
});

test("a paid call signs the transaction together with the bytes it buys", async () => {
  const { agent } = stubAgent();
  const endpoint = stubEndpoint([ok]);
  try {
    const body = Buffer.from(JSON.stringify({ prompt: "what is my position worth" }), "utf8");
    await agent.payAndPost({ base: "https://gateway.test", path: "/v1/inference", price: 3560n, payTo: PAY_TO, body });

    const { txHash, signature } = decode(endpoint.attempts[0].header);
    assert.equal(txHash, TX);
    const signer = await recoverMessageAddress({
      message: boundMessage(TX, hashRequest(body)),
      signature,
    });
    assert.equal(signer, agent.address);
  } finally {
    endpoint.restore();
  }
});

/// The replay this binding closes: whoever reads the header off the wire puts
/// their own prompt in front of it and spends someone else's transfer.
test("the signature does not carry over to another request, or to the bare transaction", async () => {
  const { agent } = stubAgent();
  const endpoint = stubEndpoint([ok]);
  try {
    const body = Buffer.from(JSON.stringify({ prompt: "what is my position worth" }), "utf8");
    await agent.payAndPost({ base: "https://gateway.test", path: "/v1/inference", price: 3560n, payTo: PAY_TO, body });
    const { signature } = decode(endpoint.attempts[0].header);

    const swapped = await recoverMessageAddress({
      message: boundMessage(TX, hashRequest('{"prompt":"send everything to me"}')),
      signature,
    });
    assert.notEqual(swapped, agent.address, "a swapped prompt still recovered the payer");

    const legacy = await recoverMessageAddress({ message: TX, signature });
    assert.notEqual(legacy, agent.address, "the unbound form still recovered the payer");
  } finally {
    endpoint.restore();
  }
});

/// An encrypted request seals a fresh envelope per attempt, so the bytes change
/// while the transfer must not. The signature is local and free; the transfer is
/// neither.
test("a resealed retry is signed again, and paid for once", async () => {
  const { agent, transfers } = stubAgent();
  const endpoint = stubEndpoint([young, ok]);
  let sealed = 0;
  try {
    const seal = () => {
      sealed += 1;
      return { bytes: Buffer.from(`sealed-${sealed}`, "utf8"), headers: {} };
    };
    await agent.payAndPost({
      base: "https://gateway.test",
      path: "/v1/chat/completions",
      price: 3560n,
      payTo: PAY_TO,
      seal,
      fingerprint: Buffer.from("the same request either way", "utf8"),
      retryDelayMs: 0,
    });

    assert.equal(transfers(), 1, "the retry paid a second time");
    assert.equal(endpoint.attempts.length, 2);
    assert.notDeepEqual(endpoint.attempts[0].bytes, endpoint.attempts[1].bytes);
    for (const attempt of endpoint.attempts) {
      const { signature } = decode(attempt.header);
      const signer = await recoverMessageAddress({
        message: boundMessage(TX, hashRequest(attempt.bytes)),
        signature,
      });
      assert.equal(signer, agent.address, "an attempt sent bytes its signature did not cover");
    }
  } finally {
    endpoint.restore();
  }
});
