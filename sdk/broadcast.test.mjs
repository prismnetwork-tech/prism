// What a failure after the wallet has already signed has to say. The chain
// takes a transaction long before a receipt can be read back, and an error that
// drops the hash leaves money in an escrow or an endpoint's balance that
// nothing in the caller's process can name.
import assert from "node:assert/strict";
import { test } from "node:test";
import { PrismAgent } from "./prism.mjs";

const KEY = `0x${"11".repeat(32)}`;
const ESCROW = "0x0000000000000000000000000000000000000009";
const NODE = `0x${"22".repeat(32)}`;
const HASH = `0x${"ab".repeat(32)}`;

// The rpc having a bad minute: the transaction went out, and reading it back is
// what failed.
function agent(broadcast = async () => HASH) {
  const prism = new PrismAgent({ privateKey: KEY, escrow: ESCROW, rpcUrl: "http://127.0.0.1:1" });
  prism.publicClient = {
    readContract: async () => 10_000n,
    waitForTransactionReceipt: async () => {
      throw new Error("timed out while waiting for transaction receipt");
    },
  };
  prism.walletClient = { writeContract: broadcast };
  return prism;
}

test("a funded lease whose receipt never arrived still names its transaction", async () => {
  const quote = { quote_id: "q", node_id: NODE, maximum_escrow: "1000", duration_seconds: 900 };
  await assert.rejects(agent().fund(quote), (err) => {
    assert.equal(err.code, "chain_error");
    assert.equal(err.body.funding_hash, HASH);
    assert.match(err.body.cause, /timed out/);
    return true;
  });
});

test("a payment whose receipt never arrived still names its transaction", async () => {
  await assert.rejects(agent().transferUsdg("0x0000000000000000000000000000000000000003", 30_000n), (err) => {
    assert.equal(err.code, "chain_error");
    assert.equal(err.body.payment_tx, HASH);
    return true;
  });
});

test("a submission the chain never accepted names nothing, because nothing left", async () => {
  const refused = agent(async () => {
    throw new Error("insufficient funds for gas * price + value");
  });
  await assert.rejects(refused.transferUsdg("0x0000000000000000000000000000000000000003", 30_000n), (err) => {
    assert.equal(err.code, "chain_error");
    assert.equal(err.body.payment_tx, undefined);
    return true;
  });
});
