import assert from "node:assert/strict";
import { test } from "node:test";
import { PrismAgent } from "./prism.mjs";

const KEY = `0x${"11".repeat(32)}`;
const ESCROW = "0x0000000000000000000000000000000000000009";
const NODE = `0x${"22".repeat(32)}`;

function agent({ allowance = 0n } = {}) {
  const prism = new PrismAgent({ privateKey: KEY, escrow: ESCROW, rpcUrl: "http://127.0.0.1:1" });
  const seen = { open: 0, peak: 0, calls: [] };
  let nth = 0;
  prism.publicClient = {
    readContract: async () => allowance,
    waitForTransactionReceipt: async () => ({ status: "success" }),
  };
  prism.walletClient = {
    writeContract: async ({ functionName }) => {
      seen.open += 1;
      seen.peak = Math.max(seen.peak, seen.open);
      seen.calls.push(functionName);
      await new Promise((r) => setTimeout(r, 5));
      seen.open -= 1;
      nth += 1;
      return `0x${nth.toString(16).padStart(64, "0")}`;
    },
  };
  return { prism, seen };
}

const quote = (id) => ({ quote_id: id, node_id: NODE, maximum_escrow: "1000", duration_seconds: 900 });

test("two leases funded from one wallet never sign at the same moment", async () => {
  const { prism, seen } = agent();
  await Promise.all([prism.fund(quote("a")), prism.fund(quote("b")), prism.fund(quote("c"))]);
  assert.equal(seen.peak, 1, "a transaction was prepared while another was still submitting");
});

test("an approval and the lease it covers are not separated by another lease", async () => {
  const { prism, seen } = agent();
  await Promise.all([prism.fund(quote("a")), prism.fund(quote("b"))]);
  assert.deepEqual(seen.calls, ["approve", "createLease", "approve", "createLease"]);
});

test("a wallet that already has the allowance skips the approval", async () => {
  const { prism, seen } = agent({ allowance: 10_000n });
  await prism.fund(quote("a"));
  assert.deepEqual(seen.calls, ["createLease"]);
});

test("payments queue behind each other too, not just leases", async () => {
  const { prism, seen } = agent();
  await Promise.all([
    prism.transferUsdg("0x0000000000000000000000000000000000000003", 1n),
    prism.transferUsdg("0x0000000000000000000000000000000000000003", 2n),
  ]);
  assert.equal(seen.peak, 1);
});

test("one failed submission does not wedge the queue behind it", async () => {
  const { prism, seen } = agent({ allowance: 10_000n });
  let first = true;
  const inner = prism.walletClient.writeContract;
  prism.walletClient.writeContract = async (args) => {
    if (first) {
      first = false;
      throw new Error("nonce too low");
    }
    return inner(args);
  };
  const [bad, good] = await Promise.allSettled([prism.fund(quote("a")), prism.fund(quote("b"))]);
  assert.equal(bad.status, "rejected");
  assert.equal(good.status, "fulfilled");
  assert.equal(seen.peak, 1);
});
