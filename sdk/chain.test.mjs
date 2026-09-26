import { strict as assert } from "node:assert";
import { test } from "node:test";

import { depositEth, prismChain, prismChainContracts, withdraw } from "./chain.mjs";
import { prismChain as fromIndex } from "./prism.mjs";

const ME = "0x9F15121215A22f2D330501CD65f1c37086190dCB";
const USDG = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";

// Records what would be signed instead of signing it.
function recorder() {
  const calls = [];
  return {
    calls,
    account: { address: ME },
    async writeContract(request) {
      calls.push(request);
      return "0xhash";
    },
  };
}

test("Prism Chain is chain 77476, settled on Robinhood Chain, and the index re-exports it", () => {
  assert.equal(prismChain.id, 77476);
  assert.equal(prismChain.sourceId, 4663);
  assert.equal(prismChain.rpcUrls.default.http[0], "https://rpc.prismnetwork.tech");
  assert.equal(fromIndex, prismChain);
});

test("an ETH deposit goes to the inbox on Robinhood Chain with the amount as value", async () => {
  const wallet = recorder();
  await depositEth(wallet, 5n);
  const [call] = wallet.calls;
  assert.equal(call.chain.id, 4663);
  assert.equal(call.address, prismChainContracts.inbox);
  assert.equal(call.functionName, "depositEth");
  assert.equal(call.value, 5n);
});

test("an ETH withdrawal starts on Prism Chain and returns to the sender", async () => {
  const wallet = recorder();
  await withdraw(wallet, 7n);
  const [call] = wallet.calls;
  assert.equal(call.chain.id, 77476);
  assert.equal(call.address, prismChainContracts.arbSys);
  assert.deepEqual(call.args, [ME]);
  assert.equal(call.value, 7n);
});

test("a token withdrawal names the Robinhood Chain token and sends no ETH", async () => {
  const wallet = recorder();
  await withdraw(wallet, 500_000n, { token: USDG });
  const [call] = wallet.calls;
  assert.equal(call.address, prismChainContracts.childRouter);
  assert.equal(call.functionName, "outboundTransfer");
  assert.deepEqual(call.args, [USDG, ME, 500_000n, "0x"]);
  assert.equal(call.value, undefined);
});
