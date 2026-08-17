#!/usr/bin/env node
// Proves the happy path against Base itself: a real signature, the real USDC
// contract, the real domain. Verification is read-only, so this runs without
// spending anything and without a funded wallet.
//
//   node exact-evm.live.mjs            reads the chain, settles nothing
//   SETTLE=1 node exact-evm.live.mjs   also broadcasts, needs gas and USDC
import { base } from "viem/chains";
import { createPublicClient, http, keccak256, parseAbi, toHex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { AUTHORIZATION_TYPES, createExactEvm } from "./exact-evm.mjs";

// Not mainnet.base.org: one verification is four calls, and the public
// endpoint rate-limits a burst that size, which fails as an opaque
// "RPC Request failed" rather than as anything about the payment.
const RPC = process.env.X402_BASE_RPC_URL ?? "https://base-rpc.publicnode.com";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAY_TO = process.env.X402_BASE_PAY_TO ?? "0xe67a61f8e2aC4057aa22e64306107E7120078447";
const AMOUNT = BigInt(process.env.AMOUNT_MICROS ?? "1000");

const client = createPublicClient({ chain: base, transport: http(RPC) });
const meta = await (async () => {
  const abi = parseAbi(["function name() view returns (string)", "function version() view returns (string)"]);
  const [name, version] = await Promise.all([
    client.readContract({ address: USDC, abi, functionName: "name" }),
    client.readContract({ address: USDC, abi, functionName: "version" }),
  ]);
  return { name, version };
})();
console.log(`domain read from the contract: name=${JSON.stringify(meta.name)} version=${JSON.stringify(meta.version)}`);

const evm = createExactEvm({
  "eip155:8453": {
    chain: base,
    rpcUrl: RPC,
    assets: { [USDC]: meta },
    privateKey: process.env.PRISM_X402_COLLECTOR_KEY,
  },
});

const payerKey = process.env.X402_TEST_PAYER_KEY ?? generatePrivateKey();
const payer = privateKeyToAccount(payerKey);
const now = Math.floor(Date.now() / 1000);

const requirements = {
  scheme: "exact",
  network: "eip155:8453",
  amount: AMOUNT.toString(),
  asset: USDC,
  payTo: PAY_TO,
  maxTimeoutSeconds: 60,
  extra: { ...meta },
};

const authorization = {
  from: payer.address,
  to: PAY_TO,
  value: AMOUNT,
  validAfter: BigInt(now - 60),
  validBefore: BigInt(now + 600),
  nonce: keccak256(toHex(`prism-live-${now}-${Math.round(performance.now())}`)),
};

const signature = await payer.signTypedData({
  domain: { name: meta.name, version: meta.version, chainId: base.id, verifyingContract: USDC },
  types: AUTHORIZATION_TYPES,
  primaryType: "TransferWithAuthorization",
  message: authorization,
});

const payload = {
  x402Version: 2,
  accepted: requirements,
  payload: {
    signature,
    authorization: {
      from: authorization.from,
      to: authorization.to,
      value: authorization.value.toString(),
      validAfter: authorization.validAfter.toString(),
      validBefore: authorization.validBefore.toString(),
      nonce: authorization.nonce,
    },
  },
};

const balance = await client.readContract({
  address: USDC,
  abi: parseAbi(["function balanceOf(address) view returns (uint256)"]),
  functionName: "balanceOf",
  args: [payer.address],
});
console.log(`payer ${payer.address} holds ${Number(balance) / 1e6} USDC, paying ${Number(AMOUNT) / 1e6}`);

const verdict = await evm.verify(payload, requirements);
console.log("verify:", JSON.stringify(verdict));

// An unfunded payer is the expected answer when nobody topped the test wallet
// up, and it proves the signature and domain were accepted: the amount check
// and the signature check both run before the balance is read.
if (!verdict.isValid && verdict.invalidReason === "insufficient_funds") {
  console.log("\nsignature and domain accepted; refused only for balance, which is the expected");
  console.log("result for an unfunded payer. Fund the payer to test settlement.");
  process.exit(0);
}
if (!verdict.isValid) {
  console.error(`\nunexpected refusal: ${verdict.invalidReason}`);
  process.exit(1);
}

if (process.env.SETTLE !== "1") {
  console.log("\nverified. Re-run with SETTLE=1 to broadcast.");
  process.exit(0);
}

const settlement = await evm.settle(payload, requirements);
console.log("settle:", JSON.stringify(settlement));
process.exit(settlement.success ? 0 : 1);
