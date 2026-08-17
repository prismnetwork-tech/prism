// Buys one generation from production the way a customer would: read the 402,
// sign an authorization for what it quotes, retry with the payment header.
// Deliberately does not import our own code, so it tests the endpoint rather
// than agreeing with itself.
import { base } from "viem/chains";
import { keccak256, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ENDPOINT = process.env.ENDPOINT ?? "https://api.prismnetwork.tech/inference/v1/inference";
const payer = privateKeyToAccount(process.env.X402_TEST_PAYER_KEY);
const body = { model: "llama3.2:3b", prompt: "Reply with exactly: paid on base", options: { num_predict: 24 } };

const TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

const unpaid = await fetch(ENDPOINT, {
  method: "POST",
  headers: { "content-type": "application/json", "PAYMENT-SIGNATURE": "" },
  body: JSON.stringify(body),
});
const quote = await unpaid.json();
console.log(`402 quoted ${quote.quote.price_micros} micros for a ${quote.quote.output_cap}-token cap`);

const terms = quote.accepts.find((a) => a.network === "base" || a.network === "eip155:8453");
if (!terms) throw new Error("the endpoint did not offer Base");
const amount = BigInt(terms.amount ?? terms.maxAmountRequired);
console.log(`paying ${Number(amount) / 1e6} USDC to ${terms.payTo}`);

const now = Math.floor(Date.now() / 1000);
const authorization = {
  from: payer.address,
  to: terms.payTo,
  value: amount,
  validAfter: BigInt(now - 60),
  validBefore: BigInt(now + 900),
  nonce: keccak256(toHex(`buy-${now}-${Math.round(performance.now())}`)),
};

// The domain comes from the endpoint's own `extra`, which is the point of
// publishing it: a client should never have to know the token's name.
const signature = await payer.signTypedData({
  domain: {
    name: terms.extra.name,
    version: terms.extra.version,
    chainId: base.id,
    verifyingContract: terms.asset,
  },
  types: TYPES,
  primaryType: "TransferWithAuthorization",
  message: authorization,
});

const header = Buffer.from(JSON.stringify({
  x402Version: 2,
  accepted: terms,
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
})).toString("base64");

const paid = await fetch(ENDPOINT, {
  method: "POST",
  headers: { "content-type": "application/json", "PAYMENT-SIGNATURE": header },
  body: JSON.stringify(body),
});
console.log(`status ${paid.status}`);
const receipt = paid.headers.get("payment-response");
if (receipt) console.log("PAYMENT-RESPONSE:", Buffer.from(receipt, "base64").toString());
const out = await paid.json();
console.log("error:", out.error ?? "(none)");
console.log("response:", out.response ?? JSON.stringify(out).slice(0, 200));
