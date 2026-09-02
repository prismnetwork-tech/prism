import { privateKeyToAccount } from "viem/accounts";

const ENDPOINT = "https://api.prismnetwork.tech/x402/run";
const payer = privateKeyToAccount(process.env.X402_TEST_PAYER_KEY);
const body = JSON.stringify({ command: "echo bazaar-refresh" });

const first = await fetch(ENDPOINT, { method: "POST", headers: { "content-type": "application/json" }, body });
if (first.status !== 402) throw new Error(`expected 402, got ${first.status}`);
const required = await first.json();
const terms = required.accepts.find((a) => a.network === "eip155:8453");
if (!terms) throw new Error("no Base option");
console.log(`paying ${Number(terms.amount) / 1e6} USDC on Base to ${terms.payTo}`);

const now = Math.floor(Date.now() / 1000);
const nonce = "0x" + Array.from(crypto.getRandomValues(new Uint8Array(32))).map((b) => b.toString(16).padStart(2, "0")).join("");
const authorization = {
  from: payer.address,
  to: terms.payTo,
  value: terms.amount,
  validAfter: String(now - 60),
  validBefore: String(now + (terms.maxTimeoutSeconds ?? 180)),
  nonce,
};
const signature = await payer.signTypedData({
  domain: { name: terms.extra.name, version: terms.extra.version, chainId: 8453, verifyingContract: terms.asset },
  types: { TransferWithAuthorization: [
    { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
  ] },
  primaryType: "TransferWithAuthorization",
  message: { ...authorization, value: BigInt(terms.amount), validAfter: BigInt(authorization.validAfter), validBefore: BigInt(authorization.validBefore) },
});
const payload = {
  x402Version: 2,
  scheme: "exact",
  network: terms.network,
  payload: { authorization, signature },
};
const header = Buffer.from(JSON.stringify(payload)).toString("base64");
const paid = await fetch(ENDPOINT, {
  method: "POST",
  headers: { "content-type": "application/json", "payment-signature": header },
  body,
});
console.log("status", paid.status);
console.log((await paid.text()).slice(0, 400));
