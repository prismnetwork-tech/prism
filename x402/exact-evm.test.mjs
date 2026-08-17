import assert from "node:assert/strict";
import test from "node:test";
import { base } from "viem/chains";
import { keccak256, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { AUTHORIZATION_TYPES, createExactEvm } from "./exact-evm.mjs";
import { detect, parsePayment, paymentRequired, paymentResponse, requirementsFor, v1Network } from "./codec.mjs";

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAY_TO = "0xe67a61f8e2aC4057aa22e64306107E7120078447";
const payer = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

// Base mainnet USDC reports "USD Coin", not "USDC". The spec example carries
// the testnet name, and the domain feeds the EIP-712 hash, so copying it
// produces signatures that verify against nothing.
const META = { name: "USD Coin", version: "2" };

const NOW = 1_800_000_000;

function requirements(overrides = {}) {
  return {
    scheme: "exact",
    network: "eip155:8453",
    amount: "35600",
    asset: USDC,
    payTo: PAY_TO,
    maxTimeoutSeconds: 60,
    extra: { ...META },
    ...overrides,
  };
}

async function signed(overrides = {}) {
  const authorization = {
    from: payer.address,
    to: PAY_TO,
    value: 35_600n,
    validAfter: BigInt(NOW - 60),
    validBefore: BigInt(NOW + 600),
    nonce: keccak256(toHex("prism-test-nonce")),
    ...overrides,
  };
  const signature = await payer.signTypedData({
    domain: { name: META.name, version: META.version, chainId: base.id, verifyingContract: USDC },
    types: AUTHORIZATION_TYPES,
    primaryType: "TransferWithAuthorization",
    message: authorization,
  });
  return {
    x402Version: 2,
    accepted: requirements(),
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
}

/// Every case below is refused before the first chain read, so the RPC is
/// deliberately unreachable: if a change starts reaching the network for these,
/// the suite fails instead of quietly depending on Base being up. The happy
/// path needs a real chain and lives in exact-evm.live.mjs.
function harness() {
  const config = { chain: base, rpcUrl: "http://127.0.0.1:1", assets: { [USDC]: META } };
  return { evm: createExactEvm({ "eip155:8453": config, base: config }) };
}

test("v1 and v2 payment headers decode to the same authorization", () => {
  const authorization = { from: payer.address, to: PAY_TO, value: "35600", validAfter: "1", validBefore: "2", nonce: "0x00" };
  const v2 = Buffer.from(JSON.stringify({
    x402Version: 2, accepted: { scheme: "exact", network: "eip155:8453" }, payload: { signature: "0xab", authorization },
  })).toString("base64");
  const v1 = Buffer.from(JSON.stringify({
    x402Version: 1, scheme: "exact", network: "base", payload: { signature: "0xab", authorization },
  })).toString("base64");

  const a = parsePayment(v2);
  const b = parsePayment(v1);
  assert.deepEqual(a.payload.authorization, b.payload.authorization);
  assert.equal(a.accepted.scheme, "exact");
  assert.equal(b.accepted.scheme, "exact");
  assert.equal(b.accepted.network, "base");
});

test("a malformed payment header is a failed payment, not an absent one", () => {
  assert.equal(parsePayment("not base64 at all !!"), null);
  assert.equal(parsePayment(Buffer.from("[]").toString("base64")).x402Version, 1);
});

test("detect picks the version from whichever header is present", () => {
  assert.equal(detect({ "PAYMENT-SIGNATURE": "abc" }).version, 2);
  assert.equal(detect({ "x-payment": "abc" }).version, 1);
  assert.equal(detect({ "X-Payment": "abc" }).version, 1);
  assert.equal(detect({}), null);
});

test("v1 requirements rename the amount and the network", () => {
  const v1 = requirementsFor(1, requirements());
  assert.equal(v1.maxAmountRequired, "35600");
  assert.equal(v1.amount, undefined);
  assert.equal(v1.network, "base");

  const v2 = requirementsFor(2, requirements());
  assert.equal(v2.amount, "35600");
  assert.equal(v2.network, "eip155:8453");
});

test("network aliases map only where they are defined", () => {
  assert.equal(v1Network("eip155:8453"), "base");
  // A chain with no established v1 name passes through unchanged.
  assert.equal(v1Network("eip155:4663"), "eip155:4663");
  assert.equal(v1Network("eip155:999999"), "eip155:999999");
});

test("v1 answers 402 in the body, v2 in a header", () => {
  const accepts = [requirements()];
  const one = paymentRequired(1, { accepts, error: "payment required" });
  assert.equal(Object.keys(one.headers).length, 0);
  assert.equal(one.body.x402Version, 1);
  assert.equal(one.body.accepts[0].maxAmountRequired, "35600");

  const two = paymentRequired(2, { accepts, error: "payment required" });
  const decoded = JSON.parse(Buffer.from(two.headers["PAYMENT-REQUIRED"], "base64").toString());
  assert.equal(decoded.x402Version, 2);
  assert.equal(decoded.accepts[0].amount, "35600");
});

test("only v2 reports settlement in a header", () => {
  const settlement = { success: true, transaction: "0xabc", network: "eip155:8453", payer: payer.address };
  assert.deepEqual(paymentResponse(1, settlement).headers, {});
  const decoded = JSON.parse(
    Buffer.from(paymentResponse(2, settlement).headers["PAYMENT-RESPONSE"], "base64").toString(),
  );
  assert.equal(decoded.transaction, "0xabc");
  assert.equal(decoded.success, true);
});

test("an unknown network is refused before any chain read", async () => {
  const { evm } = harness();
  const result = await evm.verify(await signed(), requirements({ network: "eip155:1" }));
  assert.equal(result.isValid, false);
  assert.equal(result.invalidReason, "invalid_network");
});

test("an asset we do not price is refused", async () => {
  const { evm } = harness();
  const other = "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85";
  const result = await evm.verify(await signed(), requirements({ asset: other }));
  assert.equal(result.isValid, false);
  assert.equal(result.invalidReason, "invalid_network");
});

test("a payment to the wrong recipient names the payer in the refusal", async () => {
  const { evm } = harness();
  const result = await evm.verify(
    await signed(),
    requirements({ payTo: "0x0000000000000000000000000000000000000dEaD" }),
  );
  assert.equal(result.isValid, false);
  assert.equal(result.invalidReason, "invalid_exact_evm_payload_recipient_mismatch");
  assert.equal(result.payer, payer.address);
});

test("exact means exact: paying more is refused too", async () => {
  const { evm } = harness();
  const over = await signed({ value: 40_000n });
  const result = await evm.verify(over, requirements());
  assert.equal(result.isValid, false);
  assert.equal(result.invalidReason, "invalid_exact_evm_payload_authorization_value_mismatch");
});

test("an authorization that expires mid-settlement is refused up front", async () => {
  const { evm } = harness();
  // Inside the margin: still valid this instant, reverts by the time it lands.
  const soon = await signed({ validBefore: BigInt(NOW + 3) });
  const result = await evm.verify(soon, requirements(), { now: NOW });
  assert.equal(result.isValid, false);
  assert.equal(result.invalidReason, "invalid_exact_evm_payload_authorization_valid_before");
});

test("an authorization that is not yet valid is refused", async () => {
  const { evm } = harness();
  const later = await signed({ validAfter: BigInt(NOW + 300) });
  const result = await evm.verify(later, requirements(), { now: NOW });
  assert.equal(result.isValid, false);
  assert.equal(result.invalidReason, "invalid_exact_evm_payload_authorization_valid_after");
});

test("a nonce that is not 32 bytes is a malformed payload", async () => {
  const { evm } = harness();
  const bad = await signed();
  bad.payload.authorization.nonce = "0x1234";
  const result = await evm.verify(bad, requirements());
  assert.equal(result.isValid, false);
  assert.equal(result.invalidReason, "invalid_payload");
});

test("a missing authorization is a malformed payload", async () => {
  const { evm } = harness();
  const result = await evm.verify({ x402Version: 2, payload: { signature: "0xab" } }, requirements());
  assert.equal(result.isValid, false);
  assert.equal(result.invalidReason, "invalid_payload");
});

test("an unsupported protocol version is refused by name", async () => {
  const { evm } = harness();
  const payload = await signed();
  payload.x402Version = 9;
  const result = await evm.verify(payload, requirements());
  assert.equal(result.isValid, false);
  assert.equal(result.invalidReason, "invalid_x402_version");
});

test("a scheme we do not implement is refused", async () => {
  const { evm } = harness();
  const payload = await signed();
  payload.accepted = { ...requirements(), scheme: "upto" };
  const result = await evm.verify(payload, requirements());
  assert.equal(result.isValid, false);
  assert.equal(result.invalidReason, "invalid_scheme");
});

test("requirements with no amount are refused as requirements, not as payload", async () => {
  const { evm } = harness();
  const bare = requirements();
  delete bare.amount;
  const result = await evm.verify(await signed(), bare);
  assert.equal(result.isValid, false);
  assert.equal(result.invalidReason, "invalid_payment_requirements");
});

test("supported lists both versions for every configured network", () => {
  const { evm } = harness();
  const kinds = evm.supported().kinds;
  assert.ok(kinds.some((k) => k.x402Version === 1 && k.network === "eip155:8453"));
  assert.ok(kinds.some((k) => k.x402Version === 2 && k.network === "eip155:8453"));
  assert.ok(kinds.every((k) => k.scheme === "exact"));
});

test("the signed digest matches the domain Base USDC actually reports", async () => {
  // Pins the trap: signing under "USDC" instead of "USD Coin" must not verify
  // against the domain we quote.
  const wrongDomain = await payer.signTypedData({
    domain: { name: "USDC", version: "2", chainId: base.id, verifyingContract: USDC },
    types: AUTHORIZATION_TYPES,
    primaryType: "TransferWithAuthorization",
    message: {
      from: payer.address,
      to: PAY_TO,
      value: 35_600n,
      validAfter: BigInt(NOW - 60),
      validBefore: BigInt(NOW + 600),
      nonce: keccak256(toHex("prism-test-nonce")),
    },
  });
  const right = (await signed()).payload.signature;
  assert.notEqual(wrongDomain, right, "domain name must change the signature");
});
