// The `exact` scheme on EVM, using EIP-3009 `transferWithAuthorization`.
//
// The payer signs an authorization instead of sending a transaction, so they
// need no gas and we broadcast on their behalf. The token contract enforces
// single use of the nonce, which is what makes replay protection a property of
// the chain rather than of a file on this server.
//
// Verify never writes. Settle broadcasts, and only after simulating, so a
// malformed authorization costs us nothing.
import { createPublicClient, createWalletClient, fallback, getAddress, http, parseAbi } from "viem";
import { privateKeyToAccount } from "viem/accounts";

/// Money should not stop moving because one free endpoint had a bad minute.
/// `rpcUrl` takes a list as readily as a string, and each url keeps its own
/// retries before the next one is tried.
function transportFor(rpcUrl) {
  const urls = (Array.isArray(rpcUrl) ? rpcUrl : [rpcUrl]).filter(Boolean);
  if (urls.length === 0) return http();
  const transports = urls.map((url) => http(url, { timeout: 20_000, retryCount: 2 }));
  return transports.length === 1 ? transports[0] : fallback(transports);
}

export const AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

const eip3009Abi = parseAbi([
  "function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature)",
  "function authorizationState(address authorizer, bytes32 nonce) view returns (bool)",
  "function balanceOf(address) view returns (uint256)",
]);

/// Reasons come from the protocol's own list, because a client is expected to
/// branch on them.
const REASON = {
  network: "invalid_network",
  scheme: "invalid_scheme",
  version: "invalid_x402_version",
  payload: "invalid_payload",
  requirements: "invalid_payment_requirements",
  signature: "invalid_exact_evm_payload_signature",
  early: "invalid_exact_evm_payload_authorization_valid_after",
  expired: "invalid_exact_evm_payload_authorization_valid_before",
  value: "invalid_exact_evm_payload_authorization_value_mismatch",
  recipient: "invalid_exact_evm_payload_recipient_mismatch",
  funds: "insufficient_funds",
  state: "invalid_transaction_state",
  // Not in the protocol's list, because the protocol assumes a facilitator can
  // read what it broadcast. Ours must survive an rpc that cannot.
  unconfirmed: "settlement_unconfirmed",
};

const SUPPORTED_VERSIONS = new Set([1, 2]);

function sameAddress(a, b) {
  try {
    return getAddress(a) === getAddress(b);
  } catch {
    return false;
  }
}

/// A settlement that lands after the authorization expires reverts and burns
/// gas, so anything inside this margin is refused up front instead.
const EXPIRY_MARGIN_SECONDS = 6;

/**
 * @param networks map of network id to its configuration. Both the CAIP-2 form
 *   (`eip155:8453`) and any aliases a v1 client might send (`base`) should point
 *   at the same entry, because the two protocol versions name chains
 *   differently and the underlying chain is the same either way.
 */
export function createExactEvm(networks) {
  const entries = new Map();
  for (const [id, config] of Object.entries(networks)) {
    const chain = config.chain;
    const transport = transportFor(config.rpcUrl);
    const client = createPublicClient({ chain, transport });
    const account = config.privateKey ? privateKeyToAccount(config.privateKey) : null;
    entries.set(id.toLowerCase(), {
      id,
      chain,
      client,
      account,
      wallet: account ? createWalletClient({ account, chain, transport }) : null,
      assets: new Map(
        Object.entries(config.assets).map(([address, meta]) => [getAddress(address), meta]),
      ),
    });
  }

  function resolve(requirements) {
    const entry = entries.get(String(requirements?.network ?? "").toLowerCase());
    if (!entry) return { error: REASON.network };
    let asset;
    try {
      asset = getAddress(requirements.asset);
    } catch {
      return { error: REASON.requirements };
    }
    const meta = entry.assets.get(asset);
    if (!meta) return { error: REASON.network };
    return { entry, asset, meta };
  }

  /// The amount a payment must carry. v1 calls it maxAmountRequired, v2 calls
  /// it amount, and the scheme is `exact`, so either way it is the exact figure.
  function requiredAmount(requirements) {
    const raw = requirements?.amount ?? requirements?.maxAmountRequired;
    if (raw === undefined || raw === null) return null;
    try {
      const value = BigInt(raw);
      return value >= 0n ? value : null;
    } catch {
      return null;
    }
  }

  async function verify(payload, requirements, { now = Math.floor(Date.now() / 1000) } = {}) {
    const version = payload?.x402Version;
    if (version !== undefined && !SUPPORTED_VERSIONS.has(version)) {
      return { isValid: false, invalidReason: REASON.version };
    }

    const accepted = payload?.accepted ?? requirements;
    if ((accepted?.scheme ?? "exact") !== "exact") {
      return { isValid: false, invalidReason: REASON.scheme };
    }

    const resolved = resolve(requirements);
    if (resolved.error) return { isValid: false, invalidReason: resolved.error };
    const { entry, asset, meta } = resolved;

    const authorization = payload?.payload?.authorization;
    const signature = payload?.payload?.signature;
    if (!authorization || typeof signature !== "string" || !signature.startsWith("0x")) {
      return { isValid: false, invalidReason: REASON.payload };
    }

    let from;
    let value;
    let validAfter;
    let validBefore;
    let nonce;
    try {
      from = getAddress(authorization.from);
      value = BigInt(authorization.value);
      validAfter = BigInt(authorization.validAfter);
      validBefore = BigInt(authorization.validBefore);
      nonce = authorization.nonce;
      if (!/^0x[0-9a-fA-F]{64}$/.test(nonce)) return { isValid: false, invalidReason: REASON.payload };
    } catch {
      return { isValid: false, invalidReason: REASON.payload };
    }

    // The payer is named in the authorization, so every reason below can name
    // them too. A client that gets `insufficient_funds` without knowing which
    // wallet was short cannot act on it.
    const payer = from;

    if (!sameAddress(authorization.to, requirements.payTo)) {
      return { isValid: false, invalidReason: REASON.recipient, payer };
    }

    const required = requiredAmount(requirements);
    if (required === null) return { isValid: false, invalidReason: REASON.requirements, payer };
    if (value !== required) return { isValid: false, invalidReason: REASON.value, payer };

    if (validAfter > BigInt(now)) return { isValid: false, invalidReason: REASON.early, payer };
    // The authorization has to outlive the work it pays for, not just the
    // moment it is checked. `maxTimeoutSeconds` is the server's own promise of
    // how long it may take, so a job that runs for fifteen minutes refuses a
    // sixty-second authorization up front rather than doing the work and then
    // discovering it cannot charge for it.
    const mustOutlive = Math.max(EXPIRY_MARGIN_SECONDS, Number(requirements.maxTimeoutSeconds) || 0);
    if (validBefore < BigInt(now + mustOutlive)) {
      return { isValid: false, invalidReason: REASON.expired, payer };
    }

    // The domain has to come from the token itself. The published example uses
    // the testnet token's name, and a wrong domain produces a signature that
    // verifies against nothing with no useful error.
    const valid = await entry.client.verifyTypedData({
      address: from,
      domain: { name: meta.name, version: meta.version, chainId: entry.chain.id, verifyingContract: asset },
      types: AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message: { from, to: getAddress(authorization.to), value, validAfter, validBefore, nonce },
      signature,
    });
    if (!valid) return { isValid: false, invalidReason: REASON.signature, payer };

    const [balance, used] = await Promise.all([
      entry.client.readContract({ address: asset, abi: eip3009Abi, functionName: "balanceOf", args: [from] }),
      entry.client.readContract({
        address: asset,
        abi: eip3009Abi,
        functionName: "authorizationState",
        args: [from, nonce],
      }),
    ]);
    // A spent nonce is the contract reporting this exact authorization already
    // settled, which is a replay rather than a malformed payload.
    if (used) return { isValid: false, invalidReason: REASON.state, payer };
    if (balance < value) return { isValid: false, invalidReason: REASON.funds, payer };

    try {
      await entry.client.simulateContract({
        address: asset,
        abi: eip3009Abi,
        functionName: "transferWithAuthorization",
        args: [from, getAddress(authorization.to), value, validAfter, validBefore, nonce, signature],
        account: entry.account?.address ?? from,
      });
    } catch {
      return { isValid: false, invalidReason: REASON.state, payer };
    }

    return { isValid: true, payer };
  }

  async function settle(payload, requirements, options = {}) {
    const check = await verify(payload, requirements, options);
    if (!check.isValid) {
      return {
        success: false,
        settled: false,
        errorReason: check.invalidReason,
        payer: check.payer ?? "",
        transaction: "",
        network: requirements?.network ?? "",
      };
    }

    const { entry, asset } = resolve(requirements);
    if (!entry.wallet) {
      return {
        success: false,
        settled: false,
        errorReason: REASON.network,
        payer: check.payer,
        transaction: "",
        network: requirements.network,
      };
    }

    const a = payload.payload.authorization;
    const args = [
      getAddress(a.from),
      getAddress(a.to),
      BigInt(a.value),
      BigInt(a.validAfter),
      BigInt(a.validBefore),
      a.nonce,
      payload.payload.signature,
    ];

    let hash;
    try {
      hash = await entry.wallet.writeContract({
        address: asset,
        abi: eip3009Abi,
        functionName: "transferWithAuthorization",
        args,
      });
    } catch (error) {
      return {
        success: false,
        settled: false,
        errorReason: REASON.state,
        payer: check.payer,
        transaction: "",
        network: requirements.network,
        detail: String(error?.shortMessage ?? error?.message ?? error),
      };
    }

    // The broadcast already happened, so a failure to read the receipt is not a
    // failure to pay. Reporting it as one loses money that moved: an endpoint
    // that saw an error here would refund, or serve free, against a transfer
    // that actually settled. Say "unconfirmed" and hand back the hash.
    let receipt;
    try {
      receipt = await entry.client.waitForTransactionReceipt({
        hash,
        timeout: (requirements.maxTimeoutSeconds ?? 60) * 1000,
      });
    } catch (error) {
      return {
        success: false,
        settled: null,
        errorReason: REASON.unconfirmed,
        payer: check.payer,
        transaction: hash,
        network: requirements.network,
        detail: String(error?.shortMessage ?? error?.message ?? error),
      };
    }
    return {
      success: receipt.status === "success",
      settled: receipt.status === "success",
      ...(receipt.status === "success" ? {} : { errorReason: REASON.state }),
      payer: check.payer,
      transaction: hash,
      network: requirements.network,
    };
  }

  /// What a facilitator would publish at GET /supported. Kept here so the same
  /// list drives both the manifest and this module's own routing.
  function supported() {
    // One entry per chain, not per alias. The same chain is registered under
    // both its CAIP-2 id and its v1 name so either spelling routes, but a
    // caller reading this must not conclude we settle on two chains.
    const chains = new Map();
    for (const entry of entries.values()) {
      if (!chains.has(entry.chain.id)) chains.set(entry.chain.id, entry);
    }
    const kinds = [];
    for (const entry of chains.values()) {
      for (const version of SUPPORTED_VERSIONS) {
        kinds.push({
          x402Version: version,
          scheme: "exact",
          network: `eip155:${entry.chain.id}`,
          extra: { assetTransferMethod: "eip3009", assets: [...entry.assets.keys()] },
        });
      }
    }
    return { kinds };
  }

  return { verify, settle, supported, REASON };
}
