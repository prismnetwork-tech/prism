// Settling Base through Coinbase's facilitator instead of our own.
//
// The only reason to hand settlement to someone else is discovery: the Bazaar
// indexes an endpoint after its own facilitator settles a payment for it, so a
// resource that settles locally is invisible there no matter how correct it is.
// Robinhood Chain stays on our facilitator, which is the only one that knows it.
//
// Exposes the same verify/settle contract as createExactEvm so the gateway does
// not learn which one it is talking to.

import { createPrivateKey, randomBytes, sign } from "node:crypto";
import { requirementsFor, v1Network } from "./codec.mjs";

const CDP_HOST = "api.cdp.coinbase.com";
const CDP_PREFIX = "/platform/v2/x402";

/// CDP speaks x402 v1 and names the chain "base". Our internal form is v2 with
/// CAIP-2 identifiers, so everything crossing this boundary is converted once
/// here rather than at each call site.
const V1_VERSION = 1;

const b64url = (buf) => Buffer.from(buf).toString("base64url");

function privateKeyFrom(secret) {
  const raw = Buffer.from(secret, "base64");
  // CDP issues the Ed25519 seed and public key concatenated. Node wants a JWK,
  // which is the least fragile way in without hand-rolling PKCS8.
  if (raw.length !== 64) throw new Error(`CDP secret is ${raw.length} bytes, expected 64`);
  return createPrivateKey({
    key: { kty: "OKP", crv: "Ed25519", d: b64url(raw.subarray(0, 32)), x: b64url(raw.subarray(32)) },
    format: "jwk",
  });
}

/**
 * A bearer token for exactly one request. CDP binds the token to the method and
 * path in `uris`, so a token minted for /verify is refused at /settle.
 */
function mintJwt(key, keyId, method, path) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ typ: "JWT", alg: "EdDSA", kid: keyId, nonce: randomBytes(16).toString("hex") }));
  const claims = b64url(JSON.stringify({
    sub: keyId,
    iss: "cdp",
    aud: ["cdp_service"],
    nbf: now,
    exp: now + 120,
    uris: [`${method} ${CDP_HOST}${CDP_PREFIX}${path}`],
  }));
  const signing = `${header}.${claims}`;
  return `${signing}.${b64url(sign(null, Buffer.from(signing), key))}`;
}

/**
 * Verify and settle on Base through Coinbase's facilitator.
 *
 * `networks` lists the CAIP-2 identifiers this should claim. Anything not in it
 * is left to whichever facilitator the caller falls back to.
 */
export function createCdpFacilitator({
  keyId,
  keySecret,
  networks = ["eip155:8453"],
  timeoutMs = 30_000,
  describe = null,
}) {
  if (!keyId || !keySecret) throw new Error("CDP facilitator needs both a key id and a secret");
  const key = privateKeyFrom(keySecret);
  const claimed = new Set(networks.map((n) => n.toLowerCase()));

  async function send(method, path, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`https://${CDP_HOST}${CDP_PREFIX}${path}`, {
        method,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${mintJwt(key, keyId, method, path)}`,
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal,
      });
      const text = await res.text();
      let parsed = null;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        // A non-JSON body from an upstream is a failure to answer, not a verdict.
      }
      return { ok: res.ok, status: res.status, body: parsed, raw: text };
    } finally {
      clearTimeout(timer);
    }
  }

  /// The v1 wire shape. `requirementsFor` already renames amount and network;
  /// the resource fields are what the Bazaar indexes on.
  ///
  /// This is the whole reason the integration exists, so it is worth being
  /// blunt: the indexer builds its entry from what arrives here, not by
  /// crawling us afterwards. A settle carrying an empty resource and no
  /// extensions settles the money and indexes nothing, which looks like
  /// success and achieves none of the point.
  function wire(payload, requirements) {
    const v1 = requirementsFor(1, requirements);
    const meta = describe?.(requirements) ?? {};
    return {
      x402Version: V1_VERSION,
      paymentPayload: {
        x402Version: V1_VERSION,
        scheme: payload.accepted?.scheme ?? "exact",
        network: v1Network(requirements.network),
        payload: payload.payload,
      },
      paymentRequirements: {
        ...v1,
        // The indexer keys on `resource` and will not take a relative path, so
        // the caller's description wins over whatever the requirements carry.
        resource: meta.resource ?? v1.resource ?? requirements.resource ?? "",
        description: meta.description ?? v1.description ?? requirements.description ?? "",
        mimeType: meta.mimeType ?? v1.mimeType ?? requirements.mimeType ?? "application/json",
        ...(meta.extensions ? { extensions: meta.extensions } : {}),
      },
    };
  }

  function handles(network) {
    return claimed.has(String(network ?? "").toLowerCase());
  }

  async function verify(payload, requirements) {
    const res = await send("POST", "/verify", wire(payload, requirements));
    // A refused payment comes back 4xx carrying a verdict. Treating the status
    // as the answer loses the reason and reports our own outage instead of the
    // caller's bad signature.
    if (!res.body || typeof res.body.isValid !== "boolean") {
      return { isValid: false, invalidReason: "facilitator_unavailable", detail: res.raw?.slice(0, 200) };
    }
    return {
      isValid: res.body.isValid,
      payer: res.body.payer ?? payload.payload?.authorization?.from ?? "",
      ...(res.body.isValid
        ? {}
        : { invalidReason: res.body.invalidReason ?? "invalid_payload", detail: res.body.invalidMessage }),
    };
  }

  async function settle(payload, requirements) {
    const res = await send("POST", "/settle", wire(payload, requirements));
    const payer = payload.payload?.authorization?.from ?? "";
    // An unreadable answer after a settle request is the same hazard the local
    // facilitator guards: the transfer may have happened. `settled: null` says
    // unknown, which the caller must not treat as a refundable failure.
    if (!res.body || typeof res.body.success !== "boolean") {
      return {
        success: false,
        settled: res.status >= 500 || res.status === 0 ? null : false,
        errorReason: "settlement_unconfirmed",
        payer,
        transaction: "",
        network: requirements.network,
        detail: res.raw?.slice(0, 200),
      };
    }
    const success = Boolean(res.body.success);
    return {
      success,
      settled: success,
      ...(success ? {} : { errorReason: res.body.errorReason ?? "settlement_failed" }),
      payer: res.body.payer ?? payer,
      transaction: res.body.transaction ?? "",
      network: requirements.network,
    };
  }

  async function supported() {
    const res = await send("GET", "/supported");
    return res.ok && res.body ? res.body : { kinds: [] };
  }

  return { verify, settle, supported, handles };
}

/**
 * Route by network: anything the primary claims goes to it, everything else
 * falls through. Lets Base settle at Coinbase while Robinhood Chain stays with
 * the facilitator that knows it.
 */
export function routeByNetwork(primary, fallback) {
  const pick = (requirements) =>
    primary.handles(requirements?.network) ? primary : fallback;
  return {
    verify: (payload, requirements, options) => pick(requirements).verify(payload, requirements, options),
    settle: (payload, requirements, options) => pick(requirements).settle(payload, requirements, options),
    supported: fallback.supported,
  };
}
