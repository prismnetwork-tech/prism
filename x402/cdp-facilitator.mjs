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
import { requirementsFor } from "./codec.mjs";

const CDP_HOST = "api.cdp.coinbase.com";
const CDP_PREFIX = "/platform/v2/x402";

/// CDP accepts both protocol versions. v2 is used because the Bazaar reads the
/// discovery block from `paymentPayload.extensions`, which only exists in v2,
/// and because every entry in the catalog is a v2 entry.
const V2_VERSION = 2;

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

  /// The v2 wire shape, and the placement of `extensions` is the whole point.
  ///
  /// The Bazaar builds its entry from what arrives here, not by crawling us
  /// afterwards, and it reads the discovery block from exactly one place per
  /// version: `paymentPayload.extensions` in v2, `paymentRequirements
  /// .outputSchema` in v1. Neither version's `paymentRequirements` declares an
  /// `extensions` field, and the schema strips keys it does not declare, so a
  /// block put there is discarded before the facilitator ever sees it. The
  /// settle still succeeds, the money still moves, and nothing is indexed.
  ///
  /// v2 is what is sent, so the block goes on the payload. The v1 placement is
  /// not populated here because v1 is no longer used for this hop.
  function wire(payload, requirements) {
    const meta = describe?.(requirements) ?? {};
    const resource = meta.resource ?? requirements.resource ?? "";
    const description = meta.description ?? requirements.description ?? "";
    const mimeType = meta.mimeType ?? requirements.mimeType ?? "application/json";
    return {
      x402Version: V2_VERSION,
      paymentPayload: {
        x402Version: V2_VERSION,
        // v2 carries the resource as an object rather than a bare URL.
        resource: { url: resource, description, mimeType },
        accepted: requirementsFor(2, requirements),
        payload: payload.payload,
        ...(meta.extensions ? { extensions: meta.extensions } : {}),
      },
      paymentRequirements: requirementsFor(2, requirements),
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
