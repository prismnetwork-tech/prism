// Ported from Dstack-TEE/private-ai-gateway clients/verifier-ts @ b6b5c1b, Apache-2.0.
//
// Receipt verification (§7, §9.3). A receipt is one JSON document; its
// `signature` is Ed25519 over JCS(document minus `signature`) under a key the
// established keyset lists. "Established" means a keyset whose digest the
// caller verified.
import { fromHex, jcsBytes, sha256Prefixed, verifyEd25519 } from "./crypto.mjs";

/// §9.3 checks 1-2: the `signature` member verifies over JCS(document minus
/// `signature`) under the keyset entry `key_id` names, and the document's
/// `workload_keyset_digest` equals the established digest. Documents whose
/// `api_version` is not `aci/1` are rejected (Appendix B).
export async function verifyReceipt(document, keyset, establishedDigest) {
  const checks = [];

  const signingKeys = Array.isArray(keyset.receipt_signing_keys) ? keyset.receipt_signing_keys : [];
  const keyEntry = signingKeys.find((k) => k.key_id === document.key_id);
  if (!keyEntry) {
    checks.push({
      name: "signature",
      ok: false,
      detail: `key_id "${document.key_id}" not in receipt_signing_keys`,
    });
  } else if (keyEntry.algo !== "ed25519") {
    // Appendix B: ed25519 is the only defined signature algorithm.
    checks.push({ name: "signature", ok: false, detail: `unsupported signature algo "${keyEntry.algo}"` });
  } else {
    const { signature, ...unsigned } = document;
    let ok = false;
    try {
      ok = await verifyEd25519(fromHex(keyEntry.public_key), fromHex(signature), jcsBytes(unsigned));
    } catch {
      // Malformed hex is a failed verification, not a thrown one.
    }
    checks.push({
      name: "signature",
      ok,
      ...(ok ? {} : { detail: `ed25519 verification failed under "${document.key_id}"` }),
    });
  }

  const versionOk = document.api_version === "aci/1";
  checks.push({
    name: "api_version",
    ok: versionOk,
    ...(versionOk ? {} : { detail: `api_version "${document.api_version}" is not "aci/1"` }),
  });

  const boundOk = document.workload_keyset_digest === establishedDigest;
  checks.push({
    name: "workload_keyset_digest",
    ok: boundOk,
    ...(boundOk
      ? {}
      : { detail: `document ${document.workload_keyset_digest} != established ${establishedDigest}` }),
  });

  return { ok: checks.every((c) => c.ok), checks, payload: document };
}

export function findEvent(payload, type) {
  // Server-supplied JSON: a malformed document is a failed lookup, not a throw.
  if (!Array.isArray(payload.event_log)) return undefined;
  return payload.event_log.find((e) => e.type === type);
}

/// `sha256:<hex>` of raw body bytes, the form ACI body hashes use (Appendix A).
export async function hashBody(body) {
  return sha256Prefixed(typeof body === "string" ? new TextEncoder().encode(body) : body);
}

/// §9.3 check 3: `request.received.body_hash` matches the plaintext wire body,
/// or the compact post-decryption JSON body for E2EE (§7.4).
export async function checkRequestBodyHash(payload, requestBody) {
  return eventHashMatches(payload, "request.received", requestBody);
}

/// §9.3 check 4: `response.returned.body_hash` matches the response bytes this
/// client read off the wire, SSE framing included (§7.4).
export async function checkResponseBodyHash(payload, responseBody) {
  return eventHashMatches(payload, "response.returned", responseBody);
}

async function eventHashMatches(payload, type, body) {
  const expected = findEvent(payload, type)?.body_hash;
  if (typeof expected !== "string") return false;
  return (await hashBody(body)) === expected;
}
