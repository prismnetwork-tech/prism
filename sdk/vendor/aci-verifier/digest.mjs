// Ported from Dstack-TEE/private-ai-gateway clients/verifier-ts @ b6b5c1b, Apache-2.0.
//
// The ACI digest constructions (Appendix A, §3.1, §3.2). Artifacts the service
// builds are hashed as the exact served bytes; the attestation statement is the
// one report payload a verifier constructs itself, as a fixed byte template
// whose inputs are restricted so no JSON escaping is ever needed.
import { jcsBytes, sha256Hex, sha256Prefixed } from "./crypto.mjs";
import { AciFormatError } from "./errors.mjs";

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const NONCE_RE = /^[0-9a-f]{64}$/;

/// `workload_keyset_digest` (§3.1): sha256 over the keyset's JCS form.
export async function computeKeysetDigest(keyset) {
  return sha256Prefixed(jcsBytes(keyset));
}

/// The exact attestation-statement bytes (§3.2) for a keyset digest and the
/// nonce the client sent. A null or undefined nonce means the query parameter
/// was omitted, which puts the JSON literal `null` in the template.
export function attestationStatement(keysetDigest, nonce) {
  if (!DIGEST_RE.test(keysetDigest)) {
    throw new AciFormatError(`keyset digest is not sha256:<64-hex>: "${keysetDigest}"`);
  }
  if (nonce != null && !NONCE_RE.test(nonce)) {
    throw new AciFormatError("nonce must be exactly 64 lowercase hex characters (§3.2)");
  }
  const noncePart = nonce == null ? "null" : `"${nonce}"`;
  return new TextEncoder().encode(
    `{"keyset_digest":"${keysetDigest}","nonce":${noncePart},"purpose":"aci.report_data.v1"}`,
  );
}

/// `report_data` (§3.2): SHA-256 of the attestation statement, as bare lowercase
/// hex (it fills a report-data slot, not an ACI digest string). The TEE places
/// these 32 bytes zero-padded to 64 in the quote's report-data field.
export async function computeReportData(keysetDigest, nonce) {
  return sha256Hex(attestationStatement(keysetDigest, nonce));
}
