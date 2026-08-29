// Ported from Dstack-TEE/private-ai-gateway clients/verifier-ts @ b6b5c1b, Apache-2.0.
//
// Attested-session helpers (§8, §9.2). A session is content-addressed: its id
// is the SHA-256 of the JCS form of the served document, and the signed receipt
// commits to that id. There is no session signature.
import { fromBase64, jcsBytes, sha256Hex, sha256Prefixed } from "./crypto.mjs";

/// `session_id` (§8): bare 64-hex sha256 of the JCS form of the parsed document.
export async function computeSessionId(record) {
  return sha256Hex(jcsBytes(record));
}

/// Appendix B: reject session documents whose `api_version` is not `aci/1`.
export function checkSessionApiVersion(record) {
  return record?.api_version === "aci/1";
}

/// §9.2(2): `evidence.data` decodes and hashes to `evidence.digest`. False when
/// the data URI is absent, malformed, or does not hash.
export async function checkSessionEvidence(evidence) {
  if (evidence == null || typeof evidence !== "object") return false;
  const { digest, data } = evidence;
  if (typeof digest !== "string" || typeof data !== "string") return false;
  const comma = data.indexOf(",");
  if (!data.startsWith("data:") || comma < 0 || !data.slice(0, comma).endsWith(";base64")) return false;
  let bytes;
  try {
    bytes = fromBase64(data.slice(comma + 1));
  } catch {
    return false;
  }
  return (await sha256Prefixed(bytes)) === digest;
}
