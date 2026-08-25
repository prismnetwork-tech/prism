// Ported from Dstack-TEE/private-ai-gateway clients/verifier-ts @ b6b5c1b, Apache-2.0.
//
// Every primitive goes through the Web Crypto API on `globalThis.crypto`, so
// the same code runs in a browser and in Node 20+ with no dependencies. ACI's
// only signature algorithm is Ed25519 and its only hash is SHA-256 (spec
// Appendix B); both are in Web Crypto, so nothing needs injecting.
import { AciFormatError } from "./errors.mjs";

const subtle = globalThis.crypto.subtle;

export function toHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(hex) {
  const h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new AciFormatError(`hex string has odd length: ${hex.length} chars`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new AciFormatError(`invalid hex at offset ${i * 2}: "${h.slice(i * 2, i * 2 + 2)}"`);
    }
    out[i] = byte;
  }
  return out;
}

/// Standard base64 with padding (RFC 4648 §4), the `_b64` field form (Appendix A).
export function toBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function fromBase64(b64) {
  let bin;
  try {
    bin = atob(b64);
  } catch {
    throw new AciFormatError("invalid base64");
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/// JCS (RFC 8785) bytes of a parsed JSON value under the ACI artifact
/// constraints (ASCII member names, integer numbers): compact serialization
/// with sorted member names (§7.2, §8).
export function jcsBytes(value) {
  return new TextEncoder().encode(JSON.stringify(sortedValue(value)));
}

function sortedValue(value) {
  if (Array.isArray(value)) return value.map(sortedValue);
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortedValue(value[key]);
    return out;
  }
  return value;
}

export async function sha256(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

/// The dstack RTMR replay hash (§9.1 policy).
export async function sha384(bytes) {
  return new Uint8Array(await subtle.digest("SHA-384", bytes));
}

export async function sha256Hex(bytes) {
  return toHex(await sha256(bytes));
}

/// `sha256:<lowercase-hex>`, the ACI digest form (Appendix A) used for keyset
/// digests, body hashes and session ids.
export async function sha256Prefixed(bytes) {
  return `sha256:${await sha256Hex(bytes)}`;
}

/// RFC 8032 over `message`. `publicKeyRaw` is the 32-byte raw key, `signature`
/// the 64-byte value. A bad signature or a malformed key is false, never a throw.
export async function verifyEd25519(publicKeyRaw, signature, message) {
  let key;
  try {
    key = await subtle.importKey("raw", publicKeyRaw, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return false;
  }
  try {
    return await subtle.verify({ name: "Ed25519" }, key, signature, message);
  } catch {
    return false;
  }
}
