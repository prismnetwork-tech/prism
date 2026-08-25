// E2EE v2 client for attested confidential inference: the field-level
// encryption an agent puts around a chat request so the relay that carries it
// holds ciphertext only, and the enclave holding the attested key is the one
// thing that can read the prompt.
//
// The wire contract is the X25519 suite of the ACI E2EE v2 protocol. Each
// protected field value is hex(ephemeral_public_key(32) || gcm_nonce(12) ||
// ciphertext || tag(16)); the AES-256-GCM key is HKDF-SHA256 over the X25519
// shared secret with an empty salt and the suite's info string; the AEAD's
// associated data is the JCS form of a purpose-tagged object that pins the
// field path, the model, the request nonce and the timestamp, so a ciphertext
// cannot be moved to another field, request or model.
import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import { jcsBytes } from "./vendor/aci-verifier/index.mjs";

export const E2EE_VERSION = "2";
export const X25519_SUITE = "x25519-aes-256-gcm-hkdf-sha256";
const HKDF_INFO = "aci.e2ee.v2.x25519";
const REQUEST_PURPOSE = "aci.e2ee.request.v2";
const RESPONSE_PURPOSE = "aci.e2ee.response.v2";

// Node's X25519 keys travel as DER. Raw 32-byte keys are the wire form on both
// sides, so wrap them in the one fixed SPKI/PKCS8 prefix each rather than
// pulling in a curve library to do it.
const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

const RESPONSE_FIELDS = ["content", "reasoning", "reasoning_content"];

export class E2eeError extends Error {
  constructor(message) {
    super(message);
    this.name = "E2eeError";
  }
}

/// The x25519 entry of a quote-bound key set. The service publishes a secp256k1
/// suite too; this client speaks the x25519 one, which is the suite the spec
/// recommends and the only one it implements.
export function selectE2eeKey(keyset) {
  const keys = Array.isArray(keyset?.e2ee_public_keys) ? keyset.e2ee_public_keys : [];
  const entry = keys.find((k) => k.algo === X25519_SUITE);
  if (!entry) throw new E2eeError(`the attested key set publishes no ${X25519_SUITE} key`);
  return entry;
}

export function publicKeyFromRaw(raw) {
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]),
    format: "der",
    type: "spki",
  });
}

export function privateKeyFromSeed(seed) {
  if (seed.length !== 32) throw new E2eeError("an x25519 private key is 32 bytes");
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
}

export function rawPublicKey(key) {
  return key.export({ type: "spki", format: "der" }).subarray(SPKI_PREFIX.length);
}

/// The associated data for one request field (§6). Byte-exact: the test vectors
/// pin this string.
export function requestAad({ algo, model, field, nonce, ts }) {
  return jcsBytes({ purpose: REQUEST_PURPOSE, algo, model, field, nonce, ts });
}

/// The response variant, which additionally binds the response id.
export function responseAad({ algo, model, id, field, nonce, ts }) {
  return jcsBytes({ purpose: RESPONSE_PURPOSE, algo, model, id, field, nonce, ts });
}

/// One field envelope, encrypted to `recipientRaw` under a fresh ephemeral key.
export function sealField(recipientRaw, plaintext, aad, rand = randomBytes) {
  const ephemeral = privateKeyFromSeed(Buffer.from(rand(32)));
  const shared = diffieHellman({ privateKey: ephemeral, publicKey: publicKeyFromRaw(recipientRaw) });
  const key = Buffer.from(hkdfSync("sha256", shared, Buffer.alloc(0), Buffer.from(HKDF_INFO), 32));
  const nonce = Buffer.from(rand(12));
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  return Buffer.concat([rawPublicKey(createPublicKey(ephemeral)), nonce, body, cipher.getAuthTag()]).toString("hex");
}

/// The inverse. A tampered envelope, AAD or key fails the AEAD tag and throws.
export function openField(privateKey, envelopeHex, aad) {
  const blob = Buffer.from(envelopeHex.startsWith("0x") ? envelopeHex.slice(2) : envelopeHex, "hex");
  if (blob.length < 32 + 12 + 16) throw new E2eeError("e2ee envelope is too short to hold a field");
  const shared = diffieHellman({ privateKey, publicKey: publicKeyFromRaw(blob.subarray(0, 32)) });
  const key = Buffer.from(hkdfSync("sha256", shared, Buffer.alloc(0), Buffer.from(HKDF_INFO), 32));
  const decipher = createDecipheriv("aes-256-gcm", key, blob.subarray(32, 44));
  decipher.setAAD(aad);
  decipher.setAuthTag(blob.subarray(blob.length - 16));
  try {
    return Buffer.concat([decipher.update(blob.subarray(44, blob.length - 16)), decipher.final()]).toString("utf8");
  } catch {
    throw new E2eeError("e2ee field did not authenticate: wrong key, wrong context, or altered ciphertext");
  }
}

/// §5 restoration: a decrypted whole-content plaintext that parses as a JSON
/// array is restored as structured content, and anything else stays the string
/// it was. The receipt covers what the workload restored, so a client that
/// reproduces the hash has to apply the same rule to its own copy.
export function restoreContent(plaintext) {
  if (typeof plaintext !== "string" || plaintext.trimStart()[0] !== "[") return plaintext;
  try {
    const value = JSON.parse(plaintext);
    return Array.isArray(value) ? value : plaintext;
  } catch {
    return plaintext;
  }
}

/// Encrypt every message content of a chat-completions body to the attested
/// service key. Returns the bytes to send, the five headers that must travel
/// with them, the client key the response is encrypted to, and the compact
/// restored-plaintext bytes the receipt's `request.received` hash covers.
///
/// `now` and `rand` are injectable so a test can pin the whole envelope; both
/// default to the real clock and the system CSPRNG.
export function encryptChatRequest(body, keyset, { now = Math.floor(Date.now() / 1000), rand = randomBytes } = {}) {
  if (typeof body?.model !== "string") throw new E2eeError("an e2ee request needs a top-level model string");
  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    throw new E2eeError("an e2ee chat request needs a messages array");
  }
  const serviceKey = selectE2eeKey(keyset);
  const serviceRaw = Buffer.from(serviceKey.public_key.replace(/^0x/, ""), "hex");
  if (serviceRaw.length !== 32) throw new E2eeError("the attested x25519 key is not 32 bytes");

  const clientPrivate = privateKeyFromSeed(Buffer.from(rand(32)));
  const clientPublic = rawPublicKey(createPublicKey(clientPrivate));
  const nonce = Buffer.from(rand(32)).toString("hex");
  const ts = now;

  // The plaintext copy is what the workload hashes into the receipt after it
  // restores the fields (§8 of the v2 protocol), so it is built alongside the
  // encrypted one from the same object and in the same member order.
  const restored = { ...body, messages: [] };
  const sealed = { ...body, messages: [] };
  body.messages.forEach((message, index) => {
    if (typeof message?.content !== "string") {
      // Any plaintext string at a protected path fails the request upstream, so
      // a body this client cannot fully protect is refused here instead.
      throw new E2eeError(`messages.${index}.content must be a string to be encrypted`);
    }
    const field = `messages.${index}.content`;
    const aad = requestAad({ algo: serviceKey.algo, model: body.model, field, nonce, ts });
    restored.messages.push({ ...message, content: restoreContent(message.content) });
    sealed.messages.push({ ...message, content: sealField(serviceRaw, message.content, aad, rand) });
  });

  return {
    bytes: Buffer.from(JSON.stringify(sealed), "utf8"),
    restored: Buffer.from(JSON.stringify(restored), "utf8"),
    headers: {
      "X-E2EE-Version": E2EE_VERSION,
      "X-Client-Pub-Key": Buffer.from(clientPublic).toString("hex"),
      "X-Model-Pub-Key": serviceKey.public_key,
      "X-E2EE-Nonce": nonce,
      "X-E2EE-Timestamp": String(ts),
    },
    clientKey: {
      privateKey: clientPrivate,
      publicKey: Buffer.from(clientPublic).toString("hex"),
      algo: serviceKey.algo,
      keyId: serviceKey.key_id,
      model: body.model,
      nonce,
      ts,
    },
  };
}

/// Decrypt a buffered chat-completions response in place. Every generated
/// content field the service encrypted is authenticated against the AAD that
/// names its position, so a field lifted from another response does not open.
export function decryptResponse(bodyBytes, clientKey, { model = clientKey.model } = {}) {
  const text = typeof bodyBytes === "string" ? bodyBytes : Buffer.from(bodyBytes).toString("utf8");
  const body = JSON.parse(text);
  const id = typeof body.id === "string" ? body.id : "";
  const choices = Array.isArray(body.choices) ? body.choices : [];
  choices.forEach((choice, position) => {
    const index = Number.isInteger(choice?.index) ? choice.index : position;
    const message = choice?.message;
    if (message === null || typeof message !== "object") return;
    for (const name of RESPONSE_FIELDS) {
      if (typeof message[name] !== "string" || message[name] === "") continue;
      const aad = responseAad({
        algo: clientKey.algo,
        model,
        id,
        field: `choices.${index}.message.${name}`,
        nonce: clientKey.nonce,
        ts: clientKey.ts,
      });
      message[name] = openField(clientKey.privateKey, message[name], aad);
    }
  });
  return body;
}
