import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import test from "node:test";

import {
  E2eeError,
  X25519_SUITE,
  decryptResponse,
  encryptChatRequest,
  openField,
  privateKeyFromSeed,
  rawPublicKey,
  requestAad,
  responseAad,
  restoreContent,
  sealField,
} from "./e2ee.mjs";

const utf8 = (bytes) => Buffer.from(bytes).toString("utf8");

// spec/e2ee-v2-test-vectors.md. The service seed is the vector document's
// fixed 32 x 0x03, not a live key.
const SERVICE_SEED = Buffer.alloc(32, 3);
const SERVICE_PUBLIC = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22";
const VECTOR_NONCE = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const VECTOR_TS = 1750000000;
const REQUEST_AAD =
  '{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"messages.0.content","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.request.v2","ts":1750000000}';
const RESPONSE_AAD =
  '{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"choices.0.message.content","id":"chatcmpl-123","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.response.v2","ts":1750000000}';

const servicePrivate = privateKeyFromSeed(SERVICE_SEED);
const keyset = {
  e2ee_public_keys: [
    { key_id: "legacy", algo: "secp256k1-aes-256-gcm-hkdf-sha256", public_key: "04" + "ab".repeat(64) },
    { key_id: "e2ee-1", algo: X25519_SUITE, public_key: SERVICE_PUBLIC },
  ],
};

/// A fixed byte stream, so the same call twice produces the same envelope.
function fixedRandom(seed = 0) {
  let n = seed;
  return (length) => Buffer.from(Array.from({ length }, () => (n = (n * 1103515245 + 12345) & 0xff)));
}

test("the service seed derives the public key the vectors pin", () => {
  assert.equal(Buffer.from(rawPublicKey(createPublicKey(servicePrivate))).toString("hex"), SERVICE_PUBLIC);
});

test("the associated data is byte-exact against the vectors", () => {
  assert.equal(
    utf8(requestAad({ algo: X25519_SUITE, model: "demo-model", field: "messages.0.content", nonce: VECTOR_NONCE, ts: VECTOR_TS })),
    REQUEST_AAD,
  );
  assert.equal(
    utf8(
      responseAad({
        algo: X25519_SUITE,
        model: "demo-model",
        id: "chatcmpl-123",
        field: "choices.0.message.content",
        nonce: VECTOR_NONCE,
        ts: VECTOR_TS,
      }),
    ),
    RESPONSE_AAD,
  );
});

test("a sealed field opens under the recipient key and its own context", () => {
  const aad = Buffer.from(REQUEST_AAD, "utf8");
  const envelope = sealField(Buffer.from(SERVICE_PUBLIC, "hex"), "the prompt", aad);
  assert.match(envelope, /^[0-9a-f]+$/);
  // ephemeral key, gcm nonce, ciphertext, tag
  assert.equal(Buffer.from(envelope, "hex").length, 32 + 12 + "the prompt".length + 16);
  assert.equal(openField(servicePrivate, envelope, aad), "the prompt");
});

test("a field moved to another position or request does not open", () => {
  const aad = requestAad({ algo: X25519_SUITE, model: "demo-model", field: "messages.0.content", nonce: VECTOR_NONCE, ts: VECTOR_TS });
  const envelope = sealField(Buffer.from(SERVICE_PUBLIC, "hex"), "the prompt", aad);

  const moved = requestAad({ algo: X25519_SUITE, model: "demo-model", field: "messages.1.content", nonce: VECTOR_NONCE, ts: VECTOR_TS });
  assert.throws(() => openField(servicePrivate, envelope, moved), E2eeError);

  const otherRequest = requestAad({ algo: X25519_SUITE, model: "demo-model", field: "messages.0.content", nonce: "ff".repeat(32), ts: VECTOR_TS });
  assert.throws(() => openField(servicePrivate, envelope, otherRequest), E2eeError);

  const otherModel = requestAad({ algo: X25519_SUITE, model: "another-model", field: "messages.0.content", nonce: VECTOR_NONCE, ts: VECTOR_TS });
  assert.throws(() => openField(servicePrivate, envelope, otherModel), E2eeError);
});

test("an altered ciphertext does not open", () => {
  const aad = Buffer.from(REQUEST_AAD, "utf8");
  const envelope = Buffer.from(sealField(Buffer.from(SERVICE_PUBLIC, "hex"), "the prompt", aad), "hex");
  envelope[50] ^= 0x01;
  assert.throws(() => openField(servicePrivate, envelope.toString("hex"), aad), E2eeError);
});

const body = {
  model: "demo-model",
  messages: [
    { role: "system", content: "answer briefly" },
    { role: "user", content: "what is my position worth" },
  ],
  max_tokens: 256,
};

test("a chat request travels as ciphertext with the five headers the service requires", () => {
  const sealed = encryptChatRequest(body, keyset, { now: VECTOR_TS, rand: fixedRandom(7) });
  assert.deepEqual(Object.keys(sealed.headers).sort(), [
    "X-Client-Pub-Key",
    "X-E2EE-Nonce",
    "X-E2EE-Timestamp",
    "X-E2EE-Version",
    "X-Model-Pub-Key",
  ]);
  assert.equal(sealed.headers["X-E2EE-Version"], "2");
  assert.equal(sealed.headers["X-Model-Pub-Key"], SERVICE_PUBLIC);
  assert.equal(sealed.headers["X-E2EE-Timestamp"], String(VECTOR_TS));
  assert.match(sealed.headers["X-E2EE-Nonce"], /^[0-9a-f]{64}$/);
  // X-Signing-Algo selects the pre-ACI path, which has no associated data.
  assert.equal(sealed.headers["X-Signing-Algo"], undefined);

  const wire = JSON.parse(utf8(sealed.bytes));
  assert.equal(wire.model, "demo-model");
  assert.equal(wire.max_tokens, 256);
  for (const [index, message] of wire.messages.entries()) {
    assert.notEqual(message.content, body.messages[index].content);
    const aad = requestAad({
      algo: X25519_SUITE,
      model: "demo-model",
      field: `messages.${index}.content`,
      nonce: sealed.headers["X-E2EE-Nonce"],
      ts: VECTOR_TS,
    });
    assert.equal(openField(servicePrivate, message.content, aad), body.messages[index].content);
  }
  assert.equal(utf8(sealed.bytes).includes("what is my position worth"), false);
});

test("the restored bytes are what the receipt commits to for an encrypted request", () => {
  const sealed = encryptChatRequest(body, keyset, { now: VECTOR_TS, rand: fixedRandom(3) });
  // The workload decrypts each field in place and hashes the compact JSON that
  // leaves, so the reproduction keeps the member order the wire body had.
  assert.equal(utf8(sealed.restored), JSON.stringify(body));
  assert.deepEqual(Object.keys(JSON.parse(utf8(sealed.bytes))), Object.keys(JSON.parse(utf8(sealed.restored))));
});

test("a content that parses as a JSON array is restored as structured content", () => {
  // §5: the workload restores a whole-content plaintext that parses as a JSON
  // array as structured content, so a client reproducing the receipt's request
  // hash has to restore it the same way. A pasted array of tool results is the
  // ordinary way a user hits this.
  const tools = '[{"type":"text","text":"result 1"},{"type":"text","text":"result 2"}]';
  assert.deepEqual(restoreContent(tools), JSON.parse(tools));
  assert.equal(restoreContent("[1,2,3"), "[1,2,3");
  assert.equal(restoreContent('{"a":1}'), '{"a":1}');
  assert.equal(restoreContent("what is my position worth"), "what is my position worth");
  assert.equal(restoreContent("42"), "42");

  const pasted = { model: "demo-model", messages: [{ role: "user", content: tools }], max_tokens: 256 };
  const sealed = encryptChatRequest(pasted, keyset, { now: VECTOR_TS, rand: fixedRandom(4) });
  const restored = JSON.parse(utf8(sealed.restored));
  assert.deepEqual(restored.messages[0].content, JSON.parse(tools));
  // The wire body still carries the ciphertext of the string that was sent.
  const aad = requestAad({
    algo: X25519_SUITE,
    model: "demo-model",
    field: "messages.0.content",
    nonce: sealed.headers["X-E2EE-Nonce"],
    ts: VECTOR_TS,
  });
  assert.equal(openField(servicePrivate, JSON.parse(utf8(sealed.bytes)).messages[0].content, aad), tools);
});

test("injected randomness and clock make the whole envelope reproducible", () => {
  const first = encryptChatRequest(body, keyset, { now: VECTOR_TS, rand: fixedRandom(11) });
  const second = encryptChatRequest(body, keyset, { now: VECTOR_TS, rand: fixedRandom(11) });
  assert.equal(utf8(first.bytes), utf8(second.bytes));
  assert.deepEqual(first.headers, second.headers);

  const third = encryptChatRequest(body, keyset, { now: VECTOR_TS, rand: fixedRandom(12) });
  assert.notEqual(utf8(third.bytes), utf8(first.bytes));
});

test("the response decrypts to the client's static key", () => {
  const sealed = encryptChatRequest(body, keyset, { now: VECTOR_TS, rand: fixedRandom(5) });
  const clientPublic = Buffer.from(sealed.clientKey.publicKey, "hex");
  const aad = responseAad({
    algo: X25519_SUITE,
    model: "demo-model",
    id: "chatcmpl-9",
    field: "choices.0.message.content",
    nonce: sealed.headers["X-E2EE-Nonce"],
    ts: VECTOR_TS,
  });
  const wire = JSON.stringify({
    id: "chatcmpl-9",
    choices: [{ index: 0, message: { role: "assistant", content: sealField(clientPublic, "about 4,200 USDG", aad) } }],
    usage: { prompt_tokens: 12, completion_tokens: 5 },
  });

  const restored = decryptResponse(Buffer.from(wire, "utf8"), sealed.clientKey);
  assert.equal(restored.choices[0].message.content, "about 4,200 USDG");
  assert.equal(restored.usage.completion_tokens, 5);
});

test("a response field from another generation does not decrypt", () => {
  const sealed = encryptChatRequest(body, keyset, { now: VECTOR_TS, rand: fixedRandom(9) });
  const clientPublic = Buffer.from(sealed.clientKey.publicKey, "hex");
  const aad = responseAad({
    algo: X25519_SUITE,
    model: "demo-model",
    id: "chatcmpl-other",
    field: "choices.0.message.content",
    nonce: sealed.headers["X-E2EE-Nonce"],
    ts: VECTOR_TS,
  });
  const wire = JSON.stringify({
    id: "chatcmpl-9",
    choices: [{ index: 0, message: { content: sealField(clientPublic, "about 4,200 USDG", aad) } }],
  });
  assert.throws(() => decryptResponse(Buffer.from(wire, "utf8"), sealed.clientKey), E2eeError);
});

test("a request this client cannot protect end to end is refused before it is sent", () => {
  assert.throws(() => encryptChatRequest({ ...body, model: 7 }, keyset), E2eeError);
  assert.throws(() => encryptChatRequest({ model: "demo-model", messages: [] }, keyset), E2eeError);
  assert.throws(
    () => encryptChatRequest({ model: "demo-model", messages: [{ role: "user", content: [{ type: "text", text: "hi" }] }] }, keyset),
    E2eeError,
  );
  assert.throws(() => encryptChatRequest(body, { e2ee_public_keys: [] }), E2eeError);
});
