"""The E2EE v2 envelope, and whether this SDK encrypts what the Node one reads.

The vectors are the ones ``sdk/e2ee.test.mjs`` pins, taken from the ACI E2EE v2
test-vector document. The service seed is that document's fixed 32 x 0x03, not a
live key.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from prismnetwork._e2ee import (
    X25519_SUITE,
    ClientKey,
    E2eeError,
    decrypt_response,
    encrypt_chat_request,
    open_field,
    private_key_from_seed,
    raw_public_key,
    request_aad,
    response_aad,
    restore_content,
    seal_field,
)

SERVICE_SEED = bytes([3]) * 32
SERVICE_PUBLIC = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"
VECTOR_NONCE = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
VECTOR_TS = 1750000000
REQUEST_AAD = (
    '{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"messages.0.content","model":"demo-model",'
    f'"nonce":"{VECTOR_NONCE}","purpose":"aci.e2ee.request.v2","ts":{VECTOR_TS}}}'
)
RESPONSE_AAD = (
    '{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"choices.0.message.content","id":"chatcmpl-123",'
    f'"model":"demo-model","nonce":"{VECTOR_NONCE}","purpose":"aci.e2ee.response.v2","ts":{VECTOR_TS}}}'
)

# The Node module these functions are a port of. Absent from an installed wheel,
# present in a checkout, which is where the comparison is worth making.
NODE_MODULE = Path(__file__).resolve().parents[2] / "sdk" / "e2ee.mjs"

SERVICE_PRIVATE = private_key_from_seed(SERVICE_SEED)
KEYSET = {
    "e2ee_public_keys": [
        {"key_id": "legacy", "algo": "secp256k1-aes-256-gcm-hkdf-sha256", "public_key": "04" + "ab" * 64},
        {"key_id": "e2ee-1", "algo": X25519_SUITE, "public_key": SERVICE_PUBLIC},
    ]
}
BODY = {
    "model": "demo-model",
    "messages": [
        {"role": "system", "content": "answer briefly"},
        {"role": "user", "content": "what is my position worth"},
    ],
    "max_tokens": 256,
}


def fixed_random(seed=0):
    """A fixed byte stream, so the same call twice produces the same envelope."""
    state = seed

    def rand(length):
        nonlocal state
        out = bytearray()
        for _ in range(length):
            state = (state * 1103515245 + 12345) & 0xFF
            out.append(state)
        return bytes(out)

    return rand


def node(script: str, argument) -> str:
    out = subprocess.run(["node", "--input-type=module", "-e", script, json.dumps(argument)],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


needs_node = unittest.skipUnless(shutil.which("node") and NODE_MODULE.exists(),
                                 "needs node and a checkout")


class EnvelopeTest(unittest.TestCase):
    def test_the_service_seed_derives_the_public_key_the_vectors_pin(self):
        self.assertEqual(raw_public_key(SERVICE_PRIVATE.public_key()).hex(), SERVICE_PUBLIC)

    def test_the_associated_data_is_byte_exact_against_the_vectors(self):
        self.assertEqual(
            request_aad(algo=X25519_SUITE, model="demo-model", field="messages.0.content",
                        nonce=VECTOR_NONCE, ts=VECTOR_TS).decode(),
            REQUEST_AAD,
        )
        self.assertEqual(
            response_aad(algo=X25519_SUITE, model="demo-model", chat_id="chatcmpl-123",
                         field="choices.0.message.content", nonce=VECTOR_NONCE, ts=VECTOR_TS).decode(),
            RESPONSE_AAD,
        )

    def test_a_sealed_field_opens_under_the_recipient_key_and_its_own_context(self):
        aad = REQUEST_AAD.encode()
        envelope = seal_field(bytes.fromhex(SERVICE_PUBLIC), "the prompt", aad)
        # ephemeral key, gcm nonce, ciphertext, tag
        self.assertEqual(len(bytes.fromhex(envelope)), 32 + 12 + len("the prompt") + 16)
        self.assertEqual(open_field(SERVICE_PRIVATE, envelope, aad), "the prompt")

    def test_a_field_moved_to_another_position_or_request_does_not_open(self):
        aad = request_aad(algo=X25519_SUITE, model="demo-model", field="messages.0.content",
                          nonce=VECTOR_NONCE, ts=VECTOR_TS)
        envelope = seal_field(bytes.fromhex(SERVICE_PUBLIC), "the prompt", aad)

        moved = request_aad(algo=X25519_SUITE, model="demo-model", field="messages.1.content",
                            nonce=VECTOR_NONCE, ts=VECTOR_TS)
        other_request = request_aad(algo=X25519_SUITE, model="demo-model", field="messages.0.content",
                                    nonce="ff" * 32, ts=VECTOR_TS)
        other_model = request_aad(algo=X25519_SUITE, model="another-model", field="messages.0.content",
                                  nonce=VECTOR_NONCE, ts=VECTOR_TS)
        for context in (moved, other_request, other_model):
            with self.assertRaises(E2eeError):
                open_field(SERVICE_PRIVATE, envelope, context)

    def test_an_altered_ciphertext_does_not_open(self):
        aad = REQUEST_AAD.encode()
        envelope = bytearray(bytes.fromhex(seal_field(bytes.fromhex(SERVICE_PUBLIC), "the prompt", aad)))
        envelope[50] ^= 0x01
        with self.assertRaises(E2eeError):
            open_field(SERVICE_PRIVATE, envelope.hex(), aad)


class ChatRequestTest(unittest.TestCase):
    def test_a_chat_request_travels_as_ciphertext_with_the_five_headers_the_service_requires(self):
        sealed = encrypt_chat_request(BODY, KEYSET, now=VECTOR_TS, rand=fixed_random(7))
        self.assertEqual(sorted(sealed.headers), [
            "X-Client-Pub-Key", "X-E2EE-Nonce", "X-E2EE-Timestamp", "X-E2EE-Version", "X-Model-Pub-Key",
        ])
        self.assertEqual(sealed.headers["X-E2EE-Version"], "2")
        self.assertEqual(sealed.headers["X-Model-Pub-Key"], SERVICE_PUBLIC)
        self.assertEqual(sealed.headers["X-E2EE-Timestamp"], str(VECTOR_TS))
        self.assertRegex(sealed.headers["X-E2EE-Nonce"], r"^[0-9a-f]{64}$")

        wire = json.loads(sealed.payload.decode())
        self.assertEqual(wire["model"], "demo-model")
        self.assertEqual(wire["max_tokens"], 256)
        for index, message in enumerate(wire["messages"]):
            self.assertNotEqual(message["content"], BODY["messages"][index]["content"])
            aad = request_aad(algo=X25519_SUITE, model="demo-model", field=f"messages.{index}.content",
                              nonce=sealed.headers["X-E2EE-Nonce"], ts=VECTOR_TS)
            self.assertEqual(open_field(SERVICE_PRIVATE, message["content"], aad),
                             BODY["messages"][index]["content"])
        self.assertNotIn("what is my position worth", sealed.payload.decode())

    def test_the_restored_bytes_are_what_the_receipt_commits_to(self):
        sealed = encrypt_chat_request(BODY, KEYSET, now=VECTOR_TS, rand=fixed_random(3))
        # The workload decrypts each field in place and hashes the compact JSON
        # that leaves, so the reproduction keeps the member order the wire body
        # had.
        self.assertEqual(sealed.restored.decode(), json.dumps(BODY, separators=(",", ":")))
        self.assertEqual(list(json.loads(sealed.payload.decode())),
                         list(json.loads(sealed.restored.decode())))

    def test_a_content_that_parses_as_a_json_array_is_restored_as_structured_content(self):
        tools = '[{"type":"text","text":"result 1"},{"type":"text","text":"result 2"}]'
        self.assertEqual(restore_content(tools), json.loads(tools))
        self.assertEqual(restore_content("[1,2,3"), "[1,2,3")
        self.assertEqual(restore_content('{"a":1}'), '{"a":1}')
        self.assertEqual(restore_content("what is my position worth"), "what is my position worth")
        self.assertEqual(restore_content("42"), "42")

        pasted = {"model": "demo-model", "messages": [{"role": "user", "content": tools}], "max_tokens": 256}
        sealed = encrypt_chat_request(pasted, KEYSET, now=VECTOR_TS, rand=fixed_random(4))
        restored = json.loads(sealed.restored.decode())
        self.assertEqual(restored["messages"][0]["content"], json.loads(tools))
        aad = request_aad(algo=X25519_SUITE, model="demo-model", field="messages.0.content",
                          nonce=sealed.headers["X-E2EE-Nonce"], ts=VECTOR_TS)
        wire = json.loads(sealed.payload.decode())
        self.assertEqual(open_field(SERVICE_PRIVATE, wire["messages"][0]["content"], aad), tools)

    def test_injected_randomness_and_clock_make_the_whole_envelope_reproducible(self):
        first = encrypt_chat_request(BODY, KEYSET, now=VECTOR_TS, rand=fixed_random(11))
        second = encrypt_chat_request(BODY, KEYSET, now=VECTOR_TS, rand=fixed_random(11))
        self.assertEqual(first.payload, second.payload)
        self.assertEqual(first.headers, second.headers)
        third = encrypt_chat_request(BODY, KEYSET, now=VECTOR_TS, rand=fixed_random(12))
        self.assertNotEqual(third.payload, first.payload)

    def test_the_response_decrypts_to_the_clients_static_key(self):
        sealed = encrypt_chat_request(BODY, KEYSET, now=VECTOR_TS, rand=fixed_random(5))
        aad = response_aad(algo=X25519_SUITE, model="demo-model", chat_id="chatcmpl-9",
                           field="choices.0.message.content",
                           nonce=sealed.headers["X-E2EE-Nonce"], ts=VECTOR_TS)
        wire = json.dumps({
            "id": "chatcmpl-9",
            "choices": [{"index": 0, "message": {
                "role": "assistant",
                "content": seal_field(bytes.fromhex(sealed.client_key.public_key), "about 4,200 USDG", aad),
            }}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 5},
        })

        restored = decrypt_response(wire.encode(), sealed.client_key)
        self.assertEqual(restored["choices"][0]["message"]["content"], "about 4,200 USDG")
        self.assertEqual(restored["usage"]["completion_tokens"], 5)

    def test_a_response_field_from_another_generation_does_not_decrypt(self):
        sealed = encrypt_chat_request(BODY, KEYSET, now=VECTOR_TS, rand=fixed_random(9))
        aad = response_aad(algo=X25519_SUITE, model="demo-model", chat_id="chatcmpl-other",
                           field="choices.0.message.content",
                           nonce=sealed.headers["X-E2EE-Nonce"], ts=VECTOR_TS)
        wire = json.dumps({
            "id": "chatcmpl-9",
            "choices": [{"index": 0, "message": {
                "content": seal_field(bytes.fromhex(sealed.client_key.public_key), "about 4,200 USDG", aad),
            }}],
        })
        with self.assertRaises(E2eeError):
            decrypt_response(wire.encode(), sealed.client_key)

    def test_a_request_this_client_cannot_protect_end_to_end_is_refused_before_it_is_sent(self):
        with self.assertRaises(E2eeError):
            encrypt_chat_request({**BODY, "model": 7}, KEYSET)
        with self.assertRaises(E2eeError):
            encrypt_chat_request({"model": "demo-model", "messages": []}, KEYSET)
        with self.assertRaises(E2eeError):
            encrypt_chat_request(
                {"model": "demo-model", "messages": [{"role": "user", "content": [{"type": "text"}]}]},
                KEYSET,
            )
        with self.assertRaises(E2eeError):
            encrypt_chat_request(BODY, {"e2ee_public_keys": []})


SEAL_SCRIPT = """
    import { sealField, privateKeyFromSeed, rawPublicKey } from %s;
    import { createPublicKey } from "node:crypto";
    const { seed, recipient, plaintext, aad } = JSON.parse(process.argv[1]);
    const envelope = sealField(Buffer.from(recipient, "hex"), plaintext, Buffer.from(aad, "utf8"));
    const client = privateKeyFromSeed(Buffer.from(seed, "hex"));
    console.log(JSON.stringify({
      envelope,
      clientPublic: Buffer.from(rawPublicKey(createPublicKey(client))).toString("hex"),
    }));
"""

OPEN_SCRIPT = """
    import { openField, privateKeyFromSeed } from %s;
    const { seed, envelope, aad } = JSON.parse(process.argv[1]);
    console.log(openField(privateKeyFromSeed(Buffer.from(seed, "hex")), envelope, Buffer.from(aad, "utf8")));
"""

ENCRYPT_SCRIPT = """
    import { encryptChatRequest } from %s;
    const { body, keyset } = JSON.parse(process.argv[1]);
    const sealed = encryptChatRequest(body, keyset);
    console.log(JSON.stringify({
      bytes: sealed.bytes.toString("utf8"),
      restored: sealed.restored.toString("utf8"),
      headers: sealed.headers,
    }));
"""


@needs_node
class CrossLanguageTest(unittest.TestCase):
    """One envelope, two implementations. A drift in the key derivation, the
    associated data or the byte layout shows up here rather than in production,
    where it would look like an enclave refusing a prompt."""

    def module(self, script):
        return script % json.dumps(str(NODE_MODULE))

    def test_node_opens_what_this_sdk_sealed(self):
        aad = request_aad(algo=X25519_SUITE, model="demo-model", field="messages.0.content",
                          nonce=VECTOR_NONCE, ts=VECTOR_TS)
        for plaintext in ("the prompt", "quelle heure est-il à Paris", "\U0001f680 run it", ""):
            envelope = seal_field(bytes.fromhex(SERVICE_PUBLIC), plaintext, aad)
            opened = node(self.module(OPEN_SCRIPT),
                          {"seed": SERVICE_SEED.hex(), "envelope": envelope, "aad": aad.decode()})
            self.assertEqual(opened, plaintext)

    def test_this_sdk_opens_what_node_sealed(self):
        aad = request_aad(algo=X25519_SUITE, model="demo-model", field="messages.0.content",
                          nonce=VECTOR_NONCE, ts=VECTOR_TS)
        sealed = json.loads(node(self.module(SEAL_SCRIPT), {
            "seed": SERVICE_SEED.hex(),
            "recipient": SERVICE_PUBLIC,
            "plaintext": "quelle heure est-il à Paris",
            "aad": aad.decode(),
        }))
        self.assertEqual(open_field(SERVICE_PRIVATE, sealed["envelope"], aad),
                         "quelle heure est-il à Paris")

    def test_a_whole_chat_request_sealed_by_node_opens_here(self):
        sealed = json.loads(node(self.module(ENCRYPT_SCRIPT), {"body": BODY, "keyset": KEYSET}))
        self.assertEqual(sealed["headers"]["X-E2EE-Version"], "2")
        self.assertEqual(sealed["restored"], json.dumps(BODY, separators=(",", ":")))
        wire = json.loads(sealed["bytes"])
        for index, message in enumerate(wire["messages"]):
            aad = request_aad(algo=X25519_SUITE, model=BODY["model"], field=f"messages.{index}.content",
                              nonce=sealed["headers"]["X-E2EE-Nonce"],
                              ts=int(sealed["headers"]["X-E2EE-Timestamp"]))
            self.assertEqual(open_field(SERVICE_PRIVATE, message["content"], aad),
                             BODY["messages"][index]["content"])

    def test_node_opens_a_whole_chat_request_sealed_here(self):
        sealed = encrypt_chat_request(BODY, KEYSET, now=VECTOR_TS, rand=fixed_random(21))
        wire = json.loads(sealed.payload.decode())
        for index, message in enumerate(wire["messages"]):
            aad = request_aad(algo=X25519_SUITE, model=BODY["model"], field=f"messages.{index}.content",
                              nonce=sealed.headers["X-E2EE-Nonce"], ts=VECTOR_TS)
            opened = node(self.module(OPEN_SCRIPT), {"seed": SERVICE_SEED.hex(),
                                                     "envelope": message["content"], "aad": aad.decode()})
            self.assertEqual(opened, BODY["messages"][index]["content"])

    def test_an_answer_node_sealed_to_this_client_decrypts(self):
        sealed = encrypt_chat_request(BODY, KEYSET, now=VECTOR_TS, rand=fixed_random(31))
        aad = response_aad(algo=X25519_SUITE, model=BODY["model"], chat_id="chatcmpl-9",
                           field="choices.0.message.content",
                           nonce=sealed.headers["X-E2EE-Nonce"], ts=VECTOR_TS)
        answer = json.loads(node(self.module(SEAL_SCRIPT), {
            "seed": SERVICE_SEED.hex(),
            "recipient": sealed.client_key.public_key,
            "plaintext": "about 4,200 USDG",
            "aad": aad.decode(),
        }))
        wire = json.dumps({"id": "chatcmpl-9",
                           "choices": [{"index": 0, "message": {"content": answer["envelope"]}}]})
        restored = decrypt_response(wire.encode(), sealed.client_key)
        self.assertEqual(restored["choices"][0]["message"]["content"], "about 4,200 USDG")


class ClientKeyTest(unittest.TestCase):
    def test_a_client_key_carries_the_context_its_answer_is_bound_to(self):
        sealed = encrypt_chat_request(BODY, KEYSET, now=VECTOR_TS, rand=fixed_random(13))
        self.assertIsInstance(sealed.client_key, ClientKey)
        self.assertEqual(sealed.client_key.algo, X25519_SUITE)
        self.assertEqual(sealed.client_key.key_id, "e2ee-1")
        self.assertEqual(sealed.client_key.model, "demo-model")
        self.assertEqual(sealed.client_key.ts, VECTOR_TS)
        self.assertEqual(sealed.client_key.nonce, sealed.headers["X-E2EE-Nonce"])


if __name__ == "__main__":
    unittest.main()
