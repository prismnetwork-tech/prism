"""End-to-end encryption for confidential inference.

An agent puts this around a chat request so the relay carrying it holds
ciphertext only, and the enclave holding the attested key is the one thing that
can read the prompt.

The wire contract is the X25519 suite of the ACI E2EE v2 protocol, the same one
``sdk/e2ee.mjs`` speaks. Each protected field value is
``hex(ephemeral_public_key(32) || gcm_nonce(12) || ciphertext || tag(16))``; the
AES-256-GCM key is HKDF-SHA256 over the X25519 shared secret with an empty salt
and the suite's info string; the AEAD's associated data is the canonical JSON of
a purpose-tagged object naming the field path, the model, the request nonce and
the timestamp, so a ciphertext cannot be moved to another field, request or
model.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

E2EE_VERSION = "2"
X25519_SUITE = "x25519-aes-256-gcm-hkdf-sha256"

_HKDF_INFO = b"aci.e2ee.v2.x25519"
_REQUEST_PURPOSE = "aci.e2ee.request.v2"
_RESPONSE_PURPOSE = "aci.e2ee.response.v2"
_RESPONSE_FIELDS = ("content", "reasoning", "reasoning_content")

Random = Callable[[int], bytes]


class E2eeError(Exception):
    pass


def jcs_bytes(value: Any) -> bytes:
    """RFC 8785 canonical JSON under the ACI artifact constraints (ASCII member
    names, integer numbers): compact, member names sorted."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def select_e2ee_key(keyset: dict) -> dict:
    """The x25519 entry of a quote-bound key set. The service publishes a
    secp256k1 suite too; this client speaks the x25519 one, which is the suite
    the spec recommends and the only one it implements."""
    keys = (keyset or {}).get("e2ee_public_keys")
    for entry in keys if isinstance(keys, list) else []:
        if isinstance(entry, dict) and entry.get("algo") == X25519_SUITE:
            return entry
    raise E2eeError(f"the attested key set publishes no {X25519_SUITE} key")


def public_key_from_raw(raw) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(bytes(raw))


def private_key_from_seed(seed) -> X25519PrivateKey:
    if len(seed) != 32:
        raise E2eeError("an x25519 private key is 32 bytes")
    return X25519PrivateKey.from_private_bytes(bytes(seed))


def raw_public_key(key: X25519PublicKey) -> bytes:
    return key.public_bytes_raw()


def request_aad(*, algo: str, model: str, field: str, nonce: str, ts: int) -> bytes:
    """The associated data for one request field (§6). Byte-exact: the test
    vectors pin this string."""
    return jcs_bytes({"purpose": _REQUEST_PURPOSE, "algo": algo, "model": model, "field": field,
                      "nonce": nonce, "ts": ts})


def response_aad(*, algo: str, model: str, chat_id: str, field: str, nonce: str, ts: int) -> bytes:
    """The response variant, which additionally binds the response id."""
    return jcs_bytes({"purpose": _RESPONSE_PURPOSE, "algo": algo, "model": model, "id": chat_id,
                      "field": field, "nonce": nonce, "ts": ts})


def _aead_key(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=_HKDF_INFO).derive(shared)


def seal_field(recipient_raw, plaintext: str, aad: bytes, rand: Random = os.urandom) -> str:
    """One field envelope, encrypted to ``recipient_raw`` under a fresh
    ephemeral key."""
    ephemeral = private_key_from_seed(rand(32))
    key = _aead_key(ephemeral.exchange(public_key_from_raw(recipient_raw)))
    nonce = rand(12)
    body = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return (raw_public_key(ephemeral.public_key()) + nonce + body).hex()


def open_field(private_key: X25519PrivateKey, envelope, aad: bytes) -> str:
    """The inverse. A tampered envelope, associated data or key fails the AEAD
    tag and raises."""
    text = envelope.decode("ascii") if isinstance(envelope, (bytes, bytearray)) else str(envelope)
    try:
        blob = bytes.fromhex(text[2:] if text.startswith("0x") else text)
    except ValueError as e:
        raise E2eeError("e2ee envelope is not hex") from e
    if len(blob) < 32 + 12 + 16:
        raise E2eeError("e2ee envelope is too short to hold a field")
    key = _aead_key(private_key.exchange(public_key_from_raw(blob[:32])))
    try:
        return AESGCM(key).decrypt(blob[32:44], blob[44:], aad).decode("utf-8")
    except Exception as e:
        raise E2eeError("e2ee field did not authenticate: wrong key, wrong context, "
                        "or altered ciphertext") from e


def restore_content(plaintext):
    """§5 restoration: a decrypted whole-content plaintext that parses as a JSON
    array is restored as structured content, and anything else stays the string
    it was. The receipt covers what the workload restored, so a client that
    reproduces the hash has to apply the same rule to its own copy."""
    if not isinstance(plaintext, str) or plaintext.lstrip()[:1] != "[":
        return plaintext
    try:
        value = json.loads(plaintext)
    except ValueError:
        return plaintext
    return value if isinstance(value, list) else plaintext


@dataclass
class ClientKey:
    """The static key one request's answer is encrypted to, and the context that
    answer has to be bound to."""

    private_key: X25519PrivateKey
    public_key: str
    algo: str
    key_id: str | None
    model: str
    nonce: str
    ts: int


@dataclass
class SealedRequest:
    payload: bytes
    headers: dict
    restored: bytes | None = None
    client_key: ClientKey | None = None


def encrypt_chat_request(body: dict, keyset: dict, now: int | None = None,
                         rand: Random = os.urandom) -> SealedRequest:
    """Encrypt every message content of a chat-completions body to the attested
    service key.

    Returns the bytes to send, the five headers that must travel with them, the
    client key the answer is encrypted to, and the compact restored-plaintext
    bytes the receipt's ``request.received`` hash covers.

    ``now`` and ``rand`` are injectable so a test can pin the whole envelope.
    """
    if not isinstance(body.get("model"), str):
        raise E2eeError("an e2ee request needs a top-level model string")
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise E2eeError("an e2ee chat request needs a messages array")

    service_key = select_e2ee_key(keyset)
    published = str(service_key.get("public_key", ""))
    try:
        service_raw = bytes.fromhex(published[2:] if published.startswith("0x") else published)
    except ValueError as e:
        raise E2eeError("the attested x25519 key is not hex") from e
    if len(service_raw) != 32:
        raise E2eeError("the attested x25519 key is not 32 bytes")

    client_private = private_key_from_seed(rand(32))
    client_public = raw_public_key(client_private.public_key()).hex()
    nonce = rand(32).hex()
    ts = int(now) if now is not None else int(time.time())

    # The plaintext copy is what the workload hashes into the receipt after it
    # restores the fields (§8), so it is built alongside the encrypted one from
    # the same object and in the same member order.
    restored = dict(body)
    sealed = dict(body)
    restored["messages"] = []
    sealed["messages"] = []
    for index, message in enumerate(messages):
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            # Any plaintext string at a protected path fails the request
            # upstream, so a body this client cannot fully protect is refused
            # here instead.
            raise E2eeError(f"messages.{index}.content must be a string to be encrypted")
        field = f"messages.{index}.content"
        aad = request_aad(algo=service_key["algo"], model=body["model"], field=field, nonce=nonce, ts=ts)
        restored["messages"].append({**message, "content": restore_content(content)})
        sealed["messages"].append({**message, "content": seal_field(service_raw, content, aad, rand)})

    return SealedRequest(
        payload=_compact(sealed),
        restored=_compact(restored),
        headers={
            "X-E2EE-Version": E2EE_VERSION,
            "X-Client-Pub-Key": client_public,
            "X-Model-Pub-Key": service_key["public_key"],
            "X-E2EE-Nonce": nonce,
            "X-E2EE-Timestamp": str(ts),
        },
        client_key=ClientKey(
            private_key=client_private,
            public_key=client_public,
            algo=service_key["algo"],
            key_id=service_key.get("key_id"),
            model=body["model"],
            nonce=nonce,
            ts=ts,
        ),
    )


def decrypt_response(body_bytes, client_key: ClientKey, model: str | None = None) -> dict:
    """Decrypt a buffered chat-completions response. Every generated content
    field the service encrypted is authenticated against the associated data
    naming its position, so a field lifted from another response does not
    open."""
    text = body_bytes if isinstance(body_bytes, str) else bytes(body_bytes).decode("utf-8")
    body = json.loads(text)
    chat_id = body["id"] if isinstance(body.get("id"), str) else ""
    choices = body.get("choices") if isinstance(body.get("choices"), list) else []
    for position, choice in enumerate(choices):
        index = choice.get("index") if isinstance(choice, dict) else None
        if not isinstance(index, int) or isinstance(index, bool):
            index = position
        message = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(message, dict):
            continue
        for name in _RESPONSE_FIELDS:
            if not isinstance(message.get(name), str) or message[name] == "":
                continue
            aad = response_aad(
                algo=client_key.algo,
                model=model if model is not None else client_key.model,
                chat_id=chat_id,
                field=f"choices.{index}.message.{name}",
                nonce=client_key.nonce,
                ts=client_key.ts,
            )
            message[name] = open_field(client_key.private_key, message[name], aad)
    return body


def _compact(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
