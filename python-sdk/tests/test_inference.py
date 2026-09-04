"""Paid inference: what leaves the wallet, what leaves the process, and what a
confidential call refuses to do.

Every HTTP call is answered by a stub gateway that speaks the shapes the real
one serves, so these exercise the client's own decisions: when it pays, when it
reuses a payment it has already made, and what it establishes about an enclave
before a prompt is allowed to leave.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import struct
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qsl

from eth_account import Account
from eth_account.messages import encode_defunct
from hexbytes import HexBytes
from requests.structures import CaseInsensitiveDict
from web3 import Web3

from prismnetwork import DEFAULT_IMAGE, PrismAgent, PrismError, bound_message, hash_request
from prismnetwork._e2ee import (
    X25519_SUITE,
    jcs_bytes,
    open_field,
    private_key_from_seed,
    raw_public_key,
    request_aad,
    response_aad,
    seal_field,
)
from prismnetwork._inference import (
    DSTACK_RUNTIME_EVENT,
    EXPECTED_WORKLOAD,
    ConfidentialError,
    PaymentError,
    TdReport,
    VerifiedQuote,
    appraise_workload,
    compute_session_id,
    gate_gpu_binding,
    gate_nras_claims,
    hash_body,
    keyset_digest,
    render_checks,
    replay_rtmr3,
    report_data,
    same_td,
    verdict_of,
    verify_compose_measurement,
    verify_confidential,
    verify_quote,
    verify_report_binding,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MODEL = "phala/gemma-4-26b-a4b-uncensored"
OPEN_MODEL = "llama3.2:3b"
PAY_TO = "0x1111111111111111111111111111111111111111"
PRICE = "3560"
ESCROW = "0xfD4228eEEfC49e4b76A0CD40af9fdd546220B2FD"
KEY = "0x" + "22" * 32
TX = "0x" + "ab" * 32
BASE = "https://api.test/inference"

SERVICE_SEED = bytes([3]) * 32
SERVICE_PRIVATE = private_key_from_seed(SERVICE_SEED)
SERVICE_PUBLIC = raw_public_key(SERVICE_PRIVATE.public_key()).hex()

# The workload this file's stub gateway claims to be, and the pin the client is
# given to hold it against.
TEST_COMMIT = "a1" * 20
TEST_WORKLOAD = {
    "launcher_image": f"ghcr.io/example/launcher@sha256:{'5c' * 32}",
    "repo_url": "https://example.test/gateway.git",
    "os_image_hash": "3e" * 32,
    "repo_commit": None,
}

FIXTURE = Path(__file__).resolve().parents[2] / "sdk" / "fixtures" / "aci-attestation.json"

# The key set has to hash to the same digest every time this gateway is asked,
# because a client that sealed a prompt to one digest and verifies against
# another is looking at a different key set, which is exactly what the check is
# for. So the clock is read once.
NOT_AFTER = int(time.time()) + 3600
RECEIPT_KEY = Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32)

_MR_TD = slice(184, 232)
_RTMR3 = slice(520, 568)
_REPORT_DATA = slice(568, 632)


def offset_verifier(raw: bytes, now: int) -> VerifiedQuote:
    """A stand-in for the DCAP verifier: it reads the TD report out of a v4
    quote at the offsets ``dcap-qvl`` parses, and skips the one thing it cannot
    do offline, which is checking the signature to Intel's root."""
    return VerifiedQuote(
        True,
        status="UpToDate",
        report=TdReport(mr_td=raw[_MR_TD], rt_mr3=raw[_RTMR3], report_data=raw[_REPORT_DATA]),
    )


def refusing_verifier(raw: bytes, now: int) -> VerifiedQuote:
    return VerifiedQuote(False, detail="quote did not verify: signature over the report is not Intel's")


def dstack_event(event: str, payload_hex: str) -> dict:
    body = (struct.pack("<I", DSTACK_RUNTIME_EVENT) + f":{event}:".encode()
            + bytes.fromhex(payload_hex))
    return {"imr": 3, "event_type": DSTACK_RUNTIME_EVENT, "digest": hashlib.sha384(body).hexdigest(),
            "event": event, "event_payload": payload_hex}


def compose_file(launcher: str = TEST_WORKLOAD["launcher_image"],
                 repo: str = TEST_WORKLOAD["repo_url"], commit: str = TEST_COMMIT) -> str:
    return json.dumps({
        "docker_compose_file":
            f"services:\n  launcher:\n    image: {launcher}\n    environment:\n"
            f"      REPO_URL={repo}\n      REPO_COMMIT={commit}\n",
    })


def attestation_report(nonce: str, compose: str | None = None, rtmr3: bytes | None = None,
                       e2ee_keys=None) -> dict:
    """A report whose key set carries the x25519 key this file holds, with a
    boot log that measures ``compose``. The quote is shaped only where a
    verifier reads it, so nothing here verifies to Intel's root.

    ``e2ee_keys`` replaces the published encryption keys before the digest is
    taken, so a key set a client cannot seal to is still one whose quote binds
    it and every check ahead of the seal still holds."""
    compose = compose_file() if compose is None else compose
    keyset = {
        "subject": None,
        "not_after": NOT_AFTER,
        "receipt_signing_keys": [{"key_id": "receipt-1", "algo": "ed25519",
                                  "public_key": RECEIPT_KEY.public_key().public_bytes_raw().hex()}],
        "e2ee_public_keys": [{"key_id": "e2ee-1", "algo": X25519_SUITE, "public_key": SERVICE_PUBLIC}]
        if e2ee_keys is None else e2ee_keys,
    }
    events = [
        dstack_event("compose-hash", hashlib.sha256(compose.encode()).hexdigest()),
        dstack_event("os-image-hash", TEST_WORKLOAD["os_image_hash"]),
        dstack_event("system-ready", ""),
    ]
    digest = keyset_digest(keyset)
    quote = bytearray(632)
    quote[_RTMR3] = rtmr3 if rtmr3 is not None else replay_rtmr3(events)
    quote[_MR_TD] = bytes([0x11]) * 48
    quote[568:600] = bytes.fromhex(report_data(digest, nonce))
    return {
        "api_version": "aci/1",
        "workload_keyset_digest": digest,
        "attestation": {
            "tee_type": "tdx",
            "workload_keyset": keyset,
            "report_data": report_data(digest, nonce),
            "source_provenance": {"repo_url": TEST_WORKLOAD["repo_url"], "repo_commit": TEST_COMMIT},
            "evidence": {"quote": bytes(quote).hex(), "event_log": json.dumps(events),
                         "app_compose": compose},
        },
    }


def mangled_report(mangle):
    """A report whose ``attestation`` member the endpoint shaped however it
    liked. Nothing under it is this client's to trust, so every shape has to
    come back as a refusal rather than as whatever the parse hit first."""
    def report(nonce: str) -> dict:
        body = attestation_report(nonce)
        body["attestation"] = mangle(body["attestation"])
        return body

    return report


HOSTILE_ATTESTATIONS = {
    "an attestation that is a string": lambda a: "nope",
    "evidence that is a string": lambda a: {**a, "evidence": "nope"},
    "an event log that is a number": lambda a: {**a, "evidence": {**a["evidence"], "event_log": "4"}},
    "an event log of nulls": lambda a: {**a, "evidence": {**a["evidence"], "event_log": "[null]"}},
    "an event log that is an object": lambda a: {**a, "evidence": {**a["evidence"], "event_log": "{}"}},
}


class Answer:
    """The parts of a ``requests`` response this SDK reads."""

    def __init__(self, status: int, body=b"", headers=None):
        self.status_code = status
        self.content = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.headers = CaseInsensitiveDict(headers or {})

    @property
    def ok(self):
        return 200 <= self.status_code < 400

    def json(self):
        return json.loads(self.content.decode())


class Gateway:
    """A gateway that quotes, takes one payment and answers, recording what it
    was sent so a test can hold the client to the bytes it claims to have
    sent."""

    def __init__(self, *, price=PRICE, confidential=True, attestation=None, answer=None,
                 gpu_evidence=None, e2ee_applied=None):
        self.price = price
        self.confidential = confidential
        self.attestation = attestation
        self.answer = answer
        self.gpu_evidence = gpu_evidence
        self.e2ee_applied = e2ee_applied
        self.calls = []
        self.paid = None
        self.paid_headers = None
        self.served = None
        self.quotes = 0
        self.receipts = 0

    def __call__(self, method, url, data=None, json=None, headers=None, timeout=None):
        path = url.split("?", 1)[0].removeprefix(BASE)
        query = dict(parse_qsl(url.split("?", 1)[1])) if "?" in url else {}
        self.calls.append({"method": method, "path": path, "query": query, "data": data,
                           "json": json, "headers": headers or {}})
        route = getattr(self, f"_{path.strip('/').replace('/', '_').replace('-', '_')}", None)
        if route is None and path.startswith("/v1/receipts/"):
            self.receipts += 1
            return Answer(200, self._signed_receipt())
        if route is None:
            raise AssertionError(f"unexpected request {method} {url}")
        return route(data=data, body=json, headers=headers or {}, query=query)

    def _v1_models(self, **_):
        card = {
            "endpoint": "/inference/v1/chat/completions",
            "max_tokens": 1024,
            "max_body_bytes": 32 * 1024,
            "models": {MODEL: {"base_micros": 1000, "per_token_micros": 5, "e2ee": True}},
        }
        return Answer(200, {
            "models": [OPEN_MODEL],
            "pay_to": PAY_TO,
            "price_micros": "6072",
            **({"confidential": card} if self.confidential else {}),
        })

    def _v1_attestation(self, query=None, **_):
        if self.attestation is None:
            raise AssertionError("this gateway serves no attestation")
        return Answer(200, self.attestation(query["nonce"]))

    def _v1_gpu_evidence(self, query=None, **_):
        if self.gpu_evidence is None:
            # A pre-send call never asks; verification does, and an endpoint
            # publishing none is a skip rather than a failure.
            return Answer(404, {"error": "not_found"})
        return self.gpu_evidence(len([c for c in self.calls if c["path"] == "/v1/gpu-evidence"]), query)

    def _v1_inference(self, data=None, body=None, headers=None, **_):
        if not headers.get("x-payment"):
            self.quotes += 1
            return self._quote()
        self.paid, self.paid_headers = data, headers
        return Answer(200, {"model": OPEN_MODEL, "response": "Metered GPU compute bills by the second.",
                            "usage": {"prompt_tokens": 12, "completion_tokens": 9, "duration_ms": 640},
                            "lease_id": 1047},
                      {"x-receipt-id": "rcpt-open-1"})

    def _v1_chat_completions(self, data=None, body=None, headers=None, **_):
        if not headers.get("x-payment"):
            self.quotes += 1
            return self._quote()
        self.paid, self.paid_headers = data, headers
        answer = self.answer(data, headers) if self.answer else Answer(
            200, {"id": "chatcmpl-1",
                  "choices": [{"index": 0, "message": {"role": "assistant",
                                                       "content": "about 4,200 USDG"}}],
                  "usage": {"prompt_tokens": 9, "completion_tokens": 6}},
            {"x-receipt-id": "rcpt-1"})
        self.served = {"request": self._restored(data, headers), "response": answer.content}
        return answer

    def _restored(self, data, headers) -> bytes:
        """What the workload hashes into the receipt: the request as it reads it,
        which under encryption is the compact plaintext it restored (§7.4)."""
        if not headers.get("X-E2EE-Nonce"):
            return data
        wire = json.loads(data.decode())
        opened = []
        for index, message in enumerate(wire["messages"]):
            aad = request_aad(algo=X25519_SUITE, model=wire["model"],
                              field=f"messages.{index}.content",
                              nonce=headers["X-E2EE-Nonce"], ts=int(headers["X-E2EE-Timestamp"]))
            opened.append({**message, "content": open_field(SERVICE_PRIVATE, message["content"], aad)})
        return json.dumps({**wire, "messages": opened}, separators=(",", ":")).encode()

    def _signed_receipt(self) -> dict:
        served = self.served or {"request": b"", "response": b""}
        document = {
            "api_version": "aci/1",
            "receipt_id": "rcpt-1",
            "model": MODEL,
            "served_at": int(time.time()),
            "key_id": "receipt-1",
            "workload_keyset_digest": keyset_digest(
                attestation_report("0" * 64)["attestation"]["workload_keyset"]),
            "event_log": [
                {"type": "request.received", "body_hash": hash_body(served["request"])},
                {"type": "response.returned", "body_hash": hash_body(served["response"])},
            ],
        }
        return {**document, "signature": RECEIPT_KEY.sign(jcs_bytes(document)).hex()}

    def _quote(self):
        return Answer(402, {
            "x402Version": 2,
            "accepts": [{"scheme": "exact", "network": "eip155:4663", "asset": "0x5fc5",
                         "payTo": PAY_TO, "amount": self.price}],
            "state": "warm",
            "quote": {"model": MODEL, "output_cap": 512, "price_micros": self.price},
        }, {})


def sealed_answer(data, headers):
    """What the enclave sends back when the request arrived encrypted: the same
    envelope construction, bound to this call's nonce and the client's key."""
    wire = json.loads(data.decode())
    nonce, ts = headers["X-E2EE-Nonce"], int(headers["X-E2EE-Timestamp"])
    aad = response_aad(algo=X25519_SUITE, model=wire["model"], chat_id="chatcmpl-1",
                       field="choices.0.message.content", nonce=nonce, ts=ts)
    envelope = seal_field(bytes.fromhex(headers["X-Client-Pub-Key"]), "about 4,200 USDG", aad)
    return Answer(200, {"id": "chatcmpl-1",
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": envelope}}],
                        "usage": {"prompt_tokens": 9, "completion_tokens": 6}},
                  {"x-receipt-id": "rcpt-1", "x-e2ee-applied": "true"})


class AgentCase(unittest.TestCase):
    def setUp(self):
        self.agent = PrismAgent(KEY, ESCROW)
        self.transfers = []
        self.agent._transfer_usdg = self._transfer

    def _transfer(self, to, micros):
        self.transfers.append({"to": to, "micros": int(micros)})
        return TX

    def serving(self, gateway):
        return patch("prismnetwork._inference.requests.request", gateway)


class OpenInferenceTest(AgentCase):
    def test_a_generation_quotes_pays_once_and_returns_what_it_bought(self):
        gateway = Gateway()
        with self.serving(gateway):
            run = self.agent.infer(prompt="explain metered GPU compute", max_tokens=64, endpoint=BASE)

        self.assertEqual(run["text"], "Metered GPU compute bills by the second.")
        self.assertEqual(run["model"], OPEN_MODEL)
        self.assertEqual(run["usage"]["completion_tokens"], 9)
        self.assertEqual(run["lease_id"], 1047)
        self.assertEqual(run["receipt_id"], "rcpt-open-1")
        self.assertEqual(run["price_micros"], PRICE)
        self.assertEqual(run["price_usdg"], "0.003560")
        self.assertEqual(run["tx"], TX)
        self.assertEqual(self.transfers, [{"to": PAY_TO, "micros": int(PRICE)}])
        self.assertEqual(json.loads(gateway.paid.decode()),
                         {"model": OPEN_MODEL, "prompt": "explain metered GPU compute",
                          "options": {"num_predict": 64}})

    def test_the_payment_header_binds_the_bytes_that_were_sent(self):
        gateway = Gateway()
        with self.serving(gateway):
            self.agent.infer(prompt="explain metered GPU compute", endpoint=BASE)

        envelope = json.loads(base64.b64decode(gateway.paid_headers["x-payment"]))
        self.assertEqual(envelope["txHash"], TX)
        signer = Account.recover_message(
            encode_defunct(text=bound_message(TX, hash_request(gateway.paid))),
            signature=envelope["signature"],
        )
        self.assertEqual(signer, self.agent.address)
        # The replay this closes: the same header in front of another prompt.
        other = Account.recover_message(
            encode_defunct(text=bound_message(TX, hash_request(b'{"prompt":"something else"}'))),
            signature=envelope["signature"],
        )
        self.assertNotEqual(other, self.agent.address)

    def test_a_price_above_the_cap_is_refused_before_any_money_moves(self):
        gateway = Gateway(price="500000")
        with self.serving(gateway), self.assertRaises(PaymentError) as caught:
            self.agent.infer(prompt="hi", max_usdg=0.05, endpoint=BASE)
        self.assertEqual(caught.exception.code, "cost_exceeds_max")
        self.assertEqual(self.transfers, [])

    def test_a_model_the_endpoint_does_not_offer_is_refused(self):
        with self.serving(Gateway()), self.assertRaises(PrismError) as caught:
            self.agent.infer(prompt="hi", model="gpt-4", endpoint=BASE)
        self.assertEqual(caught.exception.code, "unknown_model")
        self.assertEqual(self.transfers, [])

    def test_a_chat_list_is_flattened_for_an_endpoint_that_takes_one_prompt(self):
        gateway = Gateway()
        with self.serving(gateway):
            self.agent.infer(messages=[{"role": "system", "content": "be terse"},
                                       {"role": "user", "content": "why"}], endpoint=BASE)
        self.assertEqual(json.loads(gateway.paid.decode())["prompt"], "system: be terse\n\nuser: why")


class PaidCallTest(AgentCase):
    def pay(self, gateway, **kwargs):
        return self.agent.pay_and_post(base=BASE, path="/v1/chat/completions", price=1000,
                                       pay_to=PAY_TO, retry_delay=0, **kwargs)

    def test_an_unavailable_upstream_is_retried_with_the_payment_already_made(self):
        answers = [Answer(503, {"error": "upstream_unavailable", "retry": "the payment was not consumed"}),
                   Answer(200, b'{"ok":true}')]
        calls = []

        def gateway(method, url, **kwargs):
            calls.append(kwargs)
            return answers[len(calls) - 1]

        with self.serving(gateway):
            served = self.pay(gateway, body={"model": MODEL})
        self.assertEqual(served.status, 200)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(self.transfers), 1, "the same payment carried both attempts")

    def test_a_spend_cap_is_a_refusal_not_something_to_retry_for_ten_minutes(self):
        calls = []

        def gateway(method, url, **kwargs):
            calls.append(kwargs)
            return Answer(503, {"error": "spend_cap_reached",
                                "detail": "the confidential relay has reached its daily upstream spend cap",
                                "retry": "nothing was charged; the cap resets at 00:00 UTC"},
                          {"retry-after": "3600"})

        started = time.time()
        with self.serving(gateway), self.assertRaises(PaymentError) as caught:
            self.pay(gateway, body={"model": MODEL})
        self.assertEqual(caught.exception.code, "spend_cap_reached")
        self.assertIn("the cap resets at 00:00 UTC", caught.exception.body["cause"])
        self.assertEqual(len(calls), 1)
        self.assertLess(time.time() - started, 5)

    def test_a_kept_payment_belongs_to_the_request_it_paid_for(self):
        def gateway(method, url, **kwargs):
            return Answer(400, {"error": "upstream_rejected", "detail": "bad request"})

        with self.serving(gateway):
            def pay(prompt):
                return self.pay(gateway, body={"model": MODEL,
                                               "messages": [{"role": "user", "content": prompt}]})

            with self.assertRaises(PaymentError) as first:
                pay("first prompt")
            self.assertEqual(first.exception.code, "upstream_rejected")
            self.assertEqual(len(self.transfers), 1)

            # The signed header is exposed, because the transfer has settled and
            # this process is the only thing holding what redeems it.
            with self.assertRaises(PaymentError) as again:
                pay("first prompt")
            self.assertIsInstance(again.exception.body["payment_header"], str)
            self.assertEqual(again.exception.broadcast, TX)
            self.assertEqual(len(self.transfers), 1, "the same request reuses the payment it made")

            with self.assertRaises(PaymentError):
                pay("a different prompt")
            self.assertEqual(len(self.transfers), 2, "a different request pays for itself")

    def test_a_payment_the_endpoint_has_consumed_stops_being_retried_with(self):
        calls = []

        def gateway(method, url, **kwargs):
            calls.append(kwargs)
            return Answer(402, {"error": "payment_reused"})

        with self.serving(gateway):
            for _ in range(2):
                with self.assertRaises(PaymentError) as caught:
                    self.pay(gateway, body={"model": MODEL})
                self.assertEqual(caught.exception.code, "payment_reused")
        self.assertEqual(len(self.transfers), 2, "a consumed payment is not offered again")
        self.assertEqual(len(calls), 2)

    def test_a_replayed_answer_is_not_this_calls_answer(self):
        def gateway(method, url, **kwargs):
            return Answer(200, b'{"id":"chatcmpl-earlier"}', {"x-prism-replayed": "true"})

        with self.serving(gateway), self.assertRaises(PaymentError) as caught:
            self.pay(gateway, body={"model": MODEL})
        self.assertEqual(caught.exception.code, "payment_replayed")

    def test_an_encrypted_request_is_sealed_fresh_for_every_attempt(self):
        from prismnetwork._e2ee import encrypt_chat_request

        keyset = {"e2ee_public_keys": [{"key_id": "e2ee-1", "algo": X25519_SUITE,
                                        "public_key": SERVICE_PUBLIC}]}
        body = {"model": MODEL, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16}
        sent = []

        def gateway(method, url, data=None, headers=None, **kwargs):
            sent.append({"data": data, "nonce": headers["X-E2EE-Nonce"]})
            return Answer(503, {"error": "upstream_unavailable"}) if len(sent) < 3 \
                else Answer(200, b'{"ok":true}')

        with self.serving(gateway):
            served = self.pay(gateway, seal=lambda: encrypt_chat_request(body, keyset),
                              fingerprint=json.dumps(body, separators=(",", ":")).encode())
        self.assertEqual(served.status, 200)
        self.assertEqual(len(sent), 3)
        # A frozen timestamp cannot survive a retry budget longer than the
        # service's five-minute acceptance window, so each attempt is its own
        # envelope.
        self.assertEqual(len({s["nonce"] for s in sent}), 3)
        self.assertNotEqual(sent[0]["data"], sent[1]["data"])
        self.assertEqual(len(self.transfers), 1)


class ConfidentialTest(AgentCase):
    def run_call(self, gateway, **kwargs):
        with self.serving(gateway):
            return self.agent.confidential_infer(
                prompt="what is my position worth", endpoint=BASE,
                expected_workload=TEST_WORKLOAD, quote_verifier=offset_verifier, **kwargs)

    def test_a_generation_with_encryption_off_pays_once_and_keeps_its_bytes(self):
        gateway = Gateway()
        run = self.run_call(gateway, e2ee=False)

        self.assertEqual(run["model"], MODEL)
        self.assertEqual(run["text"], "about 4,200 USDG")
        self.assertEqual(run["usage"]["completion_tokens"], 6)
        self.assertEqual(run["receipt_id"], "rcpt-1")
        self.assertEqual(run["price_micros"], PRICE)
        self.assertEqual(run["price_usdg"], "0.003560")
        self.assertFalse(run["e2ee"])
        self.assertFalse(run["attestation"]["verified"])
        self.assertEqual(self.transfers, [{"to": PAY_TO, "micros": int(PRICE)}])
        # The receipt is fetched while the workload still holds it, not left for
        # whenever the caller gets round to verifying.
        self.assertEqual(gateway.receipts, 1)
        self.assertEqual(run["receipt"]["receipt_id"], "rcpt-1")
        # What the receipt commits to is what went over the wire, byte for byte.
        self.assertEqual(run["bytes"]["request"], gateway.paid)
        self.assertEqual(json.loads(gateway.paid.decode()), {
            "model": MODEL,
            "messages": [{"role": "user", "content": "what is my position worth"}],
            "max_tokens": 512,
        })

    def test_an_encrypted_generation_sends_ciphertext_and_opens_the_answer(self):
        gateway = Gateway(attestation=attestation_report, answer=sealed_answer)
        run = self.run_call(gateway)

        self.assertEqual(run["text"], "about 4,200 USDG")
        self.assertTrue(run["e2ee"])
        self.assertNotIn("what is my position worth", gateway.paid.decode())
        aad = request_aad(algo=X25519_SUITE, model=MODEL, field="messages.0.content",
                          nonce=gateway.paid_headers["X-E2EE-Nonce"],
                          ts=int(gateway.paid_headers["X-E2EE-Timestamp"]))
        wire = json.loads(gateway.paid.decode())
        self.assertEqual(open_field(SERVICE_PRIVATE, wire["messages"][0]["content"], aad),
                         "what is my position worth")
        self.assertEqual(run["bytes"]["restored_request"],
                         json.dumps({"model": MODEL,
                                     "messages": [{"role": "user", "content": "what is my position worth"}],
                                     "max_tokens": 512}, separators=(",", ":")).encode())

        attestation = run["attestation"]
        self.assertTrue(attestation["verified"])
        self.assertEqual(attestation["quote_status"], "UpToDate")
        self.assertRegex(attestation["keyset_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(len(bytes.fromhex(attestation["rtmr3"])), 48)
        self.assertEqual(attestation["workload"], f"{TEST_WORKLOAD['repo_url']} @ {TEST_COMMIT}")

    def test_an_encrypted_generation_verifies_against_the_bytes_the_enclave_hashed(self):
        gateway = Gateway(attestation=attestation_report, answer=sealed_answer)
        run = self.run_call(gateway)
        with self.serving(gateway):
            checked = run["verify"](quote_verifier=offset_verifier)
        status = {c["id"]: c["status"] for c in checked["checks"]}
        detail = {c["id"]: c["detail"] for c in checked["checks"]}

        # The receipt covers the plaintext the enclave restored, not the
        # ciphertext the relay carried, and the client kept both.
        self.assertEqual(status["request-hash"], "pass", detail["request-hash"])
        self.assertEqual(status["response-hash"], "pass", detail["response-hash"])
        self.assertEqual(status["receipt-signature"], "pass", detail["receipt-signature"])
        self.assertEqual(status["receipt-keyset-binding"], "pass", detail["receipt-keyset-binding"])
        # And the transcript is this call's, not whatever the endpoint serves now.
        self.assertEqual(status["keyset-digest"], "pass", detail["keyset-digest"])
        self.assertEqual(checked["keyset_digest"], run["attestation"]["keyset_digest"])
        self.assertEqual(checked["verdict"], "failed",
                         "this gateway publishes no upstream verification and no GPU evidence")

    def test_a_generation_whose_answer_was_altered_afterwards_does_not_verify(self):
        gateway = Gateway(attestation=attestation_report, answer=sealed_answer)
        run = self.run_call(gateway)
        run["bytes"]["response"] = run["bytes"]["response"].replace(b"chatcmpl-1", b"chatcmpl-2")
        with self.serving(gateway):
            checked = run["verify"](quote_verifier=offset_verifier)
        failed = next(c for c in checked["checks"] if c["id"] == "response-hash")
        self.assertEqual(failed["status"], "fail")
        self.assertIn("the receipt records", failed["detail"])

    def test_an_enclave_running_code_the_client_does_not_pin_never_receives_the_prompt(self):
        gateway = Gateway(attestation=lambda nonce: attestation_report(
            nonce, compose_file(f"ghcr.io/attacker/launcher@sha256:{'7f' * 32}")))
        with self.assertRaises(ConfidentialError) as caught:
            self.run_call(gateway)
        self.assertEqual(caught.exception.code, "attestation_unverified")
        self.assertIn("runs no ghcr.io/example/launcher", caught.exception.body["cause"])
        # Nothing was sealed, nothing was priced and nothing was paid.
        self.assertEqual(self.transfers, [])
        self.assertIsNone(gateway.paid)
        self.assertEqual(gateway.quotes, 0)

    def test_a_compose_that_does_not_hash_to_its_measurement_never_receives_the_prompt(self):
        def rewritten(nonce):
            report = attestation_report(nonce)
            report["attestation"]["evidence"]["app_compose"] = compose_file().replace(
                "services:", "services: # rewritten")
            return report

        gateway = Gateway(attestation=rewritten)
        with self.assertRaises(ConfidentialError) as caught:
            self.run_call(gateway)
        self.assertEqual(caught.exception.code, "attestation_unverified")
        self.assertIn("sha256(app_compose)", caught.exception.body["cause"])
        self.assertEqual(self.transfers, [])

    def test_a_key_set_whose_quote_does_not_verify_never_receives_the_prompt(self):
        gateway = Gateway(attestation=attestation_report)
        with self.serving(gateway), self.assertRaises(ConfidentialError) as caught:
            self.agent.confidential_infer(prompt="sensitive", endpoint=BASE,
                                          expected_workload=TEST_WORKLOAD,
                                          quote_verifier=refusing_verifier)
        self.assertEqual(caught.exception.code, "quote_unverified")
        self.assertEqual(self.transfers, [])
        self.assertIsNone(gateway.paid)

    def test_a_boot_log_that_does_not_replay_to_the_quotes_rtmr3_never_receives_the_prompt(self):
        gateway = Gateway(attestation=lambda nonce: attestation_report(nonce, rtmr3=bytes([0x99]) * 48))
        with self.assertRaises(ConfidentialError) as caught:
            self.run_call(gateway)
        self.assertEqual(caught.exception.code, "attestation_unverified")
        self.assertIn("does not replay", caught.exception.body["cause"])
        self.assertEqual(self.transfers, [])

    def test_a_report_that_binds_another_nonce_never_receives_the_prompt(self):
        gateway = Gateway(attestation=lambda nonce: attestation_report("0" * 64))
        with self.assertRaises(ConfidentialError) as caught:
            self.run_call(gateway)
        self.assertEqual(caught.exception.code, "attestation_unverified")
        self.assertEqual(self.transfers, [])

    # Everything under `attestation` is the endpoint's to shape, and a caller
    # catching PrismError has to see the refusal this method documents rather
    # than whichever AttributeError or TypeError the parse happened to hit.
    def test_a_report_this_client_cannot_read_is_refused_before_the_prompt_is_sent(self):
        for name, mangle in HOSTILE_ATTESTATIONS.items():
            with self.subTest(name):
                self.transfers.clear()
                gateway = Gateway(attestation=mangled_report(mangle))
                with self.assertRaises(ConfidentialError) as caught:
                    self.run_call(gateway)
                self.assertEqual(caught.exception.code, "attestation_unverified")
                self.assertEqual(self.transfers, [])
                self.assertIsNone(gateway.paid)
                self.assertEqual(gateway.quotes, 0)

    # An attested key set that publishes nothing this client can encrypt to is
    # an enclave it cannot establish, whatever the hardware behind it proved.
    def test_a_key_set_with_no_key_to_encrypt_to_is_refused_before_the_prompt_is_sent(self):
        for keys in ([], [None], [{"key_id": "k", "algo": "secp256k1-aes-256-gcm"}]):
            with self.subTest(keys=keys):
                self.transfers.clear()
                gateway = Gateway(attestation=lambda nonce, k=keys: attestation_report(nonce, e2ee_keys=k))
                with self.assertRaises(ConfidentialError) as caught:
                    self.run_call(gateway)
                self.assertEqual(caught.exception.code, "e2ee_unavailable")
                self.assertIn(X25519_SUITE, caught.exception.body["cause"])
                self.assertEqual(self.transfers, [])
                self.assertIsNone(gateway.paid)
                self.assertEqual(gateway.quotes, 0)

    def test_an_endpoint_with_no_confidential_model_is_refused(self):
        gateway = Gateway(confidential=False)
        with self.assertRaises(PrismError) as caught:
            self.run_call(gateway, e2ee=False)
        self.assertEqual(caught.exception.code, "no_confidential_model")
        self.assertEqual(self.transfers, [])

    def test_a_price_above_the_cap_is_refused_before_any_money_moves(self):
        gateway = Gateway(price="500000")
        with self.assertRaises(PaymentError) as caught:
            self.run_call(gateway, e2ee=False, max_usdg=0.05)
        self.assertEqual(caught.exception.code, "cost_exceeds_max")
        self.assertEqual(self.transfers, [])

    def test_an_answer_the_enclave_left_unencrypted_is_reported_rather_than_read(self):
        def plaintext(data, headers):
            return Answer(200, {"id": "chatcmpl-1",
                                "choices": [{"index": 0, "message": {"content": "about 4,200 USDG"}}]},
                          {"x-receipt-id": "rcpt-1", "x-e2ee-applied": "false"})

        gateway = Gateway(attestation=attestation_report, answer=plaintext)
        with self.assertRaises(ConfidentialError) as caught:
            self.run_call(gateway)
        self.assertEqual(caught.exception.code, "e2ee_not_applied")
        self.assertIn("rcpt-1", caught.exception.body["hint"])
        self.assertEqual(caught.exception.broadcast, TX)
        self.assertEqual(caught.exception.body["payment_tx"], TX)


def open_tier(answer):
    """The open tier's endpoint: a rate card, a price for an unpaid request, and
    ``answer`` for the paid one."""
    def serve(method, url, data=None, json=None, headers=None, timeout=None):
        if url.endswith("/v1/models"):
            return Answer(200, {"models": [OPEN_MODEL], "pay_to": PAY_TO})
        if not (headers or {}).get("x-payment"):
            return Answer(402, {"accepts": [{"scheme": "exact", "network": "eip155:4663",
                                             "payTo": PAY_TO, "amount": PRICE}]})
        return answer

    return serve


class SettledPaymentTest(AgentCase):
    """A transfer that settled, and an answer that could not be read.

    A spend ledger reads one field to decide whether the wallet was charged, so
    a reader that raises without the hash hands back a reservation for money the
    chain has already moved, and nothing left in this process can find the
    transfer again.
    """

    def confidential(self, gateway):
        with self.serving(gateway):
            return self.agent.confidential_infer(prompt="what is my position worth",
                                                 endpoint=BASE, e2ee=False)

    def test_a_paid_answer_that_is_not_json_names_the_transfer_that_bought_it(self):
        gateway = Gateway(answer=lambda data, headers: Answer(
            200, b"<html>502 Bad Gateway</html>", {"x-receipt-id": "rcpt-1"}))
        with self.assertRaises(PaymentError) as caught:
            self.confidential(gateway)
        self.assertEqual(caught.exception.code, "malformed_answer")
        self.assertEqual(caught.exception.broadcast, TX)
        self.assertEqual(caught.exception.body["payment_tx"], TX)

    def test_the_open_tier_names_its_transfer_the_same_way(self):
        with self.serving(open_tier(Answer(200, b"not json"))), self.assertRaises(PaymentError) as caught:
            self.agent.infer(prompt="explain metered GPU compute", endpoint=BASE)
        self.assertEqual(caught.exception.code, "malformed_answer")
        self.assertEqual(caught.exception.broadcast, TX)
        self.assertEqual(caught.exception.body["payment_tx"], TX)

    def test_anything_that_breaks_after_the_transfer_settled_carries_the_hash_out(self):
        self.agent._receipt = lambda *a: (_ for _ in ()).throw(RuntimeError("receipt store is down"))
        with self.assertRaises(PaymentError) as caught:
            self.confidential(Gateway())
        self.assertEqual(caught.exception.code, "answer_unreadable")
        self.assertEqual(caught.exception.broadcast, TX)
        self.assertEqual(caught.exception.body["payment_tx"], TX)
        self.assertIn("receipt store is down", caught.exception.body["cause"])

    def test_a_payment_stays_redeemable_until_the_caller_holds_the_answer(self):
        self.agent._receipt = lambda *a: (_ for _ in ()).throw(RuntimeError("receipt store is down"))
        with self.assertRaises(PaymentError):
            self.confidential(Gateway())
        self.assertEqual(len(self.agent._payments()), 1,
                         "a paid-for generation was dropped, so the retry pays for it again")

        # The same request, this time read: one transfer answered both, and the
        # payment goes when the caller has what it bought.
        del self.agent._receipt
        run = self.confidential(Gateway())
        self.assertEqual(run["text"], "about 4,200 USDG")
        self.assertEqual(len(self.transfers), 1)
        self.assertEqual(self.agent._payments(), {})


class UnexpectedAnswerTest(AgentCase):
    """A 200 whose JSON is not a completion. The generation is paid for either
    way, so the caller gets the body it bought and a null text rather than an
    exception from a `.get` on a list."""

    def confidential(self, body):
        gateway = Gateway(answer=lambda data, headers: Answer(200, body, {"x-receipt-id": "rcpt-1"}))
        with self.serving(gateway):
            return self.agent.confidential_infer(prompt="what is my position worth",
                                                 endpoint=BASE, e2ee=False)

    def test_an_error_object_served_with_a_200_is_handed_back_whole(self):
        run = self.confidential({"error": "the model is still warming up"})
        self.assertIsNone(run["text"])
        self.assertIsNone(run["usage"])
        self.assertEqual(run["response"], {"error": "the model is still warming up"})
        self.assertEqual(run["tx"], TX)

    def test_json_that_is_not_an_object_at_all_is_not_an_attribute_error(self):
        run = self.confidential(b'["still warming up"]')
        self.assertIsNone(run["text"])
        self.assertEqual(run["response"], ["still warming up"])

    def test_a_completion_with_no_choices_reads_as_no_text(self):
        run = self.confidential({"id": "chatcmpl-1", "choices": [], "usage": {"completion_tokens": 0}})
        self.assertIsNone(run["text"])
        self.assertEqual(run["usage"], {"completion_tokens": 0})

    def test_the_open_tier_hands_back_what_it_was_served(self):
        with self.serving(open_tier(Answer(200, b'"warming up"'))):
            run = self.agent.infer(prompt="explain metered GPU compute", endpoint=BASE)
        self.assertIsNone(run["text"])
        self.assertEqual(run["model"], OPEN_MODEL)
        self.assertEqual(run["response"], "warming up")


class QuoteVerifierTest(AgentCase):
    def test_without_a_quote_verifier_a_confidential_call_refuses_rather_than_sends(self):
        if importlib.util.find_spec("dcap_qvl"):
            self.skipTest("dcap-qvl is installed, so the default verifier does the real check")

        gateway = Gateway(attestation=attestation_report)
        with self.serving(gateway), self.assertRaises(ConfidentialError) as caught:
            self.agent.confidential_infer(prompt="sensitive", endpoint=BASE,
                                          expected_workload=TEST_WORKLOAD)
        self.assertEqual(caught.exception.code, "quote_unverified")
        self.assertIn("prismnetwork[confidential]", caught.exception.body["cause"])
        self.assertEqual(self.transfers, [])
        self.assertIsNone(gateway.paid)


def gpu_evidence(quote: bytes, signing_address: str, nonce: str, digest: str) -> dict:
    return {"nvidia_payload": json.dumps({"nonce": nonce}), "intel_quote": quote.hex(),
            "signing_address": signing_address, "workload_keyset_digest": digest}


class GpuEvidenceTest(AgentCase):
    """The GPU evidence is only worth anything once it is tied to the workload
    the prompt is sealed to. The endpoint answers from whichever replica the
    upstream picks, so a sibling is a routing miss and asking again resolves
    it."""

    ADDRESS = "0x" + "cd" * 20
    NONCE = "ee" * 32

    def evidence_quote(self, mr_td=bytes([0x11]) * 48, rtmr3=None):
        quote = bytearray(632)
        quote[_MR_TD] = mr_td
        quote[_RTMR3] = rtmr3 if rtmr3 is not None else replay_rtmr3(json.loads(
            attestation_report("0" * 64)["attestation"]["evidence"]["event_log"]))
        quote[_REPORT_DATA] = bytes.fromhex(
            self.ADDRESS.removeprefix("0x") + "0" * 24 + self.NONCE)
        return bytes(quote)

    def test_a_sibling_instance_is_asked_again_and_the_right_one_binds(self):
        sibling = self.evidence_quote(rtmr3=bytes([0x77]) * 48)
        gateway = Gateway(attestation=attestation_report, answer=sealed_answer)
        gateway.gpu_evidence = lambda n, query: Answer(200, gpu_evidence(
            sibling if n == 1 else self.evidence_quote(), self.ADDRESS, self.NONCE,
            query["keyset_digest"]))

        with self.serving(gateway):
            run = self.agent.confidential_infer(prompt="sensitive", endpoint=BASE,
                                                expected_workload=TEST_WORKLOAD,
                                                quote_verifier=offset_verifier, verify_gpu=True)
        self.assertTrue(run["attestation"]["verified"])
        asked = [c for c in gateway.calls if c["path"] == "/v1/gpu-evidence"]
        self.assertEqual(len(asked), 2)
        # Both asked for the instance holding this key set rather than for
        # whichever one the balancer felt like.
        for call in asked:
            self.assertEqual(call["query"]["keyset_digest"], run["attestation"]["keyset_digest"])

    def test_evidence_from_another_machine_stops_the_call(self):
        other = self.evidence_quote(mr_td=bytes([0x22]) * 48)
        gateway = Gateway(attestation=attestation_report)
        gateway.gpu_evidence = lambda n, query: Answer(200, gpu_evidence(
            other, self.ADDRESS, self.NONCE, query["keyset_digest"]))

        with self.serving(gateway), self.assertRaises(ConfidentialError) as caught:
            self.agent.confidential_infer(prompt="sensitive", endpoint=BASE,
                                          expected_workload=TEST_WORKLOAD,
                                          quote_verifier=offset_verifier, verify_gpu=True)
        self.assertEqual(caught.exception.code, "gpu_unverified")
        self.assertIn("mr_td", caught.exception.body["cause"])
        self.assertEqual(self.transfers, [])

    def test_the_report_data_slot_names_the_signer_and_the_gpu_nonce(self):
        address = "0x" + "cd" * 20
        nonce = "ee" * 32
        slot = address.removeprefix("0x") + "0" * 24 + nonce
        self.assertTrue(gate_gpu_binding(slot, address, nonce).ok)
        self.assertFalse(gate_gpu_binding(slot, "0x" + "11" * 20, nonce).ok)
        self.assertEqual(gate_gpu_binding(slot, address, "ff" * 32).detail,
                         "the quote binds a different GPU nonce than the evidence carries")
        self.assertFalse(gate_gpu_binding("00", address, nonce).ok)

    def test_two_reports_are_the_same_td_only_when_every_measurement_agrees(self):
        one = TdReport(mr_td=b"a" * 48, rt_mr0=b"b" * 48, rt_mr3=b"c" * 48)
        self.assertTrue(same_td(one, TdReport(mr_td=b"a" * 48, rt_mr0=b"b" * 48, rt_mr3=b"c" * 48)).ok)
        self.assertEqual(same_td(one, TdReport(mr_td=b"z" * 48, rt_mr0=b"b" * 48, rt_mr3=b"c" * 48)).detail,
                         "mr_td")


@unittest.skipUnless(FIXTURE.exists(), "needs a checkout")
class CapturedReportTest(unittest.TestCase):
    """One live report from the public attestation endpoint, as the offline
    vector for the replay and binding checks.

    Its ``app_compose`` travels base64 in the fixture, because the measured
    compose is a shell script whose paths a secret scanner reads as leaked local
    ones, and is restored here byte for byte: the whole point of the check is
    that those bytes hash to the measurement.
    """

    @classmethod
    def setUpClass(cls):
        capture = json.loads(FIXTURE.read_text())
        evidence = capture["report"]["attestation"]["evidence"]
        evidence["app_compose"] = base64.b64decode(evidence["app_compose_b64"]).decode("utf-8")
        cls.report = capture["report"]
        cls.nonce = capture["nonce"]
        # Before the key set's not_after, which is what the capture is a
        # snapshot of.
        cls.now = 1787600000

    def test_the_captured_report_binds_its_key_set_to_the_nonce_it_was_fetched_with(self):
        binding = verify_report_binding(self.report, self.nonce, self.now)
        self.assertTrue(binding.ok, binding.failure())
        self.assertEqual(binding.digest, self.report["workload_keyset_digest"])

    def test_a_report_answering_another_nonce_does_not_bind(self):
        binding = verify_report_binding(self.report, "0" * 64, self.now)
        self.assertFalse(binding.ok)
        self.assertIn("report_data", [c.name for c in binding.checks if not c.ok])

    def test_the_captured_event_log_replays_to_the_quotes_rtmr3_and_measures_the_compose(self):
        measurement = verify_compose_measurement(self.report)
        self.assertTrue(measurement.ok, [c.detail for c in measurement.checks if not c.ok])
        self.assertEqual(
            measurement.compose_hash,
            hashlib.sha256(self.report["attestation"]["evidence"]["app_compose"].encode()).hexdigest(),
        )

    def test_a_quote_read_at_the_v4_offsets_carries_what_the_report_states(self):
        quote = verify_quote(self.report, offset_verifier, self.now)
        self.assertTrue(quote.ok, quote.detail)
        self.assertEqual(quote.report.rt_mr3, verify_compose_measurement(self.report).rtmr3)

    def test_the_shipped_pin_is_the_deployment_the_captured_report_describes(self):
        identity = appraise_workload(self.report, verify_compose_measurement(self.report),
                                     EXPECTED_WORKLOAD)
        self.assertTrue(identity.ok, identity.detail)
        self.assertEqual(identity.provenance,
                         f"{EXPECTED_WORKLOAD['repo_url']} @ "
                         f"{self.report['attestation']['source_provenance']['repo_commit']}")

    def test_a_caller_who_pins_nothing_is_told_the_transcript_is_weaker(self):
        identity = appraise_workload(self.report, verify_compose_measurement(self.report), None)
        self.assertTrue(identity.ok)
        self.assertTrue(identity.skipped)
        self.assertIn("not pinned by caller", identity.detail)


# The vectors the Node SDK's own verification is held to, run against the same
# shapes: sdk/attest.test.mjs.
VERIFY_NOW = 1_790_000_000
REQUEST = b'{"model":"demo","messages":[{"role":"user","content":"hi"}]}'
RESPONSE = b'{"id":"chatcmpl-1","choices":[]}'
SESSION = {
    "api_version": "aci/1",
    "upstream_name": "demo-upstream",
    "endpoint": "https://upstream.test",
    "verifier_id": "test/1",
    "established_at": VERIFY_NOW - 60,
    "expires_at": VERIFY_NOW + 3600,
    "channel_binding": [],
    "claims": {},
    "evidence": {
        "digest": "sha256:80d70e44d0ae1e829fd5f37c3ee4a60dfbea8d3aa18407ea3f34cf7ec91da34d",
        "data": "data:text/plain;base64,ZXhhbXBsZS1ldmlkZW5jZQ==",
    },
}
VERIFY_BASE = "https://gateway.test/inference"
UNSET = object()


class VerifyGateway:
    """A gateway serving a report whose key set this test holds the receipt
    signing key for, with a boot log that replays to the RTMR3 its quote states
    and measures a compose naming a launcher and a source. Everything except
    Intel's signature over that quote can be checked offline this way."""

    def __init__(self, *, receipt=None, session=None, compose=None, gpu=None,
                 os_image_hash=TEST_WORKLOAD["os_image_hash"], provenance=UNSET,
                 tls_domain="gateway.test"):
        self.signing_key = Ed25519PrivateKey.generate()
        self.compose = compose_file() if compose is None else compose
        self.session = session
        self.gpu = gpu
        self.provenance = ({"repo_url": TEST_WORKLOAD["repo_url"], "repo_commit": TEST_COMMIT}
                           if provenance is UNSET else provenance)
        self.keyset = {
            "subject": None,
            "not_after": VERIFY_NOW + 3600,
            "receipt_signing_keys": [{
                "key_id": "test-1",
                "algo": "ed25519",
                "public_key": self.signing_key.public_key().public_bytes_raw().hex(),
            }],
            "e2ee_public_keys": [],
            "tls_public_keys": [{"spki_sha256": "aa" * 32, "domain": tls_domain}],
        }
        self.digest = keyset_digest(self.keyset)
        self.events = [
            dstack_event("compose-hash", hashlib.sha256(self.compose.encode()).hexdigest()),
            dstack_event("os-image-hash", os_image_hash),
            dstack_event("system-ready", ""),
        ]
        self.receipt = self._sign(receipt) if receipt else None

    def _sign(self, document: dict) -> dict:
        body = {**document, "workload_keyset_digest": self.digest, "key_id": "test-1"}
        return {**body, "signature": self.signing_key.sign(jcs_bytes(body)).hex()}

    def report(self, nonce: str) -> dict:
        quote = bytearray(632)
        quote[_RTMR3] = replay_rtmr3(self.events)
        quote[568:600] = bytes.fromhex(report_data(self.digest, nonce))
        return {
            "api_version": "aci/1",
            "workload_keyset_digest": self.digest,
            "attestation": {
                "tee_type": "tdx",
                "workload_keyset": self.keyset,
                "report_data": report_data(self.digest, nonce),
                "source_provenance": self.provenance,
                "evidence": {"quote": bytes(quote).hex(), "event_log": json.dumps(self.events),
                             "app_compose": self.compose},
            },
        }

    def __call__(self, method, url, data=None, json=None, headers=None, timeout=None):
        path = url.split("?", 1)[0].removeprefix(VERIFY_BASE)
        query = dict(parse_qsl(url.split("?", 1)[1])) if "?" in url else {}
        if path.endswith("/v1/attestation"):
            return Answer(200, self.report(query["nonce"]))
        if path.startswith("/v1/receipts/"):
            return Answer(200, self.receipt) if self.receipt else Answer(404, {"error": "not_found"})
        if path.startswith("/v1/sessions/"):
            return Answer(200, self.session) if self.session else Answer(404, {"error": "not_found"})
        if path.endswith("/v1/gpu-evidence"):
            return self.gpu() if self.gpu else Answer(404, {"error": "not_found"})
        # NVIDIA's own service, which no offline test reaches.
        return Answer(502, {"error": "unreachable"})


class MangledGateway(VerifyGateway):
    """The same gateway with one member of the report replaced after it is
    built. Every member below ``attestation`` is inside a document the endpoint
    hands over whole, so none of it is this client's to trust."""

    def __init__(self, mangle, **options):
        super().__init__(**options)
        self.mangle = mangle

    def report(self, nonce: str) -> dict:
        return self.mangle(super().report(nonce))


def served_receipt(request=REQUEST, response=RESPONSE, session=SESSION) -> dict:
    return {
        "api_version": "aci/1",
        "receipt_id": "rcpt-test",
        "chat_id": "chatcmpl-1",
        "model": "demo",
        "endpoint": "/v1/chat/completions",
        "method": "POST",
        "served_at": VERIFY_NOW,
        "event_log": [
            {"type": "request.received", "body_hash": hash_body(request)},
            *([{"type": "upstream.verified", "result": "verified", "required": True,
                "model_id": "demo", "session_id": compute_session_id(session)}] if session else []),
            {"type": "response.returned", "body_hash": hash_body(response)},
        ],
    }


class ConfidentialVerificationTest(unittest.TestCase):
    """One served call, verified after the fact: the gateway, the receipt it
    signed over these bytes, and what the transcript is willing to call it."""

    def served(self, gateway_options=None, **verify):
        gateway = VerifyGateway(receipt=served_receipt(), session=SESSION, **(gateway_options or {}))
        with patch("prismnetwork._inference.requests.request", gateway):
            result = verify_confidential(**{
                "base": VERIFY_BASE,
                "receipt_id": "rcpt-test",
                "request_bytes": REQUEST,
                "response_bytes": RESPONSE,
                "expected_workload": TEST_WORKLOAD,
                "now": VERIFY_NOW,
                "quote_verifier": refusing_verifier,
                **verify,
            })
        return gateway, result, {c["id"]: c["status"] for c in result["checks"]}

    def detail(self, result, check_id):
        return next(c["detail"] for c in result["checks"] if c["id"] == check_id)

    def test_the_transcript_reports_what_it_checked_and_what_it_could_not(self):
        _, result, status = self.served()
        for check_id in ("keyset-digest", "report-data-binding", "rtmr3-replay", "compose-hash",
                         "workload-identity", "receipt-signature", "receipt-keyset-binding",
                         "request-hash", "response-hash", "upstream-verified", "session-id",
                         "session-evidence"):
            self.assertEqual(status[check_id], "pass", f"{check_id}: {self.detail(result, check_id)}")
        # Custody has no appraiser in the protocol, and no TLS certificate was
        # observed from here. Neither is ever reported as a pass.
        self.assertEqual(status["key-custody"], "skip")
        self.assertEqual(status["tls-spki"], "skip")
        # This gateway has no quote Intel would sign and no GPU evidence, and a
        # verdict never rounds that up.
        self.assertEqual(status["tdx-quote"], "fail")
        self.assertEqual(result["verdict"], "failed")
        self.assertEqual(result["provenance"], f"{TEST_WORKLOAD['repo_url']} @ {TEST_COMMIT}")
        self.assertIn("failed (12 pass, 1 fail, 4 skip)", render_checks(result))

    def test_a_quote_that_verifies_still_leaves_the_gpu_unestablished(self):
        _, result, status = self.served(quote_verifier=offset_verifier)
        self.assertEqual(status["tdx-quote"], "pass")
        self.assertEqual(status["gpu-nras"], "skip")
        self.assertEqual(result["verdict"], "incomplete",
                         "evidence that was never fetched was rounded up to verified")

    def test_a_measured_compose_running_another_launcher_or_source_fails_the_verdict(self):
        _, swapped, status = self.served(
            {"compose": compose_file(launcher=f"ghcr.io/attacker/launcher@sha256:{'7f' * 32}")})
        self.assertEqual(status["compose-hash"], "pass",
                         "the attacker's own compose measures consistently")
        self.assertEqual(status["workload-identity"], "fail")
        self.assertEqual(swapped["verdict"], "failed")
        self.assertIn("runs no ghcr.io/example/launcher", self.detail(swapped, "workload-identity"))

        _, forked, forked_status = self.served(
            {"compose": compose_file(repo="https://example.test/fork.git"),
             "provenance": {"repo_url": "https://example.test/fork.git", "repo_commit": TEST_COMMIT}})
        self.assertEqual(forked_status["workload-identity"], "fail")
        self.assertIn("the measured source is", self.detail(forked, "workload-identity"))

    def test_a_caller_who_pins_no_workload_gets_an_explicit_incomplete(self):
        _, result, status = self.served(expected_workload=None)
        self.assertEqual(status["workload-identity"], "skip")
        self.assertIn("not pinned by caller", self.detail(result, "workload-identity"))
        # The measured source still comes back: it is inside the bytes that hash
        # to the measured compose, whatever policy the caller declined to apply.
        self.assertEqual(result["provenance"], f"{TEST_WORKLOAD['repo_url']} @ {TEST_COMMIT}")

    def test_incomplete_says_evidence_was_missing_and_failed_is_kept_for_a_check_that_failed(self):
        def check(check_id, status):
            return {"id": check_id, "title": check_id, "status": status, "detail": ""}

        documented = [check("key-custody", "skip"), check("tls-spki", "skip")]
        self.assertEqual(verdict_of([check("tdx-quote", "pass"), *documented]), "verified")
        # A receipt nobody kept the bytes for proves what the workload signed,
        # not that it signed this exchange, and the verdict says which.
        self.assertEqual(verdict_of([check("request-hash", "skip"), *documented]), "incomplete")
        self.assertEqual(verdict_of([check("workload-identity", "skip"), *documented]), "incomplete")
        self.assertEqual(verdict_of([check("tdx-quote", "fail"), check("request-hash", "skip"),
                                     *documented]), "failed")

    def test_a_request_the_client_cannot_bind_to_the_receipt_leaves_the_verdict_incomplete(self):
        _, result, status = self.served(request_bytes=None, e2ee=True)
        self.assertEqual(status["request-hash"], "skip")
        # End-to-end encryption is no excuse for tolerating that skip: the
        # reproduction rule is defined, so an unestablished request binding
        # lowers the verdict.
        self.assertEqual(verdict_of([c for c in result["checks"] if c["id"] != "tdx-quote"]),
                         "incomplete")

    def test_restored_request_bytes_that_do_not_reproduce_the_receipt_hash_fail(self):
        _, result, status = self.served(e2ee=True,
                                        restored_request_bytes=b'{"model":"demo","messages":[]}')
        self.assertEqual(status["request-hash"], "fail")
        self.assertEqual(result["verdict"], "failed")
        self.assertIn("the receipt records sha256:", self.detail(result, "request-hash"))

    def test_a_transcript_is_bound_to_the_key_set_the_prompt_was_sealed_to(self):
        _, result, status = self.served(expected_keyset_digest=f"sha256:{'0' * 64}")
        self.assertEqual(status["keyset-digest"], "fail")
        self.assertEqual(result["verdict"], "failed")
        self.assertIn("this call was sealed to sha256:0000", self.detail(result, "keyset-digest"))

        gateway, first, _ = self.served()
        with patch("prismnetwork._inference.requests.request", gateway):
            bound = verify_confidential(base=VERIFY_BASE, receipt_id="rcpt-test",
                                        request_bytes=REQUEST, response_bytes=RESPONSE,
                                        expected_workload=TEST_WORKLOAD, now=VERIFY_NOW,
                                        quote_verifier=refusing_verifier,
                                        expected_keyset_digest=first["keyset_digest"])
        self.assertEqual({c["id"]: c["status"] for c in bound["checks"]}["keyset-digest"], "pass")

    def test_a_mislabelled_key_set_does_not_stop_the_gpu_evidence_being_bound(self):
        # The evidence endpoint and the completions endpoint are served by
        # different replicas of the same workload, so the plaintext label
        # routinely names a sibling. The binding has to be decided by the
        # quotes, and the reported reason has to say which one broke.
        def evidence():
            return Answer(200, {
                "api_version": "aci/1",
                "workload_keyset_digest": "sha256:" + "9" * 64,
                "nvidia_payload": json.dumps({"nonce": "ab" * 32}),
                "signing_address": "0x" + "1" * 40,
                "intel_quote": "not-a-quote",
            })

        _, result, status = self.served({"gpu": evidence}, quote_verifier=offset_verifier)
        self.assertEqual(status["gpu-binding"], "fail")
        self.assertNotIn("names key set", self.detail(result, "gpu-binding"))
        self.assertIn("did not verify", self.detail(result, "gpu-binding"))

    def test_a_malformed_quote_comes_back_as_a_verdict_and_not_an_exception(self):
        def gateway(method, url, **kwargs):
            if "/v1/attestation" in url:
                return Answer(200, {
                    "api_version": "aci/1",
                    "workload_keyset_digest": "sha256:" + "0" * 64,
                    "attestation": {
                        "tee_type": "tdx",
                        "workload_keyset": {"not_after": VERIFY_NOW + 60, "receipt_signing_keys": [],
                                            "e2ee_public_keys": []},
                        "report_data": "ab" * 32,
                        # Odd-length hex: every hex reader in the chain refuses it.
                        "evidence": {"quote": "abc", "event_log": "[]", "app_compose": "{}"},
                    },
                })
            if "/v1/receipts/" in url:
                return Answer(200, {"api_version": "aci/1", "receipt_id": "rcpt-test"})
            return Answer(404, {"error": "not_found"})

        with patch("prismnetwork._inference.requests.request", gateway):
            result = verify_confidential(base=VERIFY_BASE, receipt_id="rcpt-test", now=VERIFY_NOW,
                                         quote_verifier=refusing_verifier)
        status = {c["id"]: c["status"] for c in result["checks"]}
        self.assertEqual(result["verdict"], "failed")
        self.assertEqual(status["tdx-quote"], "fail")
        self.assertEqual(status["report-data-binding"], "fail")
        self.assertEqual(status["rtmr3-replay"], "fail")

    # The top-level shape is already refused; these are the members under it,
    # which the same endpoint controls just as completely. A caller that asked
    # for a verdict on a generation it has already paid for gets one.
    def test_a_report_shaped_by_the_endpoint_is_a_verdict_and_never_an_exception(self):
        def signing_keys(report, value):
            report["attestation"]["workload_keyset"]["receipt_signing_keys"] = value
            return report

        def member(report, name, value):
            report["attestation"][name] = value
            return report

        def evidence(report, name, value):
            report["attestation"]["evidence"][name] = value
            return report

        hostile = {
            "a null receipt signing key": lambda r: signing_keys(r, [None]),
            "a receipt signing key that is a number": lambda r: signing_keys(r, [7]),
            "a receipt signing key that is a list": lambda r: signing_keys(r, [[]]),
            "a receipt signing key with no public key": lambda r: signing_keys(
                r, [{"key_id": "test-1", "algo": "ed25519"}]),
            "an attestation that is a string": lambda r: {**r, "attestation": "nope"},
            "evidence that is a string": lambda r: member(r, "evidence", "nope"),
            "provenance that is a list": lambda r: member(r, "source_provenance", ["x"]),
            "an event log of nulls": lambda r: evidence(r, "event_log", "[null]"),
            "an event log that is a number": lambda r: evidence(r, "event_log", "4"),
            "an event log that is an object": lambda r: evidence(r, "event_log", "{}"),
        }
        for name, mangle in hostile.items():
            with self.subTest(name):
                gateway = MangledGateway(mangle, receipt=served_receipt(), session=SESSION)
                with patch("prismnetwork._inference.requests.request", gateway):
                    result = verify_confidential(base=VERIFY_BASE, receipt_id="rcpt-test",
                                                 request_bytes=REQUEST, response_bytes=RESPONSE,
                                                 expected_workload=TEST_WORKLOAD, now=VERIFY_NOW,
                                                 quote_verifier=offset_verifier)
                self.assertIn(result["verdict"], ("failed", "incomplete"))

    def test_an_endpoint_that_answers_with_something_that_is_not_a_report_fails_every_check(self):
        with patch("prismnetwork._inference.requests.request",
                   lambda *a, **k: Answer(200, b"<html>gateway timeout</html>")):
            result = verify_confidential(base=VERIFY_BASE, receipt_id="rcpt-test", now=VERIFY_NOW)
        status = {c["id"]: c["status"] for c in result["checks"]}
        self.assertEqual(result["verdict"], "failed")
        self.assertIn("not JSON", result["checks"][0]["detail"])
        # Nothing was established, and the two checks that are never a pass
        # still say why rather than joining in as failures.
        self.assertEqual(status["key-custody"], "skip")
        self.assertEqual(status["tls-spki"], "skip")
        self.assertTrue(all(c["status"] == "fail" for c in result["checks"]
                            if c["id"] not in ("key-custody", "tls-spki")))

    def test_json_that_is_not_a_report_is_a_verdict_and_not_a_crash(self):
        for answered in ([{"attestation": "nice try"}], "a report, honest", 7):
            with patch("prismnetwork._inference.requests.request",
                       lambda *a, **k: Answer(200, answered)):
                result = verify_confidential(base=VERIFY_BASE, receipt_id="rcpt-test",
                                             now=VERIFY_NOW)
            self.assertEqual(result["verdict"], "failed")
            self.assertIn("not a report", result["checks"][0]["detail"])

    def test_a_tls_entry_with_an_explicit_null_domain_is_unscoped_and_not_a_crash(self):
        _, result, status = self.served({"tls_domain": None}, observed_spki="aa" * 32)
        self.assertEqual(status["tls-spki"], "pass", self.detail(result, "tls-spki"))

    def test_response_bytes_that_do_not_match_the_receipt_fail_the_check(self):
        gateway = VerifyGateway(receipt=served_receipt(request=b"{}", response=b"{}", session=None))
        with patch("prismnetwork._inference.requests.request", gateway):
            result = verify_confidential(base=VERIFY_BASE, receipt_id="rcpt-test",
                                         request_bytes=b"{}", response_bytes=b'{"tampered":true}',
                                         expected_workload=TEST_WORKLOAD, now=VERIFY_NOW,
                                         quote_verifier=refusing_verifier)
        status = {c["id"]: c["status"] for c in result["checks"]}
        self.assertEqual(status["response-hash"], "fail")
        # No upstream.verified event at all is a receipt that proves nothing
        # about where the model ran.
        self.assertEqual(status["upstream-verified"], "fail")
        self.assertEqual(result["verdict"], "failed")

    def test_a_receipt_altered_after_signing_does_not_verify(self):
        gateway = VerifyGateway(receipt=served_receipt(), session=SESSION)
        gateway.receipt["model"] = "something-else"
        with patch("prismnetwork._inference.requests.request", gateway):
            result = verify_confidential(base=VERIFY_BASE, receipt_id="rcpt-test",
                                         request_bytes=REQUEST, response_bytes=RESPONSE,
                                         expected_workload=TEST_WORKLOAD, now=VERIFY_NOW,
                                         quote_verifier=refusing_verifier)
        status = {c["id"]: c["status"] for c in result["checks"]}
        self.assertEqual(status["receipt-signature"], "fail")
        self.assertEqual(result["verdict"], "failed")

    def test_a_receipt_that_could_not_be_read_is_not_a_receipt_that_passed(self):
        gateway = VerifyGateway(session=SESSION)
        with patch("prismnetwork._inference.requests.request", gateway):
            result = verify_confidential(base=VERIFY_BASE, receipt_id="rcpt-test", now=VERIFY_NOW,
                                         expected_workload=TEST_WORKLOAD,
                                         quote_verifier=refusing_verifier)
        status = {c["id"]: c["status"] for c in result["checks"]}
        for check_id in ("receipt-signature", "receipt-keyset-binding", "request-hash",
                         "response-hash", "upstream-verified"):
            self.assertEqual(status[check_id], "fail")

    def test_nothing_to_verify_is_refused_before_a_gateway_is_asked(self):
        with self.assertRaises(ConfidentialError) as caught:
            verify_confidential(base=VERIFY_BASE)
        self.assertEqual(caught.exception.code, "no_receipt_to_verify")


class NrasClaimsTest(unittest.TestCase):
    NONCE = "ab" * 32
    CLEAN = {
        "measres": "success",
        "secboot": True,
        "dbgstat": "disabled",
        "hwmodel": "GH100 A01 GSP BROM",
        "eat_nonce": "AB" * 32,
        "x-nvidia-gpu-attestation-report-nonce-match": True,
        "x-nvidia-attestation-warning": None,
    }

    def gate(self, overall=None, gpus=None):
        return gate_nras_claims({"x-nvidia-overall-att-result": True, "eat_nonce": self.NONCE,
                                 "exp": VERIFY_NOW + 600, **(overall or {})},
                                {"GPU-0": {**self.CLEAN}} if gpus is None else gpus,
                                self.NONCE, VERIFY_NOW)

    def test_a_clean_attestation_passes_and_names_the_hardware(self):
        gate = self.gate()
        self.assertTrue(gate.ok, gate.detail)
        self.assertIn("GPU-0 GH100 A01 GSP BROM", gate.detail)

    def test_every_way_an_attestation_can_be_weak_is_refused(self):
        cases = {
            "overall attestation result is not true": ({"x-nvidia-overall-att-result": False}, None),
            "the overall token answers a different nonce": ({"eat_nonce": "cd" * 32}, None),
            "the overall token has expired": ({"exp": VERIFY_NOW - 1}, None),
            "no per-GPU token": (None, {}),
            "measurements do not match": (None, {"GPU-0": {**self.CLEAN, "measres": "fail"}}),
            "secure boot is off": (None, {"GPU-0": {**self.CLEAN, "secboot": False}}),
            "debug mode is not disabled": (None, {"GPU-0": {**self.CLEAN, "dbgstat": "enabled"}}),
            "attestation report answers a different nonce":
                (None, {"GPU-0": {**self.CLEAN, "x-nvidia-gpu-attestation-report-nonce-match": False}}),
            "attestation warning": (None, {"GPU-0": {**self.CLEAN,
                                                     "x-nvidia-attestation-warning": "measurement mismatch"}}),
            "token answers a different nonce": (None, {"GPU-0": {**self.CLEAN, "eat_nonce": "cd" * 32}}),
        }
        for expected, (overall, gpus) in cases.items():
            gate = self.gate(overall, gpus)
            self.assertFalse(gate.ok, expected)
            self.assertIn(expected, gate.detail)

    def test_a_warning_field_that_is_absent_is_not_a_warning_field_that_is_null(self):
        claims = {k: v for k, v in self.CLEAN.items() if k != "x-nvidia-attestation-warning"}
        self.assertFalse(self.gate(None, {"GPU-0": claims}).ok)


class Call:
    """A contract call the wallet can really sign, so what breaks is where the
    test puts the break and not the signature."""

    def __init__(self, refuse: Exception | None = None):
        self.refuse = refuse

    def build_transaction(self, params):
        if self.refuse is not None:
            raise self.refuse
        return {"to": PAY_TO, "value": 0, "data": "0x", "gas": 60_000, "gasPrice": 1_000_000_000,
                **params}


class Chain:
    """The parts of web3's eth namespace a signed send touches."""

    def __init__(self, *, refuse=None, receipt=None, contract=None, block_number=1_000):
        self.refuse = refuse
        self.receipt = receipt
        self.contract = contract
        self.block_number = block_number
        self.sent = []

    def get_transaction_count(self, address):
        return 3

    def send_raw_transaction(self, raw):
        self.sent.append(bytes(raw))
        if self.refuse is not None:
            raise self.refuse
        return HexBytes(TX)

    def wait_for_transaction_receipt(self, handle, timeout=None):
        if isinstance(self.receipt, Exception):
            raise self.receipt
        return self.receipt


def receipt(status: int = 1, logs=None):
    return SimpleNamespace(status=status, blockNumber=900, logs=logs or [])


def lease_funded_log(deposit: int, address: str = ESCROW, duration: int = 900) -> dict:
    """The event the escrow emits while it takes the deposit. leaseId, nodeId
    and renter are indexed and travel in the topics, so the data holds deposit,
    duration and the client reference in that order."""
    topic = Web3.keccak(text="LeaseFunded(uint256,bytes32,address,uint256,uint32,bytes32)")
    return {
        "address": address,
        "topics": [HexBytes(topic), HexBytes((7).to_bytes(32, "big")),
                   HexBytes(bytes.fromhex("22" * 32)),
                   HexBytes(bytes(12) + bytes.fromhex("33" * 20))],
        "data": HexBytes(deposit.to_bytes(32, "big") + duration.to_bytes(32, "big") + bytes(32)),
    }


class FundedDepositTest(unittest.TestCase):
    """What a lease actually cost.

    The quote states a ceiling and the escrow charges rate per second times
    duration, so a day settled against the quote counts money that stayed in the
    wallet and buys ten leases where it could afford twenty-five.
    """

    QUOTE = {"quote_id": "q", "node_id": "0x" + "22" * 32, "maximum_escrow": "200000",
             "duration_seconds": 900}

    def agent(self, funding_receipt):
        agent = PrismAgent(KEY, ESCROW)
        agent.w3 = SimpleNamespace(eth=Chain(receipt=funding_receipt, contract=agent.w3.eth.contract))
        agent._usdg = SimpleNamespace(functions=SimpleNamespace(
            allowance=lambda *a: SimpleNamespace(call=lambda: 10 ** 30)))
        agent._escrow = SimpleNamespace(functions=SimpleNamespace(createLease=lambda *a: Call()))
        return agent

    def test_the_deposit_is_what_the_escrow_pulled_and_not_what_the_quote_capped(self):
        agent = self.agent(receipt(logs=[lease_funded_log(137_250)]))
        self.assertEqual(agent._fund(dict(self.QUOTE)), (TX, 137_250, "receipt"))

    def test_a_funding_transaction_with_no_such_log_falls_back_to_the_quote(self):
        agent = self.agent(receipt(logs=[]))
        self.assertEqual(agent._fund(dict(self.QUOTE)), (TX, 200_000, "quote"))

    def test_a_lease_funded_by_another_contract_is_not_this_escrows_deposit(self):
        agent = self.agent(receipt(logs=[lease_funded_log(137_250, address=PAY_TO)]))
        self.assertEqual(agent._fund(dict(self.QUOTE)), (TX, 200_000, "quote"))

    def test_the_lease_carries_the_deposit_and_where_it_was_read_from(self):
        agent = self.agent(receipt(logs=[lease_funded_log(137_250)]))
        agent.session = "session"
        agent.balances = lambda: {"address": agent.address, "usdg": 5_000_000, "eth": 10 ** 18}
        agent.quote = lambda *a, **k: dict(self.QUOTE)
        agent.confirm = lambda *a: {"lease_id": 7}
        agent.wait_for_access = lambda lease_id, **k: {"mode": "ssh"}
        made = {"dir": tempfile.mkdtemp(prefix="prism-test-"), "key_path": "id",
                "public_key": "ssh-ed25519 AAAA"}
        self.addCleanup(shutil.rmtree, made["dir"], True)
        agent._generate_ssh_key = lambda: made

        lease = agent.lease(DEFAULT_IMAGE, 900)
        self.assertEqual(lease.deposit_micros, 137_250)
        self.assertEqual(lease.deposit_source, "receipt")

    def test_a_held_quote_is_funded_as_shown_and_a_command_makes_it_a_batch(self):
        agent = self.agent(receipt(logs=[lease_funded_log(137_250)]))
        agent.session = "session"
        seen = []
        agent.quote = lambda *a, **k: self.fail("fund_quote must not take a new quote")
        agent.confirm = lambda quote_id, *a: seen.append(quote_id) or {"lease_id": 7}
        agent.wait_for_access = lambda lease_id, **k: {"mode": "ssh"}
        agent.wait_for_result = lambda lease_id, **k: {"stdout": "ok", "code": 0}
        made = {"dir": tempfile.mkdtemp(prefix="prism-test-"), "key_path": "id",
                "public_key": "ssh-ed25519 AAAA"}
        self.addCleanup(shutil.rmtree, made["dir"], True)
        agent._generate_ssh_key = lambda: made

        held = dict(self.QUOTE)
        lease = agent.fund_quote(held)
        self.assertEqual(seen, [held["quote_id"]])
        self.assertEqual(lease.lease_id, 7)
        self.assertEqual(lease.deposit_micros, 137_250)

        made["dir"] = tempfile.mkdtemp(prefix="prism-test-")
        batch = agent.fund_quote({**held, "command": "nvidia-smi"})
        self.assertEqual(batch.result["stdout"], "ok")
        self.assertFalse(os.path.exists(made["dir"]), "a batch has no machine to open")


class BroadcastPhaseTest(unittest.TestCase):
    """What a failure says about the chain having seen the transaction.

    A caller's spend ledger reads exactly one field to decide whether to count
    the money, so every failure has to place itself on one side of the send.
    """

    def agent(self, **chain):
        agent = PrismAgent(KEY, ESCROW)
        agent.w3 = SimpleNamespace(eth=Chain(contract=agent.w3.eth.contract, **chain))
        return agent

    def test_a_submission_the_chain_never_accepted_names_nothing_because_nothing_left(self):
        agent = self.agent(refuse=ValueError("insufficient funds for gas * price + value"))
        with self.assertRaises(PrismError) as caught:
            agent._send(Call())
        self.assertEqual(caught.exception.code, "pre_broadcast_failure")
        self.assertIs(caught.exception.broadcast, False)
        self.assertIn("insufficient funds", caught.exception.body["cause"])

    def test_a_transaction_that_could_not_be_built_never_reached_the_wire(self):
        agent = self.agent()
        with self.assertRaises(PrismError) as caught:
            agent._send(Call(refuse=ValueError("execution reverted: gas estimate")))
        self.assertEqual(caught.exception.code, "pre_broadcast_failure")
        self.assertIs(caught.exception.broadcast, False)
        self.assertEqual(agent.w3.eth.sent, [], "a transaction was sent for a build that failed")

    def test_a_transaction_whose_receipt_never_arrived_still_names_itself(self):
        agent = self.agent(receipt=TimeoutError("timed out while waiting for transaction receipt"))
        with self.assertRaises(PrismError) as caught:
            agent._send(Call())
        self.assertEqual(caught.exception.code, "confirmation_timeout")
        self.assertEqual(caught.exception.broadcast, TX)
        self.assertEqual(caught.exception.body["hash"], TX)
        self.assertIn("timed out", caught.exception.body["cause"])

    def test_a_reverted_transaction_is_one_the_chain_saw(self):
        agent = self.agent(receipt=receipt(status=0))
        with self.assertRaises(PrismError) as caught:
            agent._send(Call())
        self.assertEqual(caught.exception.code, "tx_reverted")
        self.assertEqual(caught.exception.broadcast, TX)

    def test_a_transfer_whose_receipt_never_arrived_still_names_its_payment(self):
        agent = self.agent()
        agent._send = lambda call, confirmations=1: (_ for _ in ()).throw(
            PrismError(504, "confirmation_timeout", {"hash": TX}, TX))
        with self.assertRaises(PaymentError) as caught:
            agent._transfer_usdg(PAY_TO, 30_000)
        self.assertEqual(caught.exception.code, "confirmation_timeout")
        self.assertEqual(caught.exception.broadcast, TX)
        self.assertEqual(caught.exception.body["payment_tx"], TX)

    # No stub: the gas estimate goes to an rpc that is not there, which is the
    # ordinary way a transfer fails before anything is signed.
    def test_a_transfer_the_rpc_would_not_price_costs_nothing(self):
        agent = self.agent()
        with self.assertRaises(PaymentError) as caught:
            agent._transfer_usdg(PAY_TO, 30_000)
        self.assertEqual(caught.exception.code, "pre_broadcast_failure")
        self.assertIs(caught.exception.broadcast, False)
        self.assertEqual(agent.w3.eth.sent, [])

    def test_an_address_this_sdk_would_not_sign_costs_nothing(self):
        agent = self.agent()
        with self.assertRaises(PaymentError) as caught:
            agent._transfer_usdg("not-an-address", 30_000)
        self.assertEqual(caught.exception.code, "pre_broadcast_failure")
        self.assertIs(caught.exception.broadcast, False)
        self.assertEqual(agent.w3.eth.sent, [])


class LeasePhaseTest(unittest.TestCase):
    QUOTE = {"quote_id": "q", "node_id": "0x" + "22" * 32, "maximum_escrow": "200000",
             "duration_seconds": 900}

    def agent(self, usdg=5_000_000):
        agent = PrismAgent(KEY, ESCROW)
        agent.session = "session"
        agent.balances = lambda: {"address": agent.address, "usdg": usdg, "eth": 10 ** 18}
        agent.quote = lambda *a, **k: dict(self.QUOTE)
        agent.confirm = lambda *a: {"lease_id": 7}
        agent.wait_for_access = lambda lease_id, **k: {"mode": "ssh"}
        self.keys = []

        def keygen():
            made = {"dir": tempfile.mkdtemp(prefix="prism-test-"), "key_path": "id", "public_key": "ssh-ed25519 AAAA"}
            self.keys.append(made)
            self.addCleanup(shutil.rmtree, made["dir"], True)
            return made

        agent._generate_ssh_key = keygen
        return agent

    def test_a_funded_lease_carries_the_deposit_this_wallet_signed_for(self):
        agent = self.agent()
        agent._fund = lambda quote: (TX, 200_000, "receipt")
        lease = agent.lease(DEFAULT_IMAGE, 900)
        self.assertEqual(lease.deposit_micros, 200_000)
        self.assertEqual(lease.funding_hash, TX)

    def test_a_balance_that_cannot_be_read_is_a_failure_before_the_wire(self):
        agent = self.agent()
        agent.balances = lambda: (_ for _ in ()).throw(ConnectionError("rpc refused the connection"))
        with self.assertRaises(PrismError) as caught:
            agent.lease(DEFAULT_IMAGE, 900)
        self.assertEqual(caught.exception.code, "pre_broadcast_failure")
        self.assertIs(caught.exception.broadcast, False)
        self.assertIn("rpc refused", caught.exception.body["cause"])

    def test_an_unfunded_wallet_is_a_refusal_that_cost_nothing(self):
        with self.assertRaises(PrismError) as caught:
            self.agent(usdg=0).lease(DEFAULT_IMAGE, 900)
        self.assertEqual(caught.exception.code, "wallet_unfunded")
        self.assertIs(caught.exception.broadcast, False)

    def test_a_quote_past_the_cap_is_a_refusal_that_cost_nothing(self):
        with self.assertRaises(PrismError) as caught:
            self.agent().lease(DEFAULT_IMAGE, 900, max_deposit=1)
        self.assertEqual(caught.exception.code, "cost_exceeds_max")
        self.assertIs(caught.exception.broadcast, False)
        self.assertEqual(self.keys, [], "a key was generated for a lease that was refused")

    def test_an_approval_that_failed_left_the_deposit_in_the_wallet(self):
        agent = self.agent()
        agent._usdg = SimpleNamespace(functions=SimpleNamespace(
            allowance=lambda *a: SimpleNamespace(call=lambda: 0),
            approve=lambda *a: Call(),
        ))
        agent._send = lambda call, confirmations=1: (_ for _ in ()).throw(
            PrismError(504, "confirmation_timeout", {"hash": TX}, TX))
        with self.assertRaises(PrismError) as caught:
            agent.lease(DEFAULT_IMAGE, 900)
        self.assertEqual(caught.exception.code, "approval_failed")
        self.assertIs(caught.exception.broadcast, False, "an approval moved no USDG")
        self.assertEqual(caught.exception.body["hash"], TX)
        self.assertFalse(os.path.exists(self.keys[0]["dir"]), "a key was kept for a lease nobody paid for")

    def test_a_deposit_whose_receipt_never_arrived_keeps_the_key_and_names_the_transaction(self):
        agent = self.agent()
        agent._fund = lambda quote: (_ for _ in ()).throw(
            PrismError(504, "confirmation_timeout", {"hash": TX}, TX))
        with self.assertRaises(PrismError) as caught:
            agent.lease(DEFAULT_IMAGE, 900)
        self.assertEqual(caught.exception.broadcast, TX)
        self.assertEqual(caught.exception.body["funding_hash"], TX)
        self.assertTrue(os.path.exists(self.keys[0]["dir"]),
                        "the only key into a machine that is being paid for was discarded")

    def test_a_confirmation_that_failed_after_funding_names_the_deposit(self):
        agent = self.agent()
        agent._fund = lambda quote: (TX, 200_000, "receipt")
        agent.confirm = lambda *a: (_ for _ in ()).throw(PrismError(502, "control_plane_error", {}))
        with self.assertRaises(PrismError) as caught:
            agent.lease(DEFAULT_IMAGE, 900)
        self.assertEqual(caught.exception.broadcast, TX)
        self.assertEqual(caught.exception.body["funding_hash"], TX)
        self.assertEqual(caught.exception.body["key_path"], "id")

    def test_a_failure_after_funding_that_is_not_ours_is_still_a_funded_lease(self):
        agent = self.agent()
        agent._fund = lambda quote: (TX, 200_000, "receipt")
        agent.confirm = lambda *a: (_ for _ in ()).throw(RuntimeError("json decode failed"))
        with self.assertRaises(PrismError) as caught:
            agent.lease(DEFAULT_IMAGE, 900)
        self.assertEqual(caught.exception.code, "lease_failed_after_funding")
        self.assertEqual(caught.exception.broadcast, TX)


if __name__ == "__main__":
    unittest.main()
