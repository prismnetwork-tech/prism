"""Metered inference: one generation, paid for per request.

Two tiers sit behind the same wallet. The open tier runs a completion on a
rented GPU and is the cheaper, faster choice for text. The confidential tier
runs the model inside a GPU TEE, answers with a receipt signed over the exact
bytes of the exchange, and, with end-to-end encryption on, encrypts the prompt
to a key the enclave's own hardware quote commits to, so the relay in between
carries ciphertext.

Both are bought the same way: the endpoint answers an unpaid request with a
price, the agent's wallet transfers USDG on Robinhood Chain, and the transfer
travels back inside a signature that also covers the request bytes it buys, so a
payment header read off the wire cannot be spent on a different request.

Everything that decides who can read a confidential prompt runs before the
prompt is sent: the key set comes out of a hardware quote, that quote verifies
to Intel's root, the boot log replays to the RTMR3 the quote states, and the
measured compose runs the code this SDK pins. A prompt is never sent to an
enclave that fails any of it, and never falls back to the open tier.

The port is of ``sdk/prism.mjs``, ``sdk/attest.mjs`` and the ACI verifier they
vendor, so a Python integration and a Node one send the same bytes.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, fields
from typing import Callable
from urllib.parse import quote as urlquote
from urllib.parse import urlencode, urlsplit

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from web3 import Web3

from ._agent import USDG, PrismError
from ._e2ee import (
    E2eeError,
    SealedRequest,
    decrypt_response,
    encrypt_chat_request,
    jcs_bytes,
)
from ._x402 import hash_request, payment_header

DEFAULT_INFERENCE_BASE = "https://api.prismnetwork.tech/inference"
DEFAULT_CONFIDENTIAL_BASE = DEFAULT_INFERENCE_BASE
DEFAULT_MAX_TOKENS = 512

FETCH_TIMEOUT = 30
# A generation can wait on a cold box, so the paid call gets its own budget and
# keeps the payment across the wait rather than paying twice.
PAID_CALL_TIMEOUT = 620
PAID_CALL_DEADLINE = 600
PAID_CALL_RETRY = 15

# How the chain is spelled in an x402 quote. v1 clients read a chain name and v2
# clients read CAIP-2; Robinhood Chain has always been advertised in CAIP-2.
ROBINHOOD_NETWORKS = ("eip155:4663", "robinhood")

# The deployment the confidential tier is pinned to, read off a live known-good
# report and kept in step with the Node SDK's EXPECTED_WORKLOAD. The launcher
# image digest is the root of it: the launcher is measured into the quote, and
# it is the thing that clones and runs the gateway source, so its digest pins
# the code that ends up holding the E2EE private key.
#
# This is a snapshot of one known-good deployment. It has to be updated when
# Phala rebuilds the launcher or advances the gateway source, and it does not
# establish that the launcher image was built from the source it names.
EXPECTED_WORKLOAD = {
    "launcher_image":
        "ghcr.io/redpill-ai/private-ai-launcher@sha256:"
        "c083ff9e6a5ddf10f6c9e9bb1f74cc618deebecfea5208b563c574399db4637c",
    "repo_url": "https://github.com/Dstack-TEE/private-ai-gateway.git",
    "os_image_hash": "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033",
    "repo_commit": "b6b5c1b82f6fc59490db5a5255bf4493805e66c6",
}

_ERC20_TRANSFER = [
    {"name": "transfer", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "to", "type": "address"}, {"name": "value", "type": "uint256"}],
     "outputs": [{"type": "bool"}]},
]


class ConfidentialError(PrismError):
    """The evidence behind a confidential call did not hold. Raised before a
    prompt is sent whenever the enclave cannot be established, and after an
    answer whenever it cannot be opened."""


class PaymentError(PrismError):
    """A paid call that was refused, priced past its cap, or served nothing for
    money that has already moved. ``broadcast`` names the transfer when one was
    made, and ``body['payment_header']`` redeems it."""


def _keep() -> None:
    """A payment nothing has claimed yet."""


@dataclass
class Served:
    status: int
    headers: dict
    content: bytes
    tx: str
    sent: SealedRequest
    # Drops the payment from the in-process cache. The endpoint consumed it the
    # moment it answered, but the hash is the caller's only handle on money that
    # has moved, so it is held until the caller has the answer in hand.
    release: Callable[[], None] = _keep


def _safe_json(res):
    try:
        return res.json()
    except ValueError:
        return None


def _mapping(value) -> dict:
    """A JSON value the endpoint promised would be an object. Anything else
    reads as empty rather than raising, which is what the Node SDK's optional
    chaining does with the same body."""
    return value if isinstance(value, dict) else {}


def _paid_json(served: Served):
    """The JSON body of an answer that has already been paid for."""
    try:
        return json.loads(served.content.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise PaymentError(502, "malformed_answer", {
            "cause": f"the endpoint served {len(served.content)} bytes that are not JSON: {e}",
            "payment_tx": served.tx,
            "receipt_id": served.headers.get("x-receipt-id"),
        }, served.tx) from e


def _completion_text(completion: dict) -> str | None:
    """The generated text of a chat completion, or None from any body that is
    not one. The generation is paid for either way, so an answer this SDK does
    not recognise is handed back whole rather than raised over."""
    choices = completion.get("choices")
    first = _mapping(choices[0]) if isinstance(choices, list) and choices else {}
    content = _mapping(first.get("message")).get("content")
    return content if isinstance(content, str) else None


def _compact(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _public_json(url: str, code: str, error=PrismError):
    try:
        res = requests.request("GET", url, headers={"accept": "application/json"}, timeout=FETCH_TIMEOUT)
    except requests.RequestException as e:
        raise error(504, code, {"cause": str(e)}) from e
    if not res.ok:
        raise error(res.status_code, code, {"cause": f"{url} answered {res.status_code}"})
    body = _safe_json(res)
    if body is None:
        raise error(502, code, {"cause": f"{url} answered with something that is not JSON"})
    return body


# The ACI digest constructions (Appendix A, §3.1, §3.2). Artifacts the service
# builds are hashed as the exact served bytes; the attestation statement is the
# one payload a verifier constructs itself, as a fixed byte template whose
# inputs are restricted so no JSON escaping is ever needed.

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")


def keyset_digest(keyset) -> str:
    """``workload_keyset_digest`` (§3.1): sha256 over the key set's canonical
    JSON form."""
    return "sha256:" + hashlib.sha256(jcs_bytes(keyset)).hexdigest()


def attestation_statement(digest: str, nonce: str | None) -> bytes:
    """The exact attestation-statement bytes (§3.2). A nonce of ``None`` means
    the query parameter was omitted, which puts the JSON literal null in the
    template."""
    if not _DIGEST_RE.match(digest or ""):
        raise ValueError(f'keyset digest is not sha256:<64-hex>: "{digest}"')
    if nonce is not None and not _NONCE_RE.match(nonce):
        raise ValueError("nonce must be exactly 64 lowercase hex characters (§3.2)")
    part = "null" if nonce is None else f'"{nonce}"'
    return f'{{"keyset_digest":"{digest}","nonce":{part},"purpose":"aci.report_data.v1"}}'.encode("utf-8")


def report_data(digest: str, nonce: str | None) -> str:
    """``report_data`` (§3.2): sha256 of the attestation statement, as bare
    lowercase hex. The TEE places these 32 bytes zero-padded to 64 in the
    quote's report-data field."""
    return hashlib.sha256(attestation_statement(digest, nonce)).hexdigest()


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


# A report is served by the endpoint being appraised, so it is read as whatever
# shape it actually is. A member that is not the object the protocol defines
# carries no claim, and a missing claim is what the checks below are written to
# fail on; letting the read itself throw would hand the endpoint a way to turn a
# verdict into a crash.
def _attested(report) -> dict:
    attestation = report.get("attestation") if isinstance(report, dict) else None
    return attestation if isinstance(attestation, dict) else {}


def _evidence(report) -> dict:
    evidence = _attested(report).get("evidence")
    return evidence if isinstance(evidence, dict) else {}


def _boot_events(evidence: dict) -> list:
    """The boot event log as the list of events the replay walks. A log that is
    not one raises, which is the reason a caller reports rather than the
    AttributeError the first ``event.get`` would have produced."""
    events = json.loads(evidence.get("event_log") or "")
    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        raise ValueError("the boot event log is not a list of events")
    return events


@dataclass
class Binding:
    ok: bool
    checks: list
    digest: str | None = None
    keyset: dict | None = None

    def failure(self) -> str:
        for check in self.checks:
            if not check.ok:
                return check.detail or f"{check.name} failed"
        return ""


def verify_report_binding(report: dict, nonce: str | None, now: int | None = None) -> Binding:
    """The report's cryptographic bindings for the nonce this client sent (§9.1
    check 2). One recomputation establishes that the key set is exactly what the
    quote bound and that the quote postdates the challenge."""
    now = int(time.time()) if now is None else now
    attested = _attested(report)
    report = report if isinstance(report, dict) else {}
    checks = [_equal("api_version", report.get("api_version"), "aci/1")]

    keyset = attested.get("workload_keyset")
    if not isinstance(keyset, dict):
        detail = "workload_keyset is not a JSON object"
        checks += [Check(name, False, detail)
                   for name in ("workload_keyset_digest", "report_data", "not_after")]
        return Binding(False, checks)

    # The recomputed digest is authoritative (Appendix A): the report's restated
    # copy is checked for consistency but never feeds the statement.
    digest = keyset_digest(keyset)
    checks.append(_equal("workload_keyset_digest", report.get("workload_keyset_digest"), digest))
    checks.append(_equal("report_data", attested.get("report_data"), report_data(digest, nonce)))

    not_after = keyset.get("not_after")
    if not isinstance(not_after, int) or isinstance(not_after, bool):
        checks.append(Check("not_after", False, "keyset has no numeric not_after"))
    else:
        checks.append(Check("not_after", now < not_after, f"now {now} >= not_after {not_after}"))

    return Binding(all(c.ok for c in checks), checks, digest, keyset)


def _equal(name: str, actual, expected) -> Check:
    return Check(name, actual == expected, f"report {actual} != recomputed {expected}")


# dstack writes its runtime events with this type, and the RTMR3 replay chains
# each event's digest, never its payload. So a payload only counts once it
# reproduces the digest that was measured.
DSTACK_RUNTIME_EVENT = 0x08000001

# Byte offsets into a v4 TDX quote: 48-byte header, then the TDReport10 fields
# up to rt_mr3 (472 bytes) and the 64-byte report-data slot behind it.
_TDX_RTMR3_OFFSET = 520
_TDX_REPORT_DATA_OFFSET = 568


def replay_rtmr3(events) -> bytes:
    """Replay the dstack event log's ``imr == 3`` events to RTMR3: a SHA-384
    chain over each digest zero-padded to 48 bytes, from 48 zero bytes."""
    mr = bytes(48)
    for event in events:
        if event.get("imr") != 3:
            continue
        digest = bytes.fromhex(event["digest"])
        mr = hashlib.sha384(mr + digest.ljust(max(len(digest), 48), b"\x00")).digest()
    return mr


def measured_event(events, name: str) -> str | None:
    """The payload of the one pre-system-ready dstack event called ``name``, or
    None when there is not exactly one or its digest does not reproduce."""
    found = []
    for event in events or []:
        if event.get("imr") != 3 or event.get("event_type") != DSTACK_RUNTIME_EVENT:
            continue
        if event.get("event") == "system-ready":
            break
        if event.get("event") == name:
            found.append(event)
    if len(found) != 1:
        return None
    event = found[0]
    try:
        payload = bytes.fromhex(str(event.get("event_payload") or ""))
    except ValueError:
        return None
    body = struct.pack("<I", DSTACK_RUNTIME_EVENT) + f":{event['event']}:".encode("utf-8") + payload
    if hashlib.sha384(body).hexdigest() != str(event.get("digest", "")).lower():
        return None
    return str(event["event_payload"]).lower()


@dataclass
class Measurement:
    ok: bool
    rtmr3: bytes
    compose_hash: str
    checks: list

    def check(self, name: str) -> Check:
        return next(c for c in self.checks if c.name == name)


def verify_compose_measurement(report: dict, stated_rtmr3: bytes | None = None) -> Measurement:
    """§9.1 check 4 (dstack policy): the booted compose is the one measured into
    RTMR3. Replays the event log to RTMR3, compares it to the RTMR3 the quote
    states, then checks ``sha256(app_compose)`` against the measured
    ``compose-hash``."""
    evidence = _evidence(report)
    event_log, app_compose, quote = (evidence.get("event_log"), evidence.get("app_compose"),
                                     evidence.get("quote"))
    if not all(isinstance(v, str) for v in (event_log, app_compose, quote)):
        raise ValueError("evidence needs string event_log, app_compose, and quote")
    events = _boot_events(evidence)

    replayed = replay_rtmr3(events)
    stated = stated_rtmr3 if stated_rtmr3 is not None else quote_rtmr3(quote)
    rtmr_ok = len(stated) == 48 and replayed == stated

    # sha256(app_compose) must equal the compose-hash measured before
    # system-ready. Two pre-system-ready compose-hash events are the tampering
    # shape this lookup exists to catch.
    before_ready = []
    for event in events:
        if event.get("imr") != 3:
            continue
        if event.get("event") == "system-ready":
            break
        if event.get("event") == "compose-hash":
            before_ready.append(event)
    duplicated = len(before_ready) > 1
    measured = None if duplicated or not before_ready else before_ready[0].get("event_payload")
    recomputed = hashlib.sha256(app_compose.encode("utf-8")).hexdigest()
    compose_ok = not duplicated and str(measured).lower() == recomputed

    return Measurement(
        ok=rtmr_ok and compose_ok,
        rtmr3=replayed,
        compose_hash=recomputed,
        checks=[
            Check("rtmr3", rtmr_ok, "event log RTMR3 != quote RTMR3"),
            Check("compose_hash", compose_ok,
                  "multiple pre-system-ready compose-hash events" if duplicated
                  else f"sha256(app_compose)={recomputed} != measured {measured or '(none)'}"),
        ],
    )


def quote_rtmr3(quote_hex: str) -> bytes:
    return bytes.fromhex(quote_hex)[_TDX_RTMR3_OFFSET:_TDX_RTMR3_OFFSET + 48]


def quote_report_data(quote_hex: str) -> bytes:
    """The 64-byte report-data slot as it sits in a raw v4 TDX quote (§3.2)."""
    return bytes.fromhex(quote_hex)[_TDX_REPORT_DATA_OFFSET:_TDX_REPORT_DATA_OFFSET + 64]


_IMAGE_PIN = re.compile(r"image:\s*([^\s\"\\]+)@sha256:([0-9a-f]{64})")
_REPO_URL = re.compile(r"REPO_URL=([^\s\"\\]+)")
_REPO_COMMIT = re.compile(r"REPO_COMMIT=([0-9a-fA-F]{7,40})")


@dataclass
class Gate:
    ok: bool
    detail: str
    provenance: str | None = None
    skipped: bool = False


def _measured_workload(app_compose) -> dict:
    """What the measured compose says it runs. Every value here is inside the
    bytes that hash to the measured compose-hash, so none of it is the report's
    word for it."""
    compose = str(app_compose or "")

    def only(pattern):
        hits = pattern.findall(compose)
        return hits[0] if len(hits) == 1 else None

    commit = only(_REPO_COMMIT)
    return {
        "images": [{"repository": m[0], "digest": m[1].lower()} for m in _IMAGE_PIN.findall(compose)],
        "repo_url": only(_REPO_URL),
        "repo_commit": commit.lower() if commit else None,
    }


def _source_of(measured) -> str | None:
    if measured["repo_url"] and measured["repo_commit"]:
        return f"{measured['repo_url']} @ {measured['repo_commit']}"
    return None


def gate_workload_identity(app_compose, os_image_hash, provenance, expected) -> Gate:
    """§9.1 check 4 as a policy: which code the measured compose runs, against
    the deployment the caller pins."""
    measured = _measured_workload(app_compose)
    problems = []
    want_repository, _, want_digest = str(expected.get("launcher_image", "")).partition("@sha256:")
    running = [i for i in measured["images"] if i["repository"] == want_repository]
    if len(running) != 1:
        problems.append(f"the measured compose runs no {want_repository} image" if not running
                        else f"the measured compose names {len(running)} {want_repository} images")
    elif running[0]["digest"] != want_digest.lower():
        problems.append(f"the measured launcher is sha256:{running[0]['digest']}, "
                        f"this SDK pins sha256:{want_digest}")

    if measured["repo_url"] is None:
        problems.append("the measured compose names no single source repository")
    elif measured["repo_url"] != expected.get("repo_url"):
        problems.append(f"the measured source is {measured['repo_url']}, "
                        f"this SDK pins {expected.get('repo_url')}")
    if measured["repo_commit"] is None:
        problems.append("the measured compose pins no single source commit")
    elif expected.get("repo_commit") and measured["repo_commit"] != str(expected["repo_commit"]).lower():
        problems.append(f"the measured commit is {measured['repo_commit']}, "
                        f"this SDK pins {expected['repo_commit']}")

    # A declaration that is not an object declares nothing to contradict the
    # measured compose with, and the measured compose is the authority anyway.
    stated = provenance if isinstance(provenance, dict) else {}
    if measured["repo_url"] is not None and stated.get("repo_url") not in (None, measured["repo_url"]):
        problems.append(f"the report declares source {stated['repo_url']}, "
                        f"the measured compose clones {measured['repo_url']}")
    if (measured["repo_commit"] is not None and stated.get("repo_commit") is not None
            and str(stated["repo_commit"]).lower() != measured["repo_commit"]):
        problems.append(f"the report declares commit {stated['repo_commit']}, "
                        f"the measured compose pins {measured['repo_commit']}")

    if expected.get("os_image_hash"):
        if not isinstance(os_image_hash, str):
            problems.append("the boot log carries no os-image-hash that reproduces its measured digest")
        elif os_image_hash != str(expected["os_image_hash"]).lower():
            problems.append(f"the measured OS image is {os_image_hash}, "
                            f"this SDK pins {expected['os_image_hash']}")

    if problems:
        return Gate(False, "; ".join(problems), _source_of(measured))
    return Gate(
        True,
        f"launcher {want_repository}@sha256:{want_digest[:12]}, "
        f"dstack OS {str(expected.get('os_image_hash'))[:12]}, source {_source_of(measured)}. "
        "The pin is a snapshot of a known-good deployment, so it needs updating when the launcher "
        "is rebuilt, and it does not establish that the image was built from that source.",
        _source_of(measured),
    )


def appraise_workload(report: dict, measurement: Measurement, expected=EXPECTED_WORKLOAD) -> Gate:
    """The identity appraisal over a report whose compose measurement already
    holds. ``expected`` of None is an explicit caller downgrade and reports
    itself as one."""
    evidence = _evidence(report)
    try:
        events = _boot_events(evidence)
    except ValueError:
        return Gate(False, "the report's boot event log is not readable")
    if measured_event(events, "compose-hash") != measurement.compose_hash:
        return Gate(False, "the compose-hash event does not reproduce the digest the RTMR3 replay chains")
    if expected is None:
        return Gate(True, "workload identity not pinned by caller, so the transcript establishes a TDX "
                          "enclave and not which code runs in it",
                    _source_of(_measured_workload(evidence.get("app_compose"))), skipped=True)
    return gate_workload_identity(
        evidence.get("app_compose"),
        measured_event(events, "os-image-hash"),
        _attested(report).get("source_provenance"),
        expected,
    )


@dataclass
class TdReport:
    mr_td: bytes = b""
    mr_seam: bytes = b""
    rt_mr0: bytes = b""
    rt_mr1: bytes = b""
    rt_mr2: bytes = b""
    rt_mr3: bytes = b""
    report_data: bytes = b""


@dataclass
class VerifiedQuote:
    ok: bool
    status: str | None = None
    report: TdReport | None = None
    advisory_ids: tuple = ()
    detail: str = ""


# What ties two quotes to one machine. RTMR3 covers the instance id, so this is
# a per-instance tie and not merely "another box running the same image".
_TD_MEASUREMENTS = ("mr_td", "rt_mr0", "rt_mr1", "rt_mr2", "rt_mr3")


def same_td(a: TdReport, b: TdReport):
    differing = [f for f in _TD_MEASUREMENTS if getattr(a, f, b"") != getattr(b, f, b"")]
    return Gate(not differing, ", ".join(differing) or "the same TD")


def default_quote_verifier(raw: bytes, now: int, collateral_url: str | None = None) -> VerifiedQuote:
    """A TDX quote against the Intel vendor root, with collateral fetched from
    Intel's provisioning service.

    Loaded on demand: every other check here is pure Python, and a caller
    running the offline ones should not have to install a quote verifier to do
    it. Without ``dcap-qvl`` this reports what is missing, and a confidential
    call refuses rather than sending a prompt to an unverified enclave.
    """
    try:
        import dcap_qvl
    except ImportError:
        return VerifiedQuote(False, detail="the quote cannot be checked here: "
                                           "pip install 'prismnetwork[confidential]'")
    try:
        collateral = _collateral(dcap_qvl, collateral_url or dcap_qvl.INTEL_PCS_URL, raw)
        verified = dcap_qvl.verify(raw, collateral, now)
    except Exception as e:
        return VerifiedQuote(False, detail=f"quote did not verify: {e}")
    parsed = dcap_qvl.parse_quote(raw)
    # A verified SGX quote must not satisfy a TD report: bind the report type
    # before anyone reads a TD field off it.
    if not parsed.is_tdx():
        return VerifiedQuote(False, status=verified.status,
                             detail=f"verified quote is {parsed.quote_type()}, not a TDX TD report")
    report = parsed.report
    return VerifiedQuote(
        True,
        status=verified.status,
        report=TdReport(**{f.name: bytes(getattr(report, f.name, b"") or b"") for f in fields(TdReport)}),
        advisory_ids=tuple(verified.advisory_ids or ()),
    )


def _collateral(dcap_qvl, url: str, raw: bytes):
    """dcap-qvl fetches the Intel collateral on an event loop. Everything else
    here is synchronous, so a caller already running one gets a loop of its own
    on a worker thread rather than a deadlock."""
    async def fetch():
        return await dcap_qvl.get_collateral(url, raw)

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(fetch())
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(fetch())).result()


def verify_raw_quote(quote_hex: str, verifier: Callable, now: int) -> VerifiedQuote:
    try:
        raw = bytes.fromhex(quote_hex)
    except ValueError:
        return VerifiedQuote(False, detail="the quote is not hex")
    return verifier(raw, now)


def verify_quote(report: dict, verifier: Callable, now: int) -> VerifiedQuote:
    """§9.1 check 1: the TDX quote verifies to the Intel vendor root, and the
    verified quote's report_data equals the report's ``report_data`` zero-padded
    to 64 bytes (§3.2). A pass here is what makes the RTMR3 that
    :func:`verify_compose_measurement` replays against authentic."""
    attestation = _attested(report)
    if attestation.get("tee_type") != "tdx":
        return VerifiedQuote(False, detail=f"tee_type {json.dumps(attestation.get('tee_type'))} needs a "
                                           "verifier this library does not implement (§4.2)")
    quote = _evidence(report).get("quote")
    if not isinstance(quote, str):
        return VerifiedQuote(False, detail="report evidence carries no quote")
    stated = attestation.get("report_data")
    if not isinstance(stated, str) or not _NONCE_RE.match(stated):
        return VerifiedQuote(False, detail="report_data is not 32 bytes of lowercase hex")

    verified = verify_raw_quote(quote, verifier, now)
    if not verified.ok:
        return verified
    slot = bytes.fromhex(stated).ljust(64, b"\x00")
    if (verified.report.report_data or b"") != slot:
        return VerifiedQuote(False, status=verified.status,
                             detail="quote report_data does not bind the report")
    return verified


def gate_gpu_binding(report_data_hex: str, signing_address: str, nonce: str) -> Gate:
    """The attestation report binds the GPU nonce into the CPU quote's
    report-data slot as ``signing_address(20) || zeros(12) || nvidia_nonce(32)``.
    Both halves have to hold: the address half proves the quote belongs to the
    workload that signs its answers, the nonce half proves the GPU evidence was
    produced for this quote and not replayed from another machine."""
    slot = str(report_data_hex or "").lower()
    address = str(signing_address or "").removeprefix("0x").lower()
    want = f"{address}{'0' * 24}{str(nonce or '').lower()}"
    if len(slot) != 128 or len(address) != 40:
        return Gate(False, "the report does not carry a 64-byte report-data slot and a signing address")
    if slot != want:
        return Gate(False, "the quote binds a different GPU nonce than the evidence carries"
                    if slot[:40] == address else "the quote binds a different signing address")
    return Gate(True, f"report data binds {signing_address} and GPU nonce {nonce}")


@dataclass
class Enclave:
    """What one established key set says about the machine behind it."""

    digest: str
    keyset: dict
    rtmr3: bytes
    quote_status: str
    report: TdReport
    provenance: str | None = None


@dataclass
class ModelOffer:
    model: str
    card: dict
    pay_to: str | None


# Agent-side verification of a confidential generation: the checks an agent runs
# itself, after the fact, over the answer it just paid for. The port is of
# ``sdk/attest.mjs`` and the ACI verifier it vendors.
#
# The chain it establishes, in order: the TDX quote verifies to Intel's root;
# that quote commits to the workload's key set and to a nonce this client chose;
# the boot event log replays to the RTMR3 the quote states, and the compose it
# measures is the code this SDK pins; the per-request receipt is signed by a key
# in that same key set and commits to the exact request and response bytes; the
# upstream that ran the model was itself verified and the session it cites is
# the document it claims to be; the GPU is attested by NVIDIA under a nonce
# bound into a quote from the same TD.
#
# Two things this cannot prove, and reports as skips rather than dressing up:
# nobody outside the enclave holds the signing keys (the report publishes
# custody evidence, but no verifier in the protocol appraises the KMS chain
# today), and where TLS terminates. End-to-end encryption is what removes the
# second one from the trust path: with it on, the relay carries ciphertext.

NRAS_ATTEST_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu"
NRAS_JWKS_URL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"
NRAS_ISSUER = "https://nras.attestation.nvidia.com"

# A verified verdict tolerates only these two skips, and only for the reason
# each names. Anything else that could not run means evidence the verdict would
# have rested on was missing, which is `incomplete` rather than `verified`.
CUSTODY = "key-custody"
CHANNEL = "tls-spki"
WORKLOAD = "workload-identity"

CUSTODY_DETAIL = ("no verifier appraises the KMS custody chain yet; encrypt end to end rather than "
                  "rely on it")

CHECKS = {
    "keyset-digest": "workload key set recomputed from the served report",
    "report-data-binding": "the quote commits to that key set and to our nonce",
    "tdx-quote": "TDX quote verifies to Intel's root",
    "rtmr3-replay": "boot event log replays to the quote's RTMR3",
    "compose-hash": "the running compose is the one measured into the quote",
    "workload-identity": "the measured compose runs the pinned launcher and source",
    "receipt-signature": "receipt signed by an attested receipt key",
    "receipt-keyset-binding": "receipt binds to the verified key set",
    "request-hash": "the request bytes match the signed receipt",
    "response-hash": "the response bytes match the signed receipt",
    "upstream-verified": "the serving upstream was verified, and verification was required",
    "session-id": "the cited attestation session is the document it claims to be",
    "session-evidence": "the session's evidence hashes to its digest",
    "gpu-nras": "GPU attested by NVIDIA",
    "gpu-binding": "the GPU attestation nonce is bound to the workload's quote",
    "tls-spki": "the TLS key this client spoke to is in the attested key set",
    "key-custody": "private-key custody appraised",
}

# A claim that is absent is not a claim that is null, and NVIDIA's warning field
# is only clean when it is present and null.
_ABSENT = object()


class _Transcript:
    def __init__(self):
        self.checks = []

    def add(self, check_id: str, status: str, detail: str):
        self.checks.append({"id": check_id, "title": CHECKS.get(check_id, check_id),
                            "status": status, "detail": detail})
        return status == "pass"

    def held(self, check_id: str, detail: str):
        return self.add(check_id, "pass", detail)

    def broke(self, check_id: str, detail: str):
        return self.add(check_id, "fail", detail)

    def missed(self, check_id: str, detail: str):
        return self.add(check_id, "skip", detail)


@dataclass
class Receipt:
    ok: bool
    checks: list

    def check(self, name: str) -> Check | None:
        return next((c for c in self.checks if c.name == name), None)


def hash_body(body) -> str:
    """``sha256:<hex>`` of raw body bytes, the form ACI body hashes use
    (Appendix A)."""
    raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def find_event(document, event_type: str):
    # Server-supplied JSON: a malformed document is a failed lookup, not a throw.
    log = (document or {}).get("event_log")
    if not isinstance(log, list):
        return None
    return next((e for e in log if isinstance(e, dict) and e.get("type") == event_type), None)


def verify_receipt(document: dict, keyset: dict, established_digest: str | None) -> Receipt:
    """§9.3 checks 1-2: the ``signature`` member verifies over JCS(document
    minus ``signature``) under the key set entry ``key_id`` names, and the
    document's ``workload_keyset_digest`` equals the established digest.
    Documents whose ``api_version`` is not ``aci/1`` are rejected."""
    keys = (keyset or {}).get("receipt_signing_keys")
    entry = next((k for k in keys if isinstance(k, dict) and k.get("key_id") == document.get("key_id")),
                 None) if isinstance(keys, list) else None
    if entry is None:
        checks = [Check("signature", False,
                        f'key_id "{document.get("key_id")}" not in receipt_signing_keys')]
    elif entry.get("algo") != "ed25519":
        # Appendix B: ed25519 is the only defined signature algorithm.
        checks = [Check("signature", False, f'unsupported signature algo "{entry.get("algo")}"')]
    else:
        unsigned = {k: v for k, v in document.items() if k != "signature"}
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(_bare(entry.get("public_key")))).verify(
                bytes.fromhex(_bare(document.get("signature", ""))), jcs_bytes(unsigned))
            ok = True
        except Exception:
            # Malformed hex is a failed verification, not a raised one.
            ok = False
        checks = [Check("signature", ok,
                        "" if ok else f'ed25519 verification failed under "{document.get("key_id")}"')]

    version = document.get("api_version")
    checks.append(Check("api_version", version == "aci/1",
                        f'api_version "{version}" is not "aci/1"'))
    bound = document.get("workload_keyset_digest")
    checks.append(Check("workload_keyset_digest", bound == established_digest,
                        f"document {bound} != established {established_digest}"))
    return Receipt(all(c.ok for c in checks), checks)


def compute_session_id(record) -> str:
    """``session_id`` (§8): bare 64-hex sha256 of the JCS form of the parsed
    document."""
    return hashlib.sha256(jcs_bytes(record)).hexdigest()


def check_session_evidence(evidence) -> bool:
    """§9.2(2): ``evidence.data`` decodes and hashes to ``evidence.digest``.
    False when the data URI is absent, malformed, or does not hash."""
    if not isinstance(evidence, dict):
        return False
    digest, data = evidence.get("digest"), evidence.get("data")
    if not isinstance(digest, str) or not isinstance(data, str):
        return False
    head, sep, encoded = data.partition(",")
    if not data.startswith("data:") or not sep or not head.endswith(";base64"):
        return False
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception:
        return False
    return hash_body(raw) == digest


def gate_nras_claims(overall, gpus, nonce: str, now: int | None = None) -> Gate:
    """The claim gate over an NVIDIA attestation (NRAS) result. Kept apart from
    the token signature check so the policy is readable and testable on its own:
    a signed token saying the GPU failed its measurements is still a failure."""
    now = int(time.time()) if now is None else now
    overall = overall if isinstance(overall, dict) else {}
    problems = []
    if overall.get("x-nvidia-overall-att-result") is not True:
        problems.append("overall attestation result is not true")
    answered = overall.get("eat_nonce")
    if not isinstance(answered, str) or answered.lower() != str(nonce).lower():
        problems.append("the overall token answers a different nonce")
    expires = overall.get("exp")
    if isinstance(expires, (int, float)) and not isinstance(expires, bool) and now >= expires:
        problems.append("the overall token has expired")

    entries = list((gpus if isinstance(gpus, dict) else {}).items())
    if not entries:
        problems.append("no per-GPU token")
    models = []
    for name, claims in entries:
        claims = claims if isinstance(claims, dict) else {}
        said = []
        if claims.get("measres") != "success":
            said.append("measurements do not match the reference values")
        if claims.get("secboot") is not True:
            said.append("secure boot is off")
        if claims.get("dbgstat") != "disabled":
            said.append("debug mode is not disabled")
        if claims.get("x-nvidia-gpu-attestation-report-nonce-match") is not True:
            said.append("attestation report answers a different nonce")
        warning = claims.get("x-nvidia-attestation-warning", _ABSENT)
        if warning is not None:
            said.append(f"attestation warning: {json.dumps(None if warning is _ABSENT else warning)}")
        token_nonce = claims.get("eat_nonce")
        if isinstance(token_nonce, str) and token_nonce.lower() != str(nonce).lower():
            said.append("token answers a different nonce")
        problems += [f"{name}: {text}" for text in said]
        if isinstance(claims.get("hwmodel"), str):
            models.append(f"{name} {claims['hwmodel']}")

    if problems:
        return Gate(False, "; ".join(problems))
    return Gate(True, f"{', '.join(models)}: measurements match, secure boot on, debug disabled")


def verdict_of(checks, expected_skips=(CUSTODY, CHANNEL)) -> str:
    """The verdict rule over a finished check list. ``failed`` means a check
    actually failed. ``incomplete`` means nothing failed but evidence the
    verdict would have rested on was missing, which is a different thing to say
    and is said with a different word."""
    tolerated = set(expected_skips)
    if any(c["status"] == "fail" for c in checks):
        return "failed"
    return "incomplete" if any(c["status"] == "skip" and c["id"] not in tolerated
                               for c in checks) else "verified"


def render_checks(result: dict) -> str:
    """The checks table as a few lines of text, for a terminal or a tool
    result."""
    mark = {"pass": "ok  ", "fail": "FAIL", "skip": "skip"}
    lines = "\n".join(f"{mark[c['status']]} {c['title']}"
                      + (f"\n       {c['detail']}" if c["detail"] else "")
                      for c in result["checks"])
    counts = ", ".join(f"{sum(1 for c in result['checks'] if c['status'] == s)} {s}"
                       for s in ("pass", "fail", "skip"))
    return f"{lines}\n\n{result['verdict']} ({counts})"


def verify_confidential(*, base: str = DEFAULT_CONFIDENTIAL_BASE, model: str | None = None,
                        receipt_id: str | None = None, receipt: dict | None = None,
                        request_bytes=None, response_bytes=None,
                        request_hash: str | None = None, response_hash: str | None = None,
                        restored_request_bytes=None, restored_request_hash: str | None = None,
                        e2ee: bool = False, expected_workload=EXPECTED_WORKLOAD,
                        expected_keyset_digest: str | None = None, nonce: str | None = None,
                        now: int | None = None, observed_spki: str | None = None,
                        quote_verifier: Callable | None = None) -> dict:
    """Verify one confidential generation end to end.

    ``receipt_id`` comes from the ``x-receipt-id`` header of the response;
    ``request_bytes`` and ``response_bytes`` are the exact bytes this client
    sent and received (pass ``request_hash`` / ``response_hash`` instead when
    only the digests were kept). Under end-to-end encryption the receipt covers
    the restored plaintext request, so pass ``restored_request_bytes`` as well.

    ``expected_workload`` is the code the enclave must be running; ``None``
    downgrades that check to a skip and says so. ``expected_keyset_digest`` is
    the key set a prompt was actually sealed to, which is what ties this
    transcript to the call it describes rather than to whatever the endpoint
    serves now.

    The verdict is ``verified`` when every check that ran passed and every skip
    is one of the documented ones, ``failed`` when a check failed, and
    ``incomplete`` when nothing failed but evidence the verdict would have
    rested on was missing. No verification outcome is ever raised; the one thing
    that raises is a gateway this client cannot reach at all, which is not a
    statement about the workload.
    """
    if not receipt_id and not receipt:
        raise ConfidentialError(400, "no_receipt_to_verify",
                                {"hint": "the response carried no x-receipt-id header"})
    verifier = quote_verifier or default_quote_verifier
    nonce = os.urandom(32).hex() if nonce is None else nonce
    now = int(time.time()) if now is None else now
    root = str(base).rstrip("/")
    skips = {CUSTODY} if observed_spki else {CUSTODY, CHANNEL}
    t = _Transcript()

    fetched = _get_json(f"{root}/v1/attestation?nonce={nonce}", "the attestation endpoint")
    if not fetched["ok"] or not isinstance(fetched["body"], dict):
        # Without a report there is nothing to establish anything against, and
        # the two checks that are never a pass keep saying why they are not.
        why = fetched["detail"] if not fetched["ok"] else \
            "the attestation endpoint answered JSON that is not a report"
        for check_id in CHECKS:
            if check_id not in (CUSTODY, CHANNEL):
                t.broke(check_id, why)
        _channel_check(t, None, observed_spki, root)
        t.missed(CUSTODY, CUSTODY_DETAIL)
        return _verdict(t, skips, nonce, receipt_id, model, None, None)
    report = fetched["body"]

    binding = verify_report_binding(report, nonce, now)
    digest, keyset = binding.digest, binding.keyset
    if not binding.ok:
        t.broke("keyset-digest", binding.failure())
    elif expected_keyset_digest and digest != expected_keyset_digest:
        # The report is sound, but it describes a different key set than the one
        # the prompt was sealed to, so it is not this call's report.
        t.broke("keyset-digest",
                f"the endpoint now serves {digest}, this call was sealed to {expected_keyset_digest}")
    else:
        t.held("keyset-digest", f"{digest}, aci/1, valid until {_unix_time(keyset['not_after'])}")

    quote = verify_quote(report, verifier, now)
    if not quote.ok:
        t.broke("tdx-quote", quote.detail or "quote verification failed")
    elif quote.status != "UpToDate":
        advisories = f" ({', '.join(quote.advisory_ids)})" if quote.advisory_ids else ""
        t.broke("tdx-quote", f"verified to Intel's root, but the platform TCB is {quote.status}{advisories}")
    else:
        t.held("tdx-quote", "verified to Intel's root, platform TCB up to date")

    # The 32 bytes the enclave asked the CPU to sign, read out of the verified
    # quote rather than off the report's own copy of them. A quote too malformed
    # to read at all leaves nothing to compare, which the check below says.
    slot = quote.report.report_data if quote.ok else _report_data_slot(report)
    unverified = "" if quote.ok else " (read off an unverified quote)"
    if not digest:
        t.broke("report-data-binding",
                "no key set was established, so nothing can be recomputed against the quote")
    else:
        expected = report_data(digest, nonce)
        bound = slot[:32].hex() if len(slot) == 64 else "nothing: the quote carries no report-data slot"
        if bound == expected and slot[32:] == bytes(32):
            t.held("report-data-binding",
                   f"the quote's report data is sha256 of our nonce over {digest}{unverified}")
        else:
            t.broke("report-data-binding",
                    f"the quote binds {bound}, this nonce and key set produce {expected}")

    measurement = None
    try:
        measurement = verify_compose_measurement(report, quote.report.rt_mr3 if quote.ok else None)
        rtmr3 = measurement.check("rtmr3")
        t.add("rtmr3-replay", "pass" if rtmr3.ok else "fail",
              f"{measurement.rtmr3.hex()}{unverified}" if rtmr3.ok else rtmr3.detail)
        compose = measurement.check("compose_hash")
        t.add("compose-hash", "pass" if compose.ok else "fail",
              f"sha256(app_compose)={measurement.compose_hash} measured before system-ready"
              if compose.ok else compose.detail)
        if not measurement.ok:
            measurement = None
    except (ValueError, KeyError, TypeError) as e:
        t.broke("rtmr3-replay", f"the report's boot evidence could not be replayed: {e}")
        t.broke("compose-hash", "no replayable boot evidence to measure the compose against")

    # §9.1 check 4. Everything above establishes a genuine TDX enclave; this is
    # the check that says which code is running inside it.
    provenance = None
    if measurement is None:
        t.broke(WORKLOAD, "no measured compose to read the workload identity out of")
    else:
        identity = appraise_workload(report, measurement, expected_workload)
        provenance = identity.provenance
        t.add(WORKLOAD, "skip" if identity.skipped else "pass" if identity.ok else "fail",
              identity.detail)

    # A receipt lives in the workload's memory only, so a caller that fetched it
    # when the answer arrived passes it in rather than hoping it is still there.
    document = receipt if receipt is not None else _receipt_document(root, receipt_id)
    if not isinstance(document, dict) or not document:
        for check_id in ("receipt-signature", "receipt-keyset-binding", "request-hash", "response-hash"):
            t.broke(check_id, "the receipt for this call could not be read")
        t.broke("upstream-verified", "no receipt to read an upstream verification out of")
        t.missed("session-id", "no session is cited")
        t.missed("session-evidence", "no session is cited")
        _gpu_checks(t, root, model, digest, quote, verifier, now)
        _channel_check(t, keyset, observed_spki, root)
        t.missed(CUSTODY, CUSTODY_DETAIL)
        return _verdict(t, skips, nonce, receipt_id, model, digest, provenance)

    verified = verify_receipt(document, keyset, digest) if keyset else None
    signature = verified.check("signature") if verified else None
    t.add("receipt-signature", "pass" if signature and signature.ok else "fail",
          f'key "{document.get("key_id")}"' if signature and signature.ok
          else (signature.detail if signature else "no key set to verify the receipt against"))
    version = verified.check("api_version") if verified else None
    bound = verified.check("workload_keyset_digest") if verified else None
    if version is not None and not version.ok:
        t.broke("receipt-keyset-binding", version.detail)
    else:
        t.add("receipt-keyset-binding", "pass" if bound and bound.ok else "fail",
              f"{digest}, served at {_unix_time(document.get('served_at'))}" if bound and bound.ok
              else (bound.detail if bound else "the receipt binds no key set"))

    _body_check(t, "request-hash", document, "request.received",
                restored_request_bytes if e2ee else request_bytes,
                restored_request_hash if e2ee else request_hash)
    _body_check(t, "response-hash", document, "response.returned", response_bytes, response_hash)

    session_id = _upstream_check(t, document)
    if session_id:
        _session_checks(t, root, session_id, document.get("served_at"))

    _gpu_checks(t, root, model, digest, quote, verifier, now)
    _channel_check(t, keyset, observed_spki, root)

    # §9.1 check 5. The report does publish dstack-kms custody evidence, but
    # appraising it needs the KMS root key and chain rules no verifier in this
    # protocol implements yet, so this is reported as unproven rather than waved
    # through.
    t.missed(CUSTODY, CUSTODY_DETAIL)
    return _verdict(t, skips, nonce, receipt_id, document.get("model") or model, digest, provenance)


def _verdict(t: _Transcript, skips, nonce, receipt_id, model, digest, provenance) -> dict:
    return {
        "verdict": verdict_of(t.checks, skips),
        "checks": t.checks,
        "nonce": nonce,
        "receipt_id": receipt_id,
        "model": model,
        "keyset_digest": digest,
        "provenance": provenance,
    }


def _bare(hex_text) -> str:
    text = str(hex_text or "")
    return text[2:] if text.startswith("0x") else text


def _unix_time(seconds) -> str:
    return _iso_seconds(seconds) if isinstance(seconds, (int, float)) else str(seconds)


def _iso_seconds(seconds) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(seconds)))


def _report_data_slot(report: dict) -> bytes:
    try:
        return quote_report_data(_evidence(report).get("quote"))
    except (ValueError, TypeError):
        return b""


def _get_json(url: str, what: str) -> dict:
    """A JSON document, or a reason it is not one. Only a host this client
    cannot reach at all raises: an endpoint that answers with an error status or
    with something that is not JSON has said something about itself, and the
    caller turns that into a failed check rather than an exception."""
    try:
        res = requests.request("GET", url, headers={"accept": "application/json"},
                               timeout=FETCH_TIMEOUT)
    except requests.RequestException as e:
        raise ConfidentialError(504, "gateway_unreachable", {"cause": f"{what} unreachable: {e}"}) from e
    if not res.ok:
        return {"ok": False, "detail": f"{what} answered HTTP {res.status_code}"}
    body = _safe_json(res)
    if body is None:
        return {"ok": False, "detail": f"{what} answered with something that is not JSON"}
    return {"ok": True, "body": body}


def _receipt_document(root: str, receipt_id):
    if not receipt_id:
        return None
    fetched = _get_json(f"{root}/v1/receipts/{urlquote(str(receipt_id), safe='')}",
                        "the receipt endpoint")
    return fetched["body"] if fetched["ok"] else None


def _body_check(t: _Transcript, check_id: str, document: dict, event: str, body, digest) -> None:
    recorded = (find_event(document, event) or {}).get("body_hash")
    if not isinstance(recorded, str):
        t.broke(check_id, f"the receipt carries no {event} body hash")
        return
    computed = hash_body(body) if body else digest
    if not computed:
        kept = "request" if event == "request.received" else "response"
        t.missed(check_id, f"no {kept} bytes were kept to compare")
        return
    if computed == recorded:
        t.held(check_id, recorded)
        return
    t.broke(check_id, f"the bytes hash to {computed}, the receipt records {recorded}")


def _upstream_check(t: _Transcript, document: dict) -> str | None:
    log = document.get("event_log")
    events = [e for e in log if isinstance(e, dict) and e.get("type") == "upstream.verified"] \
        if isinstance(log, list) else []
    if not events:
        t.broke("upstream-verified", "the receipt records no upstream verification")
        t.missed("session-id", "no session is cited")
        t.missed("session-evidence", "no session is cited")
        return None
    served = next((e for e in events if e.get("result") == "verified"), None)
    if served is None:
        why = events[0].get("reason") or "no reason given"
        t.broke("upstream-verified", f"the receipt records serving through an unverified upstream: {why}")
        t.missed("session-id", "no session is cited")
        t.missed("session-evidence", "no session is cited")
        return None
    session_id = served.get("session_id")
    if served.get("required") is not True:
        t.broke("upstream-verified",
                "the upstream verified, but verification was not required for this request")
    elif not isinstance(session_id, str):
        t.broke("upstream-verified", "the upstream verified but the receipt cites no session")
    else:
        t.held("upstream-verified",
               f"{served.get('model_id') or 'the model'} served through session {session_id}")
    return session_id if isinstance(session_id, str) else None


def _session_checks(t: _Transcript, root: str, session_id: str, served_at) -> None:
    try:
        fetched = _get_json(f"{root}/v1/sessions/{urlquote(session_id, safe='')}",
                            "the sessions endpoint")
    except ConfidentialError as e:
        fetched = {"ok": False, "detail": (e.body or {}).get("cause", str(e))}
    if not fetched["ok"]:
        t.missed("session-id", f"the cited session could not be fetched: {fetched['detail']}")
        t.missed("session-evidence", "no session record to hash")
        return
    session = fetched["body"]
    if not isinstance(session, dict):
        t.broke("session-id", "the cited session is not a record")
        t.broke("session-evidence", "no session record to hash")
        return
    problems = []
    if compute_session_id(session) != session_id:
        problems.append("the record does not hash to the cited id")
    if session.get("api_version") != "aci/1":
        problems.append(f'api_version "{session.get("api_version")}" is not "aci/1"')
    window = (session.get("established_at"), session.get("expires_at"))
    if not all(isinstance(v, (int, float)) for v in (served_at, *window)) \
            or not window[0] <= served_at <= window[1]:
        problems.append("the request was served outside the session's validity window")
    t.add("session-id", "fail" if problems else "pass", "; ".join(problems) or
          f"{session.get('upstream_name')}, valid {_unix_time(window[0])} to {_unix_time(window[1])}")

    ok = check_session_evidence(session.get("evidence"))
    t.add("session-evidence", "pass" if ok else "fail",
          (session.get("evidence") or {}).get("digest") if ok
          else "the session's evidence does not hash to the digest it records")


def _verify_nras_tokens(payload: str, nonce: str, now: int) -> Gate:
    try:
        res = requests.request("POST", NRAS_ATTEST_URL, data=payload,
                               headers={"content-type": "application/json", "accept": "application/json"},
                               timeout=FETCH_TIMEOUT)
    except requests.RequestException as e:
        return Gate(False, f"NVIDIA attestation unreachable: {e}")
    if not res.ok:
        return Gate(False, f"NVIDIA attestation answered HTTP {res.status_code}")
    body = _safe_json(res)
    overall_token = body[0][1] if (isinstance(body, list) and body
                                   and isinstance(body[0], list) and len(body[0]) > 1) else None
    tokens = body[1] if isinstance(body, list) and len(body) > 1 else None
    if not isinstance(overall_token, str) or not isinstance(tokens, dict):
        return Gate(False, "NVIDIA attestation returned an unexpected shape")
    try:
        import jwt
    except ImportError:
        return Gate(False, "NVIDIA's tokens cannot be checked here: pip install 'prismnetwork[confidential]'")
    # NVIDIA rotates these keys every couple of days, which is why the tokens
    # are verified now and the decoded claims are what gets kept.
    keys = jwt.PyJWKClient(NRAS_JWKS_URL)

    def opened(token: str) -> dict:
        return jwt.decode(token, keys.get_signing_key_from_jwt(token).key,
                          algorithms=["ES384"], issuer=NRAS_ISSUER)

    try:
        overall = opened(overall_token)
        gpus = {name: opened(token) for name, token in tokens.items()}
    except Exception as e:
        return Gate(False, f"an NVIDIA token did not verify: {e}")
    return gate_nras_claims(overall, gpus, nonce, now)


def _gpu_checks(t: _Transcript, root: str, model, digest, quote: VerifiedQuote, verifier, now: int) -> None:
    # Name the instance we need. The model runs on several, and the endpoint
    # answers from whichever the upstream picks, so asking blind returns a
    # sibling most of the time: same image, same compose, different RTMR3.
    query = urlencode({k: v for k, v in (("model", model), ("keyset_digest", digest)) if v})
    try:
        fetched = _get_json(f"{root}/v1/gpu-evidence{f'?{query}' if query else ''}",
                            "the GPU evidence endpoint")
    except ConfidentialError as e:
        fetched = {"ok": False, "detail": (e.body or {}).get("cause", str(e))}
    if not fetched["ok"]:
        t.missed("gpu-nras", f"the GPU evidence could not be fetched: {fetched['detail']}")
        t.missed("gpu-binding", "no GPU evidence to bind")
        return
    evidence = fetched["body"]
    payload = evidence.get("nvidia_payload") if isinstance(evidence, dict) else None
    if not isinstance(payload, str):
        t.broke("gpu-nras", "the GPU evidence carries no NVIDIA attestation payload")
        t.broke("gpu-binding", "no GPU evidence to bind")
        return
    try:
        nonce = json.loads(payload).get("nonce")
    except ValueError:
        nonce = None
    if not isinstance(nonce, str):
        t.broke("gpu-nras", "the NVIDIA attestation payload carries no nonce")
        t.broke("gpu-binding", "no GPU nonce to bind")
        return

    nras = _verify_nras_tokens(payload, nonce, now)
    t.add("gpu-nras", "pass" if nras.ok else "fail", nras.detail)

    # The GPU evidence is only worth anything once it is tied to the workload we
    # verified. Its own quote is verified here, the report-data slot is read out
    # of that verified structure, and the TD it came from is held against the TD
    # whose quote carried our nonce. The plaintext key-set field the same
    # response supplies is a label, not a binding, so a label that disagrees is
    # reported and then ignored: the evidence endpoint is served by one replica
    # and completions by another, so the label routinely names a sibling even
    # when the quotes below prove the evidence came from the TD that served us.
    labelled = evidence.get("workload_keyset_digest")
    if not isinstance(evidence.get("intel_quote"), str):
        t.broke("gpu-binding", "the GPU evidence carries no CPU quote to bind against")
        return
    if not quote.ok:
        t.broke("gpu-binding",
                "the workload's own quote did not verify, so the GPU evidence cannot be tied to it")
        return
    gpu_quote = verify_raw_quote(evidence["intel_quote"], verifier, now)
    if not gpu_quote.ok:
        t.broke("gpu-binding", f"the GPU evidence's own quote did not verify: {gpu_quote.detail}")
        return
    tie = same_td(quote.report, gpu_quote.report)
    if not tie.ok:
        t.broke("gpu-binding", f"the GPU evidence's quote comes from a different TD: {tie.detail} "
                               "do not match the workload's quote")
        return
    gate = gate_gpu_binding(gpu_quote.report.report_data.hex(), evidence.get("signing_address"), nonce)
    aside = (f"; the evidence labels itself key set {labelled}, which the quotes above override"
             if labelled != digest else "")
    t.add("gpu-binding", "pass" if gate.ok else "fail",
          f"{gate.detail}, quoted by the TD that carried our nonce{aside}" if gate.ok else gate.detail)


def _channel_check(t: _Transcript, keyset, observed_spki, root: str) -> None:
    """§9.1 check 6. The pin says the connection terminated at a key the enclave
    published. It does not say TLS terminates inside the enclave: no evidence in
    this protocol establishes that, which is why the honest answer without an
    observed certificate is a skip and why end-to-end encryption is the
    mechanism that does not depend on the answer."""
    if not observed_spki:
        t.missed(CHANNEL, "no TLS certificate was observed from here; a prompt's protection rests "
                          "on end-to-end encryption, not on this pin")
        return
    published = (keyset or {}).get("tls_public_keys")
    entries = published if isinstance(published, list) else []
    if not entries:
        t.broke(CHANNEL, "the attested key set publishes no TLS key to pin against")
        return
    host = urlsplit(root).hostname
    observed = observed_spki.lower()
    # §3.1 makes `domain` optional, and the same report shape uses explicit
    # nulls for unknown values, so anything that is not a string is unscoped.
    candidates = [k for k in entries if isinstance(k, dict)
                  and (not isinstance(k.get("domain"), str) or host is None
                       or k["domain"].lower() == host)]
    if any(str(k.get("spki_sha256")).lower() == observed for k in candidates):
        t.held(CHANNEL, f"the observed TLS key {observed} is in the attested key set")
        return
    t.broke(CHANNEL, f"the observed TLS key {observed} is not in the attested key set")


class InferenceMixin:
    """The paid-inference half of :class:`PrismAgent`.

    Kept apart from leasing because nothing here rents a machine: the wallet
    pays per generation and the endpoint owns the GPU.
    """

    def infer(self, prompt: str | None = None, messages: list | None = None, model: str | None = None,
              max_tokens: int = DEFAULT_MAX_TOKENS, max_usdg: float = 0.05,
              endpoint: str = DEFAULT_INFERENCE_BASE) -> dict:
        """Buy one generation from the open tier.

        The supplier running the GPU can read this prompt and its answer. Use
        :meth:`confidential_infer` for anything that must stay private.

        ``max_usdg`` is the ceiling for this call: a quote above it is refused
        before any money moves.
        """
        text = _one_prompt(prompt, messages)
        if not isinstance(max_tokens, int) or max_tokens <= 0:
            raise PrismError(400, "invalid_max_tokens")
        base = str(endpoint).rstrip("/")

        offer = _public_json(f"{base}/v1/models", "inference_endpoint_unavailable")
        models = offer.get("models") or []
        chosen = model or (models[0] if models else None)
        if not chosen or (models and chosen not in models):
            raise PrismError(400, "unknown_model",
                             {"hint": f"models: {', '.join(models) or '(the endpoint offered none)'}"})

        body = {"model": chosen, "prompt": text, "options": {"num_predict": max_tokens}}
        price, pay_to = self._quote(base, "/v1/inference", body, offer.get("pay_to"))
        _within_cap(price, max_usdg)

        served = self.pay_and_post(base=base, path="/v1/inference", price=price, pay_to=pay_to,
                                   body=body, caller="infer")

        def result() -> dict:
            answer = _paid_json(served)
            generated = _mapping(answer)
            return {
                "text": generated.get("response"),
                "model": generated.get("model", chosen),
                "usage": generated.get("usage"),
                "lease_id": generated.get("lease_id"),
                "receipt_id": served.headers.get("x-receipt-id"),
                "price_micros": str(price),
                "price_usdg": f"{price / 1e6:.6f}",
                "tx": served.tx,
                "response": answer,
            }

        return self._delivered(served, result)

    def confidential_infer(self, prompt: str | None = None, messages: list | None = None,
                           model: str | None = None, max_usdg: float = 0.25,
                           max_tokens: int = DEFAULT_MAX_TOKENS, e2ee: bool = True,
                           expected_workload=EXPECTED_WORKLOAD,
                           endpoint: str = DEFAULT_CONFIDENTIAL_BASE,
                           quote_verifier: Callable | None = None,
                           verify_gpu: bool = False) -> dict:
        """Buy one generation from the confidential tier: a chat request served
        by a model running in a GPU TEE, answered with a receipt signed over the
        exact bytes of the exchange.

        With ``e2ee`` on (the default) the message contents are encrypted to a
        key the enclave's own attestation quote commits to, established here
        before anything is sent or paid, so the relay in between carries
        ciphertext. Nothing about a failed check is retried in the open: a call
        that cannot establish the enclave raises :class:`ConfidentialError` and
        no prompt leaves this process.

        ``expected_workload`` is the code that enclave must be running,
        defaulting to the deployment this SDK ships pinned. Passing ``None``
        skips that appraisal and leaves the prompt protected only by "some TDX
        enclave holds the key".

        ``verify_gpu`` additionally ties NVIDIA's GPU evidence to the same TD
        before the prompt is sent. It costs a round trip, and the NVIDIA tokens
        themselves are not checked here.
        """
        chat = messages or ([{"role": "user", "content": prompt}]
                            if isinstance(prompt, str) and prompt.strip() else None)
        if not isinstance(chat, list) or not chat:
            raise PrismError(400, "prompt_required", {"hint": "pass a prompt string or a messages list"})
        if not isinstance(max_tokens, int) or max_tokens <= 0:
            raise PrismError(400, "invalid_max_tokens")
        if verify_gpu and not e2ee:
            raise PrismError(400, "gpu_check_needs_e2ee", {
                "hint": "GPU evidence is tied to the key set encryption establishes, so there is "
                        "nothing to tie it to with e2ee off",
            })
        base = str(endpoint).rstrip("/")
        offer = self._confidential_model(base, model, max_tokens)

        # Everything that protects the prompt happens before it is sent: the key
        # it is encrypted to has to be one the hardware quote commits to, and
        # the code behind that quote has to be the code this SDK pins, not
        # whatever the relay offered.
        body = {"model": offer.model, "messages": chat, "max_tokens": max_tokens}
        plaintext = _compact(body)
        enclave = None
        seal = None
        if e2ee:
            enclave = self._establish_keyset(base, expected_workload, quote_verifier)
            if verify_gpu:
                self._tie_gpu_evidence(base, offer.model, enclave, quote_verifier)
            # The service rejects a request whose timestamp is more than five
            # minutes old, and the retry budget is longer than that, so each
            # attempt seals its own envelope with a fresh nonce and clock.
            seal = _sealer(body, enclave.keyset)

        # Encryption roughly doubles the body, and the relay refuses an
        # oversized one after the payment has been made, so one envelope is
        # built here purely to measure and the attempts seal their own.
        sized = len(seal().payload) if seal else len(plaintext)
        cap_bytes = offer.card.get("max_body_bytes")
        if isinstance(cap_bytes, int) and sized > cap_bytes:
            raise PrismError(413, "request_too_large", {"required": str(sized), "max": str(cap_bytes)})

        price, pay_to = self._quote(base, "/v1/chat/completions",
                                    {"model": offer.model, "max_tokens": max_tokens}, offer.pay_to)
        _within_cap(price, max_usdg)

        served = self.pay_and_post(
            base=base, path="/v1/chat/completions", price=price, pay_to=pay_to,
            **({"seal": seal, "fingerprint": plaintext} if seal else {"body": body}),
            caller="confidential_infer",
        )
        receipt_id = served.headers.get("x-receipt-id")

        def result() -> dict:
            answer = _decrypt_answer(served, receipt_id) if seal else _paid_json(served)
            completion = _mapping(answer)
            run = {
                "text": _completion_text(completion),
                "model": offer.model,
                "usage": completion.get("usage"),
                "endpoint": base,
                "keyset_digest": enclave.digest if enclave else None,
                "expected_workload": expected_workload,
                "receipt_id": receipt_id,
                # The workload keeps receipts in memory only, so this one is
                # fetched now and kept, whether or not the caller ever looks at
                # it.
                "receipt": self._receipt(base, receipt_id) if receipt_id else None,
                "price_micros": str(price),
                "price_usdg": f"{price / 1e6:.6f}",
                "tx": served.tx,
                "e2ee": bool(seal),
                "attestation": _attestation(enclave),
                "bytes": {
                    "request": served.sent.payload,
                    "response": served.content,
                    **({"restored_request": served.sent.restored} if seal else {}),
                },
                "response": answer,
            }
            # The bytes above are what a receipt commits to, and they live in
            # this process only. Verification is offered on the answer itself so
            # a caller never has to reassemble them.
            run["verify"] = lambda **options: self.verify_confidential(run, **options)
            return run

        return self._delivered(served, result)

    def _delivered(self, served: Served, build: Callable[[], dict]) -> dict:
        """The answer the payment bought, or a failure that still names the
        transfer that bought it.

        The transfer is on-chain and irreversible by the time the endpoint
        answers. A spend ledger reads one field to decide whether the money
        moved, so anything raised while the answer is being read carries the
        hash out with it and the payment stays cached until the caller holds the
        answer.
        """
        try:
            run = build()
        except PrismError as e:
            # The class and the code say what went wrong and are the caller's;
            # what this layer knows, and what nothing above it can recover once
            # the cache is cleared, is which transfer paid for the attempt.
            if not isinstance(e.broadcast, str):
                e.broadcast = served.tx
            e.body = {**(e.body or {}), "payment_tx": served.tx}
            raise
        except Exception as e:
            raise PaymentError(502, "answer_unreadable", {
                "cause": str(e),
                "payment_tx": served.tx,
                "receipt_id": served.headers.get("x-receipt-id"),
                "hint": "the endpoint served an answer this payment bought and it could not be read; "
                        "the transfer above is what it cost",
            }, served.tx) from e
        served.release()
        return run

    def verify_confidential(self, result: dict, **options) -> dict:
        """Verify one confidential generation end to end, from what
        :meth:`confidential_infer` returned.

        Everything the checks need is in that mapping: the endpoint, the key set
        the prompt was sealed to, the receipt, and the exact bytes of the
        exchange. ``options`` overrides any of them, and takes the same
        arguments as :func:`verify_confidential`.

        Nothing here is a condition of the answer being usable. It is what turns
        "the endpoint says it ran in an enclave" into evidence a third party can
        check.
        """
        kept = result.get("bytes") or {}
        return verify_confidential(**{
            "base": result.get("endpoint", DEFAULT_CONFIDENTIAL_BASE),
            "model": result.get("model"),
            "receipt_id": result.get("receipt_id"),
            "receipt": result.get("receipt"),
            "request_bytes": kept.get("request"),
            "response_bytes": kept.get("response"),
            "restored_request_bytes": kept.get("restored_request"),
            "e2ee": bool(result.get("e2ee")),
            "expected_workload": result.get("expected_workload", EXPECTED_WORKLOAD),
            "expected_keyset_digest": result.get("keyset_digest"),
            **options,
        })

    def pay_and_post(self, *, base: str, path: str, price: int, pay_to: str, body=None,
                     headers: dict | None = None, seal: Callable | None = None,
                     fingerprint: bytes | None = None, retry_delay: float = PAID_CALL_RETRY,
                     caller: str = "call") -> Served:
        """Pay for one call to a metered endpoint and keep the payment until the
        endpoint actually serves.

        A 503 from an upstream that is merely unavailable and a 402 for a
        payment that is only too young both heal by themselves, so both retry
        with the same payment. Everything else is final, and the payment stays
        cached for the next attempt at the same request.

        ``body`` is sent verbatim when it is already bytes, which is what a
        signed receipt over the request needs: nothing between the caller and
        the workload re-serializes it. Pass ``seal`` instead for a request that
        has to be built fresh per attempt, and ``fingerprint`` so the cache
        still recognises two attempts as the same request.

        A served answer keeps its payment cached. Call ``served.release()`` once
        the answer has been read; anything raised before that leaves the
        transfer redeemable for one more attempt at the same request.
        """
        sent = seal() if seal else SealedRequest(payload=_as_bytes(body), headers=dict(headers or {}))
        identity = hash_request(fingerprint if fingerprint is not None else sent.payload)
        key = f"{base}{path}:{price}:{identity}"
        pending = self._payments()
        tx = pending.get(key)
        if tx is None:
            tx = pending[key] = self._transfer_usdg(pay_to, price)
        deadline = time.time() + PAID_CALL_DEADLINE

        while True:
            # The signature covers the transfer and the bytes it buys, so a
            # header read off the wire cannot be spent on a different request. A
            # resealed attempt carries different bytes and is signed again; the
            # transfer, which is the half that costs money, is made once.
            header = payment_header(self.account, tx, sent.payload)
            # The transfer is on-chain and irreversible from here. The signed
            # header is the only thing that redeems it, and it lives in this
            # process.
            kept = {
                "payment_tx": tx,
                "payment_header": header,
                "hint": f"the payment (tx {tx}) settled on-chain and the endpoint did not serve. While this "
                        f"process lives, the next {caller} for this same request redeems it without paying "
                        "again. payment_header redeems it from anywhere else, and only for this request: "
                        "the signature covers these exact bytes.",
            }
            try:
                res = requests.request(
                    "POST", f"{base}{path}",
                    data=sent.payload,
                    headers={"content-type": "application/json", "accept": "application/json",
                             "x-payment": header, **sent.headers},
                    timeout=PAID_CALL_TIMEOUT,
                )
            except requests.RequestException as e:
                raise PaymentError(504, "endpoint_unreachable", {"cause": str(e), **kept}, tx) from e

            if res.status_code == 200:
                # The endpoint replays a stored answer when it sees a payment it
                # has already consumed. That is an answer to an earlier call, so
                # it is not this one's, whatever the status line says.
                if str(res.headers.get("x-prism-replayed", "")).lower() == "true":
                    pending.pop(key, None)
                    raise PaymentError(409, "payment_replayed", {
                        "cause": f"the endpoint replayed an earlier answer for tx {tx}",
                        "hint": "this payment was already consumed by another call; pay again to have "
                                "this request served",
                    }, tx)
                # The payment is spent, but dropping it here would let a retry
                # after an unreadable answer pay a second time for a generation
                # that was already bought. The caller releases it once it holds
                # the answer; until then the same request redeems the same
                # transfer and the endpoint says it has seen it.
                return Served(200, res.headers, res.content, tx, sent,
                              lambda: pending.pop(key, None))

            answered = _safe_json(res) or {}
            # A payment the endpoint has already consumed will never serve
            # anything again, so it stops being something to retry with.
            if answered.get("error") == "payment_reused":
                pending.pop(key, None)
            retry_after = _number(res.headers.get("retry-after"))
            retryable = (
                (res.status_code == 503 and answered.get("error") == "upstream_unavailable"
                 and not retry_after > 120)
                or (res.status_code == 402
                    and answered.get("error") in ("insufficient_confirmations", "tx_not_found"))
            )
            if not retryable or time.time() > deadline:
                said = "; ".join(str(v) for v in (answered.get("detail"), answered.get("retry")) if v)
                raise PaymentError(
                    res.status_code, answered.get("error") or "generation_failed",
                    {
                        "cause": said or answered.get("error") or f"status {res.status_code}",
                        **(kept if key in pending else {"payment_tx": tx}),
                    },
                    tx,
                )
            time.sleep(retry_delay)
            if seal:
                sent = seal()

    def _payments(self) -> dict:
        """Unconsumed inference payments, keyed by the endpoint, the price and
        the request they paid for, so a generation that never happened is
        retried with the payment already made instead of paying for it twice,
        and a different prompt never inherits it."""
        return self.__dict__.setdefault("_pending_payments", {})

    def _transfer_usdg(self, to: str, micros: int) -> str:
        try:
            contract = self.w3.eth.contract(address=USDG, abi=_ERC20_TRANSFER)
            call = contract.functions.transfer(Web3.to_checksum_address(to), int(micros))
        except Exception as e:
            # An address or an amount this SDK would not sign. Nothing was put
            # on the wire, so nothing left the wallet.
            raise PaymentError(400, "pre_broadcast_failure", {"cause": str(e)}, broadcast=False) from e
        try:
            return self._send(call)
        except PrismError as e:
            body = dict(e.body or {})
            if isinstance(e.broadcast, str):
                # A transfer whose receipt never arrived is still a transfer.
                # The Node SDK names the same fact payment_tx.
                body["payment_tx"] = e.broadcast
            raise PaymentError(e.status, e.code, body, e.broadcast) from e

    def _quote(self, base: str, path: str, body: dict, fallback_pay_to: str | None):
        """The endpoint prices each request itself, so the figure comes from an
        unpaid request rather than from arithmetic on the rate card."""
        try:
            res = requests.request("POST", f"{base}{path}", json=body,
                                   headers={"accept": "application/json"}, timeout=FETCH_TIMEOUT)
        except requests.RequestException as e:
            raise PaymentError(504, "inference_endpoint_unavailable", {"cause": str(e)}) from e
        if res.status_code != 402:
            raise PaymentError(res.status_code, "no_quote",
                               {"hint": "the endpoint did not answer an unpaid request with a price"})
        answered = _safe_json(res) or {}
        accepted = next((a for a in answered.get("accepts") or []
                         if str(a.get("network", "")).lower() in ROBINHOOD_NETWORKS), {})
        micros = ((answered.get("quote") or {}).get("price_micros")
                  or accepted.get("amount") or accepted.get("maxAmountRequired"))
        pay_to = accepted.get("payTo") or fallback_pay_to
        if micros is None or not pay_to:
            raise PaymentError(502, "no_quote", {"cause": "the 402 named no USDG price to pay"})
        return int(micros), pay_to

    def _confidential_model(self, base: str, requested: str | None, max_tokens: int) -> ModelOffer:
        """The confidential half of the endpoint's rate card, and the model this
        call should use. The card also states the caps the endpoint enforces, so
        a request it would refuse is refused here instead, before it is paid
        for."""
        offer = _public_json(f"{base}/v1/models", "inference_endpoint_unavailable")
        card = offer.get("confidential") or {}
        models = list((card.get("models") or {}).keys())
        if not models:
            raise PrismError(503, "no_confidential_model",
                             {"hint": f"{base} offers no confidential model right now"})
        model = requested or models[0]
        if model not in models:
            raise PrismError(400, "unknown_model", {"hint": f"confidential models: {', '.join(models)}"})
        cap = card.get("max_tokens")
        if isinstance(cap, int) and max_tokens > cap:
            raise PrismError(400, "invalid_max_tokens",
                             {"hint": f"the endpoint caps max_tokens at {cap}"})
        return ModelOffer(model, card, offer.get("pay_to"))

    def _establish_keyset(self, base: str, expected_workload, quote_verifier) -> Enclave:
        """The key set the enclave's quote commits to, and the code behind that
        quote.

        Only the checks that protect the prompt run here, which is every check
        that says who can read it: the quote verifies to Intel's root and
        commits to this key set and this nonce, the boot log replays to the
        measurement that quote states, and the measured compose runs the pinned
        launcher and source. Anything short of all of that refuses to hand over
        a prompt.
        """
        verifier = quote_verifier or default_quote_verifier
        now = int(time.time())
        nonce = os.urandom(32).hex()
        report = _public_json(f"{base}/v1/attestation?nonce={nonce}", "attestation_unavailable",
                              ConfidentialError)

        binding = verify_report_binding(report, nonce, now)
        if not binding.ok:
            raise ConfidentialError(502, "attestation_unverified", {"cause": binding.failure()})

        # Which code the report describes is appraised before its quote is, so a
        # report naming the wrong workload is refused whatever hardware signed
        # it.
        try:
            measurement = verify_compose_measurement(report)
        except (ValueError, KeyError, TypeError) as e:
            raise ConfidentialError(502, "attestation_unverified",
                                    {"cause": f"the report's boot evidence could not be read: {e}"}) from e
        compose = measurement.check("compose_hash")
        if not compose.ok:
            raise ConfidentialError(502, "attestation_unverified", {"cause": compose.detail})
        identity = appraise_workload(report, measurement, expected_workload)
        if not identity.ok:
            raise ConfidentialError(502, "attestation_unverified", {
                "cause": identity.detail,
                "hint": "the enclave quoting this key set is not running the code this SDK pins, "
                        "so no prompt was sent to it",
            })

        quote = verify_quote(report, verifier, now)
        if not quote.ok:
            raise ConfidentialError(502, "quote_unverified", {"cause": quote.detail})
        if quote.status != "UpToDate":
            raise ConfidentialError(502, "quote_unverified",
                                    {"cause": f"the platform TCB is {quote.status}"})
        # What makes the measurement above authentic: the log replays to the
        # RTMR3 the verified quote itself states.
        if quote.report.rt_mr3 != measurement.rtmr3:
            raise ConfidentialError(502, "attestation_unverified", {
                "cause": "the boot event log does not replay to the RTMR3 the verified quote states",
            })
        return Enclave(binding.digest, binding.keyset, measurement.rtmr3, quote.status,
                       quote.report, identity.provenance)

    def _tie_gpu_evidence(self, base: str, model: str, enclave: Enclave, quote_verifier) -> dict:
        """Tie NVIDIA's GPU evidence to the TD that quoted this key set.

        The model runs on several instances and the endpoint answers from
        whichever the upstream picks, so the request names the one we need. A
        sibling answering anyway is a routing miss rather than a failure, and
        asking again is what resolves it; a second sibling is where this stops.

        NVIDIA's own tokens are not checked here. What this establishes is that
        the GPU evidence was produced by the machine holding the key the prompt
        is sealed to.
        """
        verifier = quote_verifier or default_quote_verifier
        now = int(time.time())
        query = urlencode({"model": model, "keyset_digest": enclave.digest})
        for attempt in (1, 2):
            evidence = _public_json(f"{base}/v1/gpu-evidence?{query}", "gpu_evidence_unavailable",
                                    ConfidentialError)
            payload = evidence.get("nvidia_payload")
            if not isinstance(payload, str):
                raise ConfidentialError(502, "gpu_unverified",
                                        {"cause": "the GPU evidence carries no NVIDIA attestation payload"})
            if not isinstance(evidence.get("intel_quote"), str):
                raise ConfidentialError(502, "gpu_unverified",
                                        {"cause": "the GPU evidence carries no CPU quote to bind against"})
            quote = verify_raw_quote(evidence["intel_quote"], verifier, now)
            if not quote.ok:
                raise ConfidentialError(502, "gpu_unverified", {
                    "cause": f"the GPU evidence's own quote did not verify: {quote.detail}"})
            tie = same_td(enclave.report, quote.report)
            if tie.ok:
                break
            if attempt == 2:
                raise ConfidentialError(502, "gpu_unverified", {
                    "cause": f"the GPU evidence's quote comes from a different TD: {tie.detail} do not "
                             "match the workload's quote",
                })

        try:
            nonce = json.loads(payload).get("nonce")
        except ValueError:
            nonce = None
        if not isinstance(nonce, str):
            raise ConfidentialError(502, "gpu_unverified",
                                    {"cause": "the NVIDIA attestation payload carries no nonce"})
        gate = gate_gpu_binding(quote.report.report_data.hex(), evidence.get("signing_address"), nonce)
        if not gate.ok:
            raise ConfidentialError(502, "gpu_unverified", {"cause": gate.detail})
        return {"signing_address": evidence.get("signing_address"), "nonce": nonce,
                "mr_td": quote.report.mr_td.hex(), "rtmr3": quote.report.rt_mr3.hex(),
                "nras": "NVIDIA's tokens are not checked by this SDK"}

    def _receipt(self, base: str, receipt_id: str):
        try:
            return _public_json(f"{base}/v1/receipts/{urlquote(receipt_id, safe='')}", "receipt_unavailable")
        except PrismError:
            # The generation is paid for and delivered; a receipt that cannot be
            # fetched right now is a verification the caller loses, not a
            # failure of the call.
            return None


def _sealer(body: dict, keyset: dict) -> Callable:
    """Seals one attempt's envelope. A key set the quote committed to but whose
    published suites this client does not speak is an enclave the call never
    established, and it is reported as one rather than as the low-level protocol
    error: everything ahead of the prompt leaving either works or raises
    :class:`ConfidentialError`."""
    def seal() -> SealedRequest:
        try:
            return encrypt_chat_request(body, keyset)
        except E2eeError as e:
            raise ConfidentialError(502, "e2ee_unavailable",
                                    {"cause": str(e), "hint": "no prompt left this process"}) from e

    return seal


def _attestation(enclave: Enclave | None) -> dict:
    if enclave is None:
        return {"verified": False,
                "reason": "end-to-end encryption was off, so nothing was checked before the prompt was sent"}
    return {
        "verified": True,
        "workload": enclave.provenance,
        "keyset_digest": enclave.digest,
        "rtmr3": enclave.rtmr3.hex(),
        "quote_status": enclave.quote_status,
    }


def _decrypt_answer(served: Served, receipt_id) -> dict:
    """A sealed answer, or an error that names the reason it did not open. The
    service marks an encrypted answer with ``x-e2ee-applied``, and a plaintext
    one fails the AEAD for a reason that has nothing to do with the key."""
    applied = served.headers.get("x-e2ee-applied")
    paid_for = f"the generation is paid for, and receipt {receipt_id} still verifies what the workload served"
    if applied is not None and str(applied).lower() != "true":
        raise ConfidentialError(502, "e2ee_not_applied", {
            "cause": f"the endpoint answered with x-e2ee-applied: {applied}",
            "hint": f"the enclave returned the answer unencrypted; {paid_for}",
        })
    try:
        return decrypt_response(served.content, served.sent.client_key)
    except Exception as e:
        if applied is not None:
            raise ConfidentialError(502, "e2ee_not_opened", {"cause": str(e), "hint": paid_for}) from e
        raise ConfidentialError(502, "e2ee_not_applied", {
            "cause": str(e),
            "hint": "the endpoint marked no answer as encrypted and this one did not open under this "
                    f"call's key; {paid_for}",
        }) from e


def _answer_json(served: Served):
    """The body of a served answer, as JSON.

    A 200 carrying something that is not JSON at all is the one shape there is
    no answer to hand back, so it is named rather than left to a decoder's
    exception. What the JSON turned out to be is the caller's problem, and
    :func:`_completion` reads it the way the Node SDK does.
    """
    try:
        return json.loads(served.content.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise PaymentError(502, "malformed_answer", {
            "cause": str(e),
            "hint": f"the generation is paid for (tx {served.tx}) and the endpoint answered with "
                    f"{len(served.content)} bytes that are not JSON",
        }, served.tx) from e


def _completion(answer):
    """The generated text, or ``None`` where the answer holds none.

    An endpoint that answers 200 with an error object, a bare string, or a
    completion with no choices has still been paid, so the caller gets the
    answer it bought under ``response`` and a null text, which is the shape the
    Node SDK returns for the same body.
    """
    choices = _mapping(answer).get("choices")
    first = _mapping(choices[0]) if isinstance(choices, list) and choices else {}
    return _mapping(first.get("message")).get("content")


def _one_prompt(prompt, messages) -> str:
    """The open tier takes one prompt string. A chat list is flattened for it,
    labelled by role so a model can still tell the turns apart."""
    if isinstance(prompt, str) and prompt.strip():
        return prompt
    if isinstance(messages, list) and messages:
        if len(messages) == 1 and isinstance(messages[0].get("content"), str):
            return messages[0]["content"]
        turns = [f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages]
        return "\n\n".join(turns)
    raise PrismError(400, "prompt_required", {"hint": "pass a prompt string or a messages list"})


def _within_cap(price: int, max_usdg: float) -> None:
    cap = round(float(max_usdg) * 1e6)
    if price <= 0 or price > cap:
        raise PaymentError(402, "cost_exceeds_max", {"required": str(price), "max": str(cap)})


def _as_bytes(body) -> bytes:
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    return _compact(body)


def _number(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
