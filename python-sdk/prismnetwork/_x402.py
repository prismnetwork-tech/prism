"""What a payer signs on Prism's legacy x402 rail.

The transfer is already on chain by the time the header is sent, so the header
only says who made it. Signing the transaction hash alone proves who paid and
not what for: anyone who read the header in flight could put their own command
in front of it and spend someone else's transfer. The request travels inside the
signed message, and the endpoint checks it against the request that arrived.

This is the construction the Node SDK signs in ``sdk/x402.mjs``, and
``tests/test_x402.py`` holds the two against each other.
"""

from __future__ import annotations

import base64
import hashlib
import json

from eth_account.messages import encode_defunct


def hash_request(payload) -> str:
    """The digest both sides compare: the command for a job, the request bytes
    for a generation. Text is hashed as UTF-8, which is how it goes on the wire."""
    data = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    return hashlib.sha256(data).hexdigest()


def bound_message(tx_hash: str, request_hash: str) -> str:
    return f"prism-x402:v2\n{str(tx_hash).lower()}\n{request_hash}"


def payment_header(account, tx_hash: str, body, network: str | None = None) -> str:
    """The ``X-PAYMENT`` value for one paid request: the transfer that funded it,
    and a signature over that transfer together with the exact bytes being sent.

    ``body`` has to be the bytes the request actually carries. Re-encoding a dict
    here would sign something the endpoint never receives.
    """
    signed = account.sign_message(encode_defunct(text=bound_message(tx_hash, hash_request(body))))
    signature = signed.signature.hex()
    envelope = {
        "txHash": tx_hash,
        "signature": signature if signature.startswith("0x") else "0x" + signature,
    }
    if network:
        envelope["network"] = network
    return base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8")).decode("ascii")
