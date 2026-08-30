"""The payment binding, and whether this SDK signs the same bytes the Node one does."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct

from prismnetwork import bound_message, hash_request, payment_header

TX = "0x" + "ab" * 32
KEY = "0x" + "33" * 32

# The Node definition these functions are a port of. Absent from an installed
# wheel, present in a checkout, which is where the comparison is worth making.
NODE_MODULE = Path(__file__).resolve().parents[2] / "sdk" / "x402.mjs"

VECTORS = [
    (TX, "nvidia-smi"),
    (TX.upper().replace("0X", "0x"), "nvidia-smi"),
    ("0x" + "0" * 64, ""),
    (TX, '{"model":"llama3.2:3b","prompt":"quelle heure est-il à Paris"}'),
    (TX, "\U0001f680 run it"),
]


def node_says(vectors):
    """What ``sdk/x402.mjs`` produces for the same inputs, out of a real node."""
    script = """
        import { boundMessage, hashRequest } from %s;
        const answers = JSON.parse(process.argv[1]).map(([tx, payload]) => [
          hashRequest(payload),
          boundMessage(tx, hashRequest(payload)),
        ]);
        console.log(JSON.stringify(answers));
    """ % json.dumps(str(NODE_MODULE))
    out = subprocess.run(
        ["node", "--input-type=module", "-e", script, json.dumps(vectors)],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(out.stdout)


class BindingTest(unittest.TestCase):
    def test_digest_is_a_plain_sha256_of_the_bytes_on_the_wire(self):
        self.assertEqual(hash_request("nvidia-smi"), hashlib.sha256(b"nvidia-smi").hexdigest())
        self.assertEqual(hash_request(b"nvidia-smi"), hash_request("nvidia-smi"))
        self.assertEqual(hash_request("café"), hashlib.sha256("café".encode("utf-8")).hexdigest())

    def test_message_names_its_version_the_transaction_and_the_request(self):
        digest = hash_request("nvidia-smi")
        self.assertEqual(bound_message(TX, digest), f"prism-x402:v2\n{TX}\n{digest}")
        # A payer holding a checksummed hash and a server reading a lowercase one
        # have to arrive at the same string.
        self.assertEqual(bound_message(TX.upper().replace("0X", "0x"), digest), bound_message(TX, digest))

    @unittest.skipUnless(shutil.which("node") and NODE_MODULE.exists(), "needs node and a checkout")
    def test_the_two_sdks_sign_the_same_bytes(self):
        mine = [[hash_request(payload), bound_message(tx, hash_request(payload))] for tx, payload in VECTORS]
        self.assertEqual(mine, node_says(VECTORS))

    def test_the_header_a_payer_sends_recovers_that_payer(self):
        account = Account.from_key(KEY)
        body = json.dumps({"model": "llama3.2:3b", "prompt": "hello"}).encode("utf-8")

        envelope = json.loads(base64.b64decode(payment_header(account, TX, body)))
        self.assertEqual(envelope["txHash"], TX)
        self.assertNotIn("network", envelope)

        signer = Account.recover_message(
            encode_defunct(text=bound_message(TX, hash_request(body))), signature=envelope["signature"]
        )
        self.assertEqual(signer, account.address)

        # The replay this closes: the same header sent back with a body of the
        # reader's own choosing.
        swapped = Account.recover_message(
            encode_defunct(text=bound_message(TX, hash_request(b"something else"))),
            signature=envelope["signature"],
        )
        self.assertNotEqual(swapped, account.address)

    def test_a_named_network_travels_with_the_payment(self):
        account = Account.from_key(KEY)
        envelope = json.loads(base64.b64decode(payment_header(account, TX, b"{}", network="eip155:4663")))
        self.assertEqual(envelope["network"], "eip155:4663")


if __name__ == "__main__":
    unittest.main()
