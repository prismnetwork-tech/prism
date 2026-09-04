"""end_lease releases the lease on the network, which is what stops the meter.
Before this the call only deleted key material and an interactive lease billed
for its whole window."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from prismnetwork import PrismAgent, PrismError
from prismnetwork._agent import Lease

KEY = "0x" + "11" * 32
ESCROW = "0x" + "22" * 20


class Answer:
    def __init__(self, status, body):
        self.status_code = status
        self.ok = 200 <= status < 300
        self._body = body

    def json(self):
        return self._body


class ControlPlane:
    def __init__(self, status=202, body=None):
        self.status = status
        self.body = body if body is not None else {"lease_id": 7, "state": "active", "release": "queued"}
        self.calls = []

    def __call__(self, method, url, json=None, headers=None, timeout=None):
        self.calls.append((method, url, json))
        return Answer(self.status, self.body)


def lease(key_dir):
    return Lease(lease_id=7, access={}, key_path=f"{key_dir}/id", key_dir=key_dir,
                 public_key="ssh-ed25519 AAAA", funding_hash="0x" + "ab" * 32, quote={},
                 deposit_micros=0, deposit_source="quote")


class EndLeaseTest(unittest.TestCase):
    def setUp(self):
        self.agent = PrismAgent(KEY, ESCROW)
        self.agent.session = "session"
        self.key_dir = tempfile.mkdtemp(prefix="prism-test-")

    def test_posts_release_then_removes_keys(self):
        cp = ControlPlane()
        with patch("prismnetwork._agent.requests.request", cp):
            out = self.agent.end_lease(lease(self.key_dir))
        method, url, body = cp.calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/api/agent/proxy/leases/7/release"))
        self.assertIsNone(body)
        self.assertEqual(out["release"], "queued")
        self.assertFalse(os.path.exists(self.key_dir))

    def test_already_closed_is_not_an_error(self):
        cp = ControlPlane(200, {"lease_id": 7, "state": "finalized", "release": "already_closed"})
        with patch("prismnetwork._agent.requests.request", cp):
            out = self.agent.end_lease(lease(self.key_dir))
        self.assertEqual(out["release"], "already_closed")

    def test_refused_release_raises_and_still_removes_keys(self):
        cp = ControlPlane(409, {"error": "lease_not_active"})
        with patch("prismnetwork._agent.requests.request", cp):
            with self.assertRaises(PrismError) as raised:
                self.agent.end_lease(lease(self.key_dir))
        self.assertEqual(raised.exception.code, "lease_not_active")
        self.assertFalse(os.path.exists(self.key_dir))

    def test_none_is_a_no_op(self):
        cp = ControlPlane()
        with patch("prismnetwork._agent.requests.request", cp):
            self.assertIsNone(self.agent.end_lease(None))
        self.assertEqual(cp.calls, [])


if __name__ == "__main__":
    unittest.main()
