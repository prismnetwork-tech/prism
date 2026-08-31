"""What a renter's client does about the machine on the other end of a lease."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

from prismnetwork import PrismError, host_key_policy
from prismnetwork._agent import _host_key_args, _known_hosts_fingerprint, _known_hosts_path

SSHD = "/usr/sbin/sshd"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def reachable(port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.2)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def generate_key(directory: str, name: str) -> tuple:
    path = os.path.join(directory, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path], check=True)
    listed = subprocess.run(["ssh-keygen", "-lf", path + ".pub"], capture_output=True, text=True, check=True)
    return path, listed.stdout.split()[1]


def serve_sshd(directory: str, host_key: str, port: int):
    """A real sshd, because what is being tested is whether the key the network
    named is the key the machine actually offers. Nothing logs in: ssh-keyscan
    reads the host key out of the exchange and hangs up."""
    config = os.path.join(directory, "sshd_config")
    with open(config, "w") as handle:
        handle.write(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {host_key}\n"
                     "PasswordAuthentication no\nStrictModes no\n")
    child = subprocess.Popen([SSHD, "-D", "-e", "-f", config],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if reachable(port):
            return child
        time.sleep(0.1)
    child.kill()
    raise AssertionError("sshd did not come up")


def stop(child):
    child.kill()
    child.wait()


class HostKeyTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="prism-hostkey-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.key_path = os.path.join(self.dir, "id_ed25519")
        open(self.key_path, "w").close()
        self.known = _known_hosts_path(self.key_path)

    @unittest.skipUnless(os.path.exists(SSHD), "no sshd to serve a host key")
    def test_a_published_fingerprint_is_checked_against_the_machine_that_answers(self):
        served, fingerprint = generate_key(self.dir, "served")
        port = free_port()
        sshd = serve_sshd(self.dir, served, port)
        self.addCleanup(stop, sshd)

        args = _host_key_args("127.0.0.1", port, self.key_path,
                              {"channel_key_fingerprint": fingerprint, "channel_key_source": "node_report"},
                              False)
        self.assertEqual(args, ["-o", f"UserKnownHostsFile={self.known}", "-o", "StrictHostKeyChecking=yes"])
        with open(self.known) as handle:
            recorded = handle.read().strip().splitlines()
        self.assertEqual(len(recorded), 1, "only the key that was checked is recorded")
        self.assertEqual(recorded[0].split()[0], f"[127.0.0.1]:{port}")
        self.assertEqual(_known_hosts_fingerprint(recorded[0]), fingerprint)

        # A grant naming a key the machine does not hold has to fail before
        # anything is sent to it.
        os.remove(self.known)
        _, other = generate_key(self.dir, "other")
        with self.assertRaises(PrismError) as caught:
            _host_key_args("127.0.0.1", port, self.key_path, {"channel_key_fingerprint": other}, False)
        self.assertEqual(caught.exception.code, "host_key_mismatch")
        self.assertEqual(caught.exception.body["offered"], [fingerprint])
        self.assertFalse(os.path.exists(self.known), "a machine that failed the check is not recorded")

    def test_an_unreachable_box_reads_as_a_wait_rather_than_a_wrong_machine(self):
        with self.assertRaises(PrismError) as caught:
            _host_key_args("127.0.0.1", free_port(), self.key_path,
                           {"channel_key_fingerprint": "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"},
                           False)
        self.assertEqual(caught.exception.code, "host_key_unavailable")

    def test_a_lease_that_publishes_no_key_is_pinned_on_first_sight_or_refused(self):
        args = _host_key_args("127.0.0.1", 2222, self.key_path, {"mode": "direct_ssh"}, False)
        self.assertEqual(args, ["-o", f"UserKnownHostsFile={self.known}",
                                "-o", "StrictHostKeyChecking=accept-new"])
        self.assertNotIn("StrictHostKeyChecking=no", args)
        self.assertNotIn("UserKnownHostsFile=/dev/null", args)

        with self.assertRaises(PrismError) as caught:
            _host_key_args("127.0.0.1", 2222, self.key_path, {"mode": "direct_ssh"}, True)
        self.assertEqual(caught.exception.code, "host_key_unpublished")

    def test_the_grant_says_which_claim_it_is_making_about_the_host_key(self):
        attested = {"channel_key_fingerprint": "SHA256:a", "channel_key_source": "snp_report"}
        reported = {"channel_key_fingerprint": "SHA256:a", "channel_key_source": "node_report"}
        self.assertEqual(host_key_policy(attested),
                         {"mode": "attested", "fingerprint": "SHA256:a", "source": "snp_report"})
        self.assertEqual(host_key_policy(reported),
                         {"mode": "reported", "fingerprint": "SHA256:a", "source": "node_report"})
        self.assertEqual(host_key_policy({"mode": "direct_ssh"}),
                         {"mode": "unverified", "fingerprint": None, "source": None})
        self.assertEqual(host_key_policy(None),
                         {"mode": "unverified", "fingerprint": None, "source": None})


if __name__ == "__main__":
    unittest.main()
