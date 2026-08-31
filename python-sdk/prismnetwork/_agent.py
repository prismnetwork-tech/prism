from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass

from urllib.parse import urlencode

import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

ROBINHOOD_RPC = "https://rpc.mainnet.chain.robinhood.com"
CHAIN_ID = 4663
USDG = Web3.to_checksum_address("0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168")

# A digest-pinned image, matching the Node SDK so a default can't drift.
DEFAULT_IMAGE = "docker.io/ollama/ollama@sha256:a61a8fd395dbb931cc8cb1b5da7a2510746575c87113fdc45b647ee59ef7f808"

# Weakest to strongest. "open" means the supplier can read everything the
# workload touches, so raise it for anything sensitive.
TRUST_CLASSES = ("open", "isolated", "attested", "confidential")

CONFIRMATIONS = 12
FETCH_TIMEOUT = 30

_ERC20 = [
    {"name": "approve", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "spender", "type": "address"}, {"name": "value", "type": "uint256"}],
     "outputs": [{"type": "bool"}]},
    {"name": "allowance", "type": "function", "stateMutability": "view",
     "inputs": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}],
     "outputs": [{"type": "uint256"}]},
    {"name": "balanceOf", "type": "function", "stateMutability": "view",
     "inputs": [{"name": "owner", "type": "address"}], "outputs": [{"type": "uint256"}]},
]
_ESCROW = [
    {"name": "createLease", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "nodeId", "type": "bytes32"}, {"name": "duration", "type": "uint32"},
                {"name": "clientReference", "type": "bytes32"}],
     "outputs": [{"type": "uint256"}]},
]

_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")

# Matches the limit the control plane and the node both enforce, so a command
# that cannot run is rejected here rather than after an escrow is funded.
MAX_COMMAND_BYTES = 8 * 1024


def _command(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PrismError(400, "invalid_command", {"hint": "a batch command cannot be empty"})
    if len(value.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise PrismError(400, "invalid_command", {"hint": "a batch command cannot exceed 8 KiB"})
    return value


def _trust_class(value: str) -> str:
    if value not in TRUST_CLASSES:
        raise PrismError(400, "invalid_trust_class", {"expected": list(TRUST_CLASSES)})
    return value


class PrismError(Exception):
    def __init__(self, status: int, code: str, body=None):
        super().__init__(f"prism {status}: {code}")
        self.status = status
        self.code = code
        self.body = body


@dataclass
class Lease:
    lease_id: int
    access: dict
    key_path: str
    key_dir: str
    public_key: str
    funding_hash: str
    quote: dict


@dataclass
class BatchLease:
    """A lease that carried a command. There is no access to wait for; the node
    runs the command and reports its output, which is all a renter receives."""

    lease_id: int
    result: dict
    funding_hash: str
    quote: dict


class PrismAgent:
    """Headless GPU leasing for a wallet-holding agent. Authenticate with a wallet
    signature, pay on-chain in USDG, provision, and run over SSH."""

    def __init__(self, private_key: str, escrow: str,
                 api_base: str = "https://prismnetwork.tech", rpc_url: str = ROBINHOOD_RPC,
                 require_host_key: bool = False):
        if not escrow:
            raise ValueError("escrow address is required")
        if not isinstance(private_key, str) or not private_key.strip():
            raise ValueError("private_key is required: a 32-byte hex key, with or without 0x "
                             "(most surfaces read it from PRISM_AGENT_KEY)")
        self.api_base = api_base.rstrip("/")
        self.escrow = Web3.to_checksum_address(escrow)
        try:
            self.account = Account.from_key(private_key.strip())
        except Exception as e:
            raise ValueError(f"private_key is not a valid key: {e}. Expected 32 bytes of hex, "
                             "with or without the 0x prefix.") from e
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self._usdg = self.w3.eth.contract(address=USDG, abi=_ERC20)
        self._escrow = self.w3.eth.contract(address=self.escrow, abi=_ESCROW)
        self.session: str | None = None
        # Off by default because most capacity publishes no host key, and
        # refusing those leases would take the network's own supply away from
        # callers who never asked for the guarantee. On, nothing runs anywhere
        # the grant cannot name.
        self.require_host_key = require_host_key

    @property
    def address(self) -> str:
        return self.account.address

    def authenticate(self) -> dict:
        challenge = self._json("GET", f"/api/agent/challenge?address={self.address}")
        signed = self.account.sign_message(encode_defunct(text=challenge["message"]))
        sig = signed.signature.hex()
        session = self._json("POST", "/api/agent/session", {
            "challenge": challenge["challenge"],
            "address": self.address,
            "signature": sig if sig.startswith("0x") else "0x" + sig,
        })
        self.session = session["session"]
        return session

    def offers(self, min_trust: str = "open") -> list:
        return self._proxy("GET", ["offers"], query={"min_trust": _trust_class(min_trust)})

    def balances(self) -> dict:
        return {
            "address": self.address,
            "usdg": self._usdg.functions.balanceOf(self.address).call(),
            "eth": self.w3.eth.get_balance(self.address),
        }

    def quote(self, image: str, duration_seconds: int, min_vram_mib: int = 16000,
              preferred_node_id: str | None = None, min_trust_class: str = "open",
              command: str | None = None) -> dict:
        if not isinstance(image, str) or not _DIGEST.search(image):
            raise PrismError(400, "image_must_be_digest_pinned")
        request = {
            "image": image,
            "duration_seconds": duration_seconds,
            "min_vram_mib": min_vram_mib,
            "preferred_node_id": preferred_node_id,
            "min_trust_class": _trust_class(min_trust_class),
        }
        if command is not None:
            request["command"] = _command(command)
        return self._proxy("POST", ["leases", "match"], {"request": request})

    def confirm(self, quote_id: str, transaction_hash: str, ssh_authorized_key: str) -> dict:
        return self._proxy("POST", ["leases", "confirm"], {
            "quote_id": quote_id,
            "transaction_hash": transaction_hash,
            "ssh_authorized_key": ssh_authorized_key,
        })

    def leases(self) -> list:
        return self._proxy("GET", ["leases"])

    def access(self, lease_id) -> dict:
        return self._proxy("GET", ["leases", str(lease_id), "access"])

    def result(self, lease_id) -> dict:
        """The output of a batch lease, once its node has reported."""
        return self._proxy("GET", ["leases", str(lease_id), "result"])

    def wait_for_result(self, lease_id, timeout: int = 900, interval: int = 10) -> dict:
        deadline = time.time() + timeout
        checked = 0
        while time.time() < deadline:
            status, body = self._proxy("GET", ["leases", str(lease_id), "result"], raw=True)
            if status == 200:
                return body
            # The control plane keeps answering 404 for a batch whose node died
            # without reporting, so a 404 alone cannot distinguish "still
            # running" from "never coming". Check the lease state occasionally
            # and stop waiting once it is terminal.
            if status == 404:
                checked += 1
                if checked % 6 == 0 and (state := self._terminal_state(lease_id)):
                    status2, body2 = self._proxy("GET", ["leases", str(lease_id), "result"], raw=True)
                    if status2 == 200:
                        return body2
                    raise PrismError(502, "batch_no_result", {"lease_id": lease_id, "state": state})
            elif status != 429 and status < 500:
                raise PrismError(status, (body or {}).get("code", "result_failed"), body)
            time.sleep(interval)
        raise PrismError(408, "result_timeout", {"lease_id": lease_id})

    def _terminal_state(self, lease_id) -> str | None:
        try:
            leases = self.leases()
        except PrismError:
            return None
        for lease in leases:
            if lease.get("lease_id") == lease_id:
                state = lease.get("state", "")
                if state in ("closing", "settlement_pending", "finalized", "refunded", "failed"):
                    return state
                return None
        return None

    def wait_for_access(self, lease_id, timeout: int = 600, interval: int = 10) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status, body = self._proxy("GET", ["leases", str(lease_id), "access"], raw=True)
            if status == 200:
                return body
            # 429 and 5xx are transient (proxy rate limit, control-plane blip);
            # aborting a paid wait on one would strand the deposit.
            if status != 404 and status != 429 and status < 500:
                raise PrismError(status, (body or {}).get("error", "access_error"), body)
            time.sleep(interval)
        raise PrismError(408, "access_timeout", {"lease_id": lease_id})

    def lease(self, image: str, duration_seconds: int, min_vram_mib: int = 16000,
              preferred_node_id: str | None = None, max_deposit: int | None = None,
              min_trust_class: str = "open", command: str | None = None) -> Lease | BatchLease:
        if not self.session:
            self.authenticate()
        # A wallet with no balance at all cannot fund anything, and a doomed
        # quote still holds capacity against other renters until it expires.
        # Refuse before quoting.
        b = self.balances()
        if int(b["usdg"]) == 0 or int(b["eth"]) == 0:
            raise PrismError(402, "wallet_unfunded", {
                "address": self.address, "usdg": int(b["usdg"]), "eth_wei": int(b["eth"]),
                "hint": "the wallet needs USDG for the deposit and native ETH for gas "
                        "on Robinhood Chain (id 4663) before it can lease",
            })
        quote = self.quote(image, duration_seconds, min_vram_mib, preferred_node_id,
                           min_trust_class, command)
        if max_deposit is not None and int(quote["maximum_escrow"]) > int(max_deposit):
            raise PrismError(402, "cost_exceeds_max",
                             {"required": quote["maximum_escrow"], "max": str(max_deposit)})
        key = self._generate_ssh_key()
        funding = None
        lease_id = None
        try:
            funding = self._fund(quote)
            record = self.confirm(quote["quote_id"], funding, key["public_key"])
            lease_id = record.get("lease_id")
            if not isinstance(lease_id, int):
                raise PrismError(502, "malformed_lease_record", {"funding_hash": funding})
            # A batch lease never hands out access, so waiting for it would block
            # until the timeout and then report a failure that never happened.
            # Wait for what the command printed instead.
            if command is not None:
                result = self.wait_for_result(lease_id, timeout=duration_seconds + 900)
                shutil.rmtree(key["dir"], ignore_errors=True)
                return BatchLease(lease_id, result, funding, quote)
            return Lease(lease_id, self.wait_for_access(lease_id),
                         key["key_path"], key["dir"], key["public_key"], funding, quote)
        except Exception as e:
            # Before funding, the key opens nothing; discard it. After funding
            # it is the only way into a machine that is being paid for, so it
            # stays on disk and the error says where everything is.
            if funding is None:
                shutil.rmtree(key["dir"], ignore_errors=True)
                raise
            detail = {"funding_hash": funding, "lease_id": lease_id, "key_path": key["key_path"]}
            if isinstance(e, PrismError):
                e.body = {**(e.body or {}), **detail}
                raise
            raise PrismError(502, "lease_failed_after_funding", {**detail, "cause": str(e)}) from e

    def run(self, lease: Lease, command: str, timeout: int = 120,
            connect_retries: int = 24, connect_delay: int = 10,
            stdin: str | None = None) -> dict:
        a = lease.access
        # Physical nodes hand out gateway access, which has no ssh endpoint.
        # Fail as a PrismError rather than a KeyError so callers holding a paid
        # lease see what they are dealing with.
        if not a.get("ssh_host") or not a.get("ssh_port"):
            raise PrismError(400, "ssh_access_unavailable",
                             {"mode": a.get("mode"), "lease_id": lease.lease_id})
        last = None
        for attempt in range(connect_retries + 1):
            try:
                host_key = _host_key_args(a["ssh_host"], a["ssh_port"], lease.key_path, a,
                                          self.require_host_key)
            except PrismError as e:
                # A box that is still coming up has nothing listening to read a
                # key from, which is the same wait this loop already exists for.
                # Being answered by the wrong machine is not a wait.
                if e.code != "host_key_unavailable":
                    raise
                res = {"code": 255, "stdout": "", "stderr": f"ssh: {e.code}"}
            else:
                args = ["ssh", "-i", lease.key_path, "-p", str(a["ssh_port"]), *host_key,
                        "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                        f"{a.get('ssh_user', 'root')}@{a['ssh_host']}", command]
                try:
                    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 20,
                                       input=stdin if stdin is not None else "")
                    res = {"code": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
                except subprocess.TimeoutExpired:
                    res = {"code": -1, "stdout": "", "stderr": "timed out"}
            if not _is_ssh_warmup(res):
                return res
            last = res
            if attempt < connect_retries:
                time.sleep(connect_delay)
        return last

    def end_lease(self, lease: Lease) -> None:
        """Release local key material. The on-chain lease settles at the end of its duration."""
        if lease and lease.key_dir:
            shutil.rmtree(lease.key_dir, ignore_errors=True)

    def _fund(self, quote: dict) -> str:
        deposit = int(quote["maximum_escrow"])
        duration = int(quote["duration_seconds"])
        client_ref = Web3.keccak(text=quote["quote_id"])
        node_id = bytes.fromhex(quote["node_id"].removeprefix("0x"))
        allowance = self._usdg.functions.allowance(self.address, self.escrow).call()
        if allowance < deposit:
            self._send(self._usdg.functions.approve(self.escrow, deposit))
        return self._send(self._escrow.functions.createLease(node_id, duration, client_ref),
                          confirmations=CONFIRMATIONS)

    def _send(self, call, confirmations: int = 1) -> str:
        tx = call.build_transaction({
            "from": self.address,
            "nonce": self.w3.eth.get_transaction_count(self.address),
            "chainId": CHAIN_ID,
        })
        signed = self.account.sign_transaction(tx)
        h = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        # Once broadcast, the hash is the one thing the caller must not lose.
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(h, timeout=180)
        except Exception as e:
            raise PrismError(504, "confirmation_timeout",
                             {"hash": h.hex(), "cause": str(e)}) from e
        if receipt.status != 1:
            raise PrismError(402, "tx_reverted", {"hash": h.hex()})
        if confirmations > 1:
            target = receipt.blockNumber + confirmations - 1
            deadline = time.time() + 180
            while self.w3.eth.block_number < target:
                if time.time() > deadline:
                    raise PrismError(504, "confirmation_timeout", {"hash": h.hex()})
                time.sleep(2)
        return h.hex()

    def _proxy(self, method: str, segments: list, body=None, raw: bool = False,
               reauthed: bool = False, query: dict | None = None):
        if not self.session:
            self.authenticate()
        search = f"?{urlencode(query)}" if query else ""
        res = self._request(f"/api/agent/proxy/{'/'.join(segments)}{search}", method, body,
                            {"authorization": f"Bearer {self.session}"})
        if res.status_code == 401 and not reauthed:
            self.session = None
            self.authenticate()
            return self._proxy(method, segments, body, raw, True, query)
        if raw:
            return res.status_code, _safe_json(res)
        return self._unwrap(res)

    def _json(self, method: str, path: str, body=None):
        return self._unwrap(self._request(path, method, body))

    def _request(self, path: str, method: str, body=None, headers: dict | None = None):
        try:
            return requests.request(method, f"{self.api_base}{path}",
                                     json=body, headers={"accept": "application/json", **(headers or {})},
                                     timeout=FETCH_TIMEOUT)
        except requests.RequestException as e:
            raise PrismError(504, "control_plane_unreachable", {"cause": str(e)})

    @staticmethod
    def _unwrap(res):
        data = _safe_json(res)
        if not res.ok:
            raise PrismError(res.status_code, (data or {}).get("error") or (data or {}).get("code") or "request_failed", data)
        return data

    def _generate_ssh_key(self) -> dict:
        d = tempfile.mkdtemp(prefix="prism-ssh-")
        try:
            key_path = f"{d}/id_ed25519"
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", key_path, "-C", "prism-agent"],
                           check=True, capture_output=True)
            with open(f"{key_path}.pub") as f:
                return {"dir": d, "key_path": key_path, "public_key": f.read().strip()}
        except Exception as e:
            shutil.rmtree(d, ignore_errors=True)
            raise PrismError(500, "ssh_keygen_failed", {"cause": str(e)})


def _safe_json(res):
    try:
        return res.json()
    except ValueError:
        return None


# Checking which machine answered.
#
# A lease hands the renter an address and a private key. Until the host key on
# the other end is checked, anything that can reach that address can take the
# session, read the work and answer as if it were the GPU. What the network can
# say about that key differs by where the capacity came from, so the decision is
# made here rather than defaulted: a grant that names a fingerprint is checked
# before the session opens, and a grant that names none has its key recorded on
# first sight and held for the rest of the lease. The record lives beside the
# lease's private key and goes when the lease does; the caller's own
# ~/.ssh/known_hosts is never touched.

_SCAN_TIMEOUT = 10


def host_key_policy(access: dict | None) -> dict:
    """What the network is willing to say about the machine behind a grant.

    ``attested`` is the only one that survives a hostile operator: the
    fingerprint comes out of a report the processor signed. ``reported`` is the
    operator's word under their bonded device key, which rules out everyone
    between them and the renter. ``unverified`` means nobody published a key and
    the first connection decides.
    """
    fingerprint = (access or {}).get("channel_key_fingerprint")
    if not fingerprint:
        return {"mode": "unverified", "fingerprint": None, "source": None}
    source = access.get("channel_key_source")
    return {
        "mode": "attested" if source == "snp_report" else "reported",
        "fingerprint": fingerprint,
        "source": source,
    }


def _known_hosts_path(key_path: str) -> str:
    return os.path.join(os.path.dirname(key_path), "known_hosts")


def _known_hosts_fingerprint(line: str) -> str | None:
    """The ``ssh-keygen -lf`` form of the key in a known_hosts line. The control
    plane publishes fingerprints in exactly this form, so the two are compared
    as strings."""
    fields = line.strip().split()
    if len(fields) < 3:
        return None
    try:
        raw = base64.b64decode(fields[2], validate=True)
    except Exception:
        return None
    if not raw:
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def _host_field(host: str, port) -> str:
    return str(host) if int(port) == 22 else f"[{host}]:{port}"


def _already_pinned(path: str, host: str, port, fingerprint: str) -> bool:
    # The relay hands out a fresh local port for every session, so a record that
    # names the right key under the wrong address is a record ssh will refuse to
    # use. Both halves have to match for the scan to be worth skipping.
    try:
        with open(path) as handle:
            lines = handle.read().splitlines()
    except OSError:
        return False
    return any(line.split()[:1] == [_host_field(host, port)]
               and _known_hosts_fingerprint(line) == fingerprint for line in lines if line.strip())


def _pin_host_key(host: str, port, fingerprint: str, path: str) -> None:
    """Read the host key off the wire and record it only if it is the one the
    grant named.

    Done as a separate exchange before ssh runs, because a fingerprint cannot be
    turned into a known_hosts entry without the key itself, and letting ssh learn
    the key first would mean trusting it to find out whether it should have.
    ``ssh-keyscan`` reads the key the server offers and hangs up, so nothing the
    machine could use is sent.
    """
    if _already_pinned(path, host, port, fingerprint):
        return
    try:
        scan = subprocess.run(["ssh-keyscan", "-T", str(_SCAN_TIMEOUT), "-p", str(port), str(host)],
                              capture_output=True, text=True, timeout=_SCAN_TIMEOUT + 5)
        offered = [l for l in scan.stdout.splitlines() if l and not l.startswith("#")]
    except (OSError, subprocess.TimeoutExpired) as e:
        raise PrismError(503, "host_key_unavailable", {"host": host, "port": port, "cause": str(e)}) from e
    if not offered:
        raise PrismError(503, "host_key_unavailable",
                         {"host": host, "port": port, "cause": (scan.stderr or "").strip()[:200]})
    for line in offered:
        if _known_hosts_fingerprint(line) == fingerprint:
            # Only the key that matched. Writing everything the machine offered
            # would pin keys nobody vouched for alongside the one that was
            # checked.
            with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
                handle.write(line + "\n")
            return
    raise PrismError(502, "host_key_mismatch", {
        "expected": fingerprint,
        "offered": [f for f in (_known_hosts_fingerprint(l) for l in offered) if f],
        "hint": "the machine answering is not the one the lease names; nothing was sent to it",
    })


def _host_key_args(host, port, key_path: str, access: dict | None, require_host_key: bool) -> list:
    """The ssh options that make the connection check the machine it reaches."""
    path = _known_hosts_path(key_path)
    policy = host_key_policy(access)
    if policy["fingerprint"] is None:
        if require_host_key:
            raise PrismError(400, "host_key_unpublished", {
                "mode": (access or {}).get("mode"),
                "hint": "this lease publishes no host key, so which machine answers cannot be checked",
            })
        return ["-o", f"UserKnownHostsFile={path}", "-o", "StrictHostKeyChecking=accept-new"]
    _pin_host_key(host, port, policy["fingerprint"], path)
    return ["-o", f"UserKnownHostsFile={path}", "-o", "StrictHostKeyChecking=yes"]


def _is_ssh_warmup(res: dict) -> bool:
    if res["code"] != 255:
        return False
    e = res["stderr"]
    return (e.startswith("ssh: ") or "\nssh: " in e
            or "kex_exchange_identification" in e or "Connection reset by peer" in e
            or ("Permission denied (publickey" in e and res["stdout"] == ""))
