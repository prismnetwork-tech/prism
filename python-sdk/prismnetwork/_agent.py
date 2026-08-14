from __future__ import annotations

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
                 api_base: str = "https://prismnetwork.tech", rpc_url: str = ROBINHOOD_RPC):
        if not escrow:
            raise ValueError("escrow address is required")
        self.api_base = api_base.rstrip("/")
        self.escrow = Web3.to_checksum_address(escrow)
        self.account = Account.from_key(private_key)
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self._usdg = self.w3.eth.contract(address=USDG, abi=_ERC20)
        self._escrow = self.w3.eth.contract(address=self.escrow, abi=_ESCROW)
        self.session: str | None = None

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
        while time.time() < deadline:
            status, body = self._proxy("GET", ["leases", str(lease_id), "result"], raw=True)
            if status == 200:
                return body
            if status != 404:
                raise PrismError(status, (body or {}).get("code", "result_failed"), body)
            time.sleep(interval)
        raise PrismError(408, "result_timeout")

    def wait_for_access(self, lease_id, timeout: int = 600, interval: int = 10) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status, body = self._proxy("GET", ["leases", str(lease_id), "access"], raw=True)
            if status == 200:
                return body
            if status != 404:
                raise PrismError(status, (body or {}).get("error", "access_error"))
            time.sleep(interval)
        raise PrismError(408, "access_timeout")

    def lease(self, image: str, duration_seconds: int, min_vram_mib: int = 16000,
              preferred_node_id: str | None = None, max_deposit: int | None = None,
              min_trust_class: str = "open", command: str | None = None) -> Lease | BatchLease:
        if not self.session:
            self.authenticate()
        quote = self.quote(image, duration_seconds, min_vram_mib, preferred_node_id,
                           min_trust_class, command)
        if max_deposit is not None and int(quote["maximum_escrow"]) > int(max_deposit):
            raise PrismError(402, "cost_exceeds_max",
                             {"required": quote["maximum_escrow"], "max": str(max_deposit)})
        key = self._generate_ssh_key()
        try:
            funding = self._fund(quote)
            record = self.confirm(quote["quote_id"], funding, key["public_key"])
            lease_id = record["lease_id"]
            # A batch lease never hands out access, so waiting for it would block
            # until the timeout and then report a failure that never happened.
            # Wait for what the command printed instead.
            if command is not None:
                result = self.wait_for_result(lease_id)
                shutil.rmtree(key["dir"], ignore_errors=True)
                return BatchLease(lease_id, result, funding, quote)
            return Lease(lease_id, self.wait_for_access(lease_id),
                         key["key_path"], key["dir"], key["public_key"], funding, quote)
        except Exception:
            shutil.rmtree(key["dir"], ignore_errors=True)
            raise

    def run(self, lease: Lease, command: str, timeout: int = 120,
            connect_retries: int = 24, connect_delay: int = 10) -> dict:
        a = lease.access
        args = ["ssh", "-i", lease.key_path, "-p", str(a["ssh_port"]),
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                f"{a.get('ssh_user', 'root')}@{a['ssh_host']}", command]
        last = None
        for attempt in range(connect_retries + 1):
            try:
                p = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 20)
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
        receipt = self.w3.eth.wait_for_transaction_receipt(h)
        if receipt.status != 1:
            raise PrismError(402, "tx_reverted", {"hash": h.hex()})
        if confirmations > 1:
            target = receipt.blockNumber + confirmations - 1
            while self.w3.eth.block_number < target:
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


def _is_ssh_warmup(res: dict) -> bool:
    if res["code"] != 255:
        return False
    e = res["stderr"]
    return (e.startswith("ssh: ") or "\nssh: " in e
            or "kex_exchange_identification" in e or "Connection reset by peer" in e
            or ("Permission denied (publickey" in e and res["stdout"] == ""))
