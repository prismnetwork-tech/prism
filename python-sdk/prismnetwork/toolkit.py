"""A framework-neutral tool surface over :class:`PrismAgent`.

Agent frameworks disagree about how a tool is declared but agree about what one
is: a named function with typed arguments that returns text. ``PrismToolset``
holds the wallet, the open leases, and the per-lease spending cap in one place
so the LangChain, CrewAI and AutoGen adapters stay thin wrappers instead of
three diverging copies of the same logic.

Every method returns a string, including on failure. These tools are driven by
language models, and a model can act on "the lease could not be funded: the
wallet holds 0 USDG" where a traceback ends the conversation. Without a wallet
the read-only questions still answer from the public API.
"""

from __future__ import annotations

import atexit
import os
import shutil

import requests

from ._agent import DEFAULT_IMAGE, MAX_COMMAND_BYTES, TRUST_CLASSES, Lease, PrismAgent, PrismError

DEFAULT_ESCROW = "0x62C042265991bEa17B07229322A01850974626dA"
PUBLIC_API = "https://api.prismnetwork.tech"

NO_WALLET = (
    "No wallet is configured, so this needs PRISM_AGENT_KEY (a funded wallet on "
    "Robinhood Chain). Looking at capacity and prices works without one."
)

_MICROS = 1_000_000


def _usdg(micros) -> str:
    return f"{int(micros) / _MICROS:.6f} USDG"


def agent_from_env() -> PrismAgent | None:
    key = os.environ.get("PRISM_AGENT_KEY", "").strip()
    if not key:
        return None
    return PrismAgent(
        key,
        os.environ.get("PRISM_ESCROW", DEFAULT_ESCROW),
        api_base=os.environ.get("PRISM_API_BASE", "https://prismnetwork.tech"),
        rpc_url=os.environ.get("PRISM_RPC_URL", "https://rpc.mainnet.chain.robinhood.com"),
    )


def _describe(e: Exception) -> str:
    if isinstance(e, PrismError):
        body = e.body or {}
        if e.code == "cost_exceeds_max":
            return (f"the quote needs {_usdg(body.get('required', 0))} but the cap is "
                    f"{_usdg(body.get('max', 0))}; raise max_usdg or shorten the lease")
        if e.code == "wallet_unfunded":
            return (f"wallet {body.get('address')} holds {_usdg(body.get('usdg', 0))} and "
                    f"{int(body.get('eth_wei', 0)) / 1e18:.6f} ETH for gas; fund it on "
                    "Robinhood Chain (id 4663) before leasing")
        detail = body.get("cause") or body.get("hint") or body.get("message")
        return f"{e.code}{f' ({detail})' if detail else ''}"
    return str(e)


class PrismToolset:
    """The five Prism tools every framework adapter exposes.

    Leases opened here stay open until ``end_lease`` or process exit (an atexit
    hook discards leftover key material); the on-chain escrow settles at the
    end of its paid window either way.
    """

    _UNSET = object()

    def __init__(self, agent: PrismAgent | None = _UNSET, public_api: str = PUBLIC_API):
        # Passing agent=None means deliberately keyless; leaving it unset reads
        # the environment.
        self.agent = agent_from_env() if agent is PrismToolset._UNSET else agent
        self.public_api = os.environ.get("PRISM_PUBLIC_API", public_api).rstrip("/")
        self._leases: dict[int, Lease] = {}
        atexit.register(self._cleanup)

    def _cleanup(self) -> None:
        for lease in self._leases.values():
            shutil.rmtree(lease.key_dir, ignore_errors=True)
        self._leases.clear()

    def wallet(self) -> str:
        """Show the Prism wallet address and its USDG and gas balances on Robinhood Chain."""
        if self.agent is None:
            return NO_WALLET
        try:
            b = self.agent.balances()
        except Exception as e:
            return f"The balance check failed: {_describe(e)}"
        return (
            f"address: {b['address']}\n"
            f"usdg: {_usdg(b['usdg'])}\n"
            f"eth: {int(b['eth']) / 1e18:.6f} for gas"
        )

    def list_gpus(self, min_trust_class: str = "open") -> str:
        """List GPUs available to rent right now: model, VRAM, price per hour, trust class.

        Trust class runs open < isolated < attested < confidential. On an 'open'
        supplier the host operator can read anything the workload touches.
        """
        if min_trust_class not in TRUST_CLASSES:
            return f"min_trust_class must be one of {', '.join(TRUST_CLASSES)}."
        try:
            if self.agent is not None:
                offers = self.agent.offers(min_trust=min_trust_class)
            else:
                res = requests.get(f"{self.public_api}/v1/offers",
                                   params={"min_trust": min_trust_class},
                                   headers={"accept": "application/json"}, timeout=10)
                res.raise_for_status()
                offers = res.json()
        except Exception as e:
            return f"Prism capacity is unreachable right now: {_describe(e)}"
        if not isinstance(offers, list):
            return "Prism capacity answered in an unexpected shape; try again shortly."
        if not offers:
            return f"No GPUs at trust class '{min_trust_class}' or above are online right now."
        rows = []
        for o in offers:
            gpu = o.get("gpu", {})
            per_hr = int(o.get("rate_per_second", 0)) * 3600 / _MICROS
            row = (f"{gpu.get('model', 'GPU')} · {gpu.get('vram_mib', '?')} MiB · "
                   f"{per_hr:.2f} USDG/hr · {o.get('trust_class', 'open')}")
            if o.get("staker_only"):
                row += " · stakers only"
            rows.append(row)
        return "\n".join(rows)

    def lease_and_run(
        self,
        command: str,
        duration_seconds: int = 600,
        min_vram_mib: int = 16000,
        image: str = DEFAULT_IMAGE,
        max_usdg: float = 1.0,
        min_trust_class: str = "open",
    ) -> str:
        """Rent a GPU, run one shell command on it over SSH, and return the output.

        Funds an on-chain USDG escrow up to max_usdg and blocks while the machine
        provisions, usually one to four minutes. The lease stays open for
        follow-up commands with run(); release it with end_lease().
        """
        if self.agent is None:
            return NO_WALLET
        if not isinstance(command, str) or not command.strip():
            return "command is required: the shell command to run on the GPU, e.g. 'nvidia-smi'."
        if len(command.encode("utf-8")) > MAX_COMMAND_BYTES:
            return (f"command exceeds the {MAX_COMMAND_BYTES // 1024} KiB limit; "
                    "fetch the payload on the box instead of inlining it.")
        if min_trust_class not in TRUST_CLASSES:
            return f"min_trust_class must be one of {', '.join(TRUST_CLASSES)}."
        try:
            lease = self.agent.lease(
                image=image,
                duration_seconds=duration_seconds,
                min_vram_mib=min_vram_mib,
                max_deposit=round(max_usdg * _MICROS),
                min_trust_class=min_trust_class,
            )
        except Exception as e:
            return f"The lease did not go through: {_describe(e)}"
        self._leases[lease.lease_id] = lease
        try:
            res = self.agent.run(lease, command)
        except Exception as e:
            return (
                f"Lease {lease.lease_id} is funded (tx {lease.funding_hash}) but the command "
                f"could not run: {_describe(e)}. The lease stays open; try run({lease.lease_id}, ...) "
                "or release it with end_lease."
            )
        out = res.get("stdout") or res.get("stderr") or ""
        return (
            f"lease {lease.lease_id} funded onchain (tx {lease.funding_hash}), "
            f"exit {res.get('code')}:\n{out}"
        )

    def run(self, lease_id: int, command: str) -> str:
        """Run another shell command on a GPU already leased in this session."""
        if self.agent is None:
            return NO_WALLET
        try:
            lease_id = int(lease_id)
        except (TypeError, ValueError):
            return "lease_id must be a positive integer."
        lease = self._leases.get(lease_id)
        if lease is None:
            return f"No active lease {lease_id} in this session."
        if not isinstance(command, str) or not command.strip():
            return "command is required: the shell command to run on the GPU, e.g. 'nvidia-smi'."
        try:
            res = self.agent.run(lease, command)
        except Exception as e:
            return f"The command could not run on lease {lease_id}: {_describe(e)}"
        return f"exit {res.get('code')}:\n{res.get('stdout') or res.get('stderr') or ''}"

    def end_lease(self, lease_id: int) -> str:
        """Release a leased GPU. The on-chain lease settles when its paid window ends."""
        if self.agent is None:
            return NO_WALLET
        try:
            lease_id = int(lease_id)
        except (TypeError, ValueError):
            return "lease_id must be a positive integer."
        lease = self._leases.pop(lease_id, None)
        if lease is None:
            return f"No active lease {lease_id} in this session."
        self.agent.end_lease(lease)
        return f"released lease {lease_id}"
