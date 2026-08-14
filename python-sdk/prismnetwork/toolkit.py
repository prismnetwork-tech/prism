"""A framework-neutral tool surface over :class:`PrismAgent`.

Agent frameworks disagree about how a tool is declared but agree about what one
is: a named function with typed arguments that returns text. ``PrismToolset``
holds the wallet, the open leases, and the spending cap in one place so the
LangChain, CrewAI and AutoGen adapters stay thin wrappers instead of three
diverging copies of the same logic.
"""

from __future__ import annotations

import os

from ._agent import DEFAULT_IMAGE, TRUST_CLASSES, Lease, PrismAgent

DEFAULT_ESCROW = "0x62C042265991bEa17B07229322A01850974626dA"

_MICROS = 1_000_000


def _usdg(micros) -> str:
    return f"{int(micros) / _MICROS:.6f} USDG"


def agent_from_env() -> PrismAgent:
    key = os.environ.get("PRISM_AGENT_KEY")
    if not key:
        raise ValueError("PRISM_AGENT_KEY is required (a funded wallet on Robinhood Chain)")
    return PrismAgent(key, os.environ.get("PRISM_ESCROW", DEFAULT_ESCROW))


class PrismToolset:
    """The five Prism tools every framework adapter exposes.

    Each method takes plain typed arguments and returns a human-readable string.
    Leases opened here stay open until ``end_lease`` or process exit; the
    on-chain escrow settles at the end of its paid window either way.
    """

    def __init__(self, agent: PrismAgent | None = None):
        self.agent = agent or agent_from_env()
        self._leases: dict[int, Lease] = {}

    def wallet(self) -> str:
        """Show the Prism wallet address and its USDG and gas balances on Robinhood Chain."""
        b = self.agent.balances()
        return (
            f"address: {b['address']}\n"
            f"usdg: {_usdg(b['usdg'])}\n"
            f"eth: {int(b['eth']) / 1e18:.6f} for gas"
        )

    def list_gpus(self, min_trust: str = "open") -> str:
        """List GPUs available to rent right now: model, VRAM, price per hour, trust class.

        Trust class runs open < isolated < attested < confidential. On an 'open'
        supplier the host operator can read anything the workload touches.
        """
        if min_trust not in TRUST_CLASSES:
            return f"min_trust must be one of {', '.join(TRUST_CLASSES)}"
        offers = self.agent.offers(min_trust=min_trust)
        if not offers:
            return "No GPUs are online to rent right now."
        rows = []
        for o in offers:
            gpu = o.get("gpu", {})
            per_hr = int(o.get("rate_per_second", 0)) * 3600 / _MICROS
            rows.append(
                f"{gpu.get('model', 'GPU')} · {gpu.get('vram_mib', '?')} MiB · "
                f"${per_hr:.2f}/hr · {o.get('trust_class', 'open')}"
            )
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
        lease = self.agent.lease(
            image=image,
            duration_seconds=duration_seconds,
            min_vram_mib=min_vram_mib,
            max_deposit=int(max_usdg * _MICROS),
            min_trust_class=min_trust_class,
        )
        self._leases[lease.lease_id] = lease
        res = self.agent.run(lease, command)
        out = res.get("stdout") or res.get("stderr") or ""
        return (
            f"lease {lease.lease_id} funded onchain (tx {lease.funding_hash}), "
            f"exit {res.get('code')}:\n{out}"
        )

    def run(self, lease_id: int, command: str) -> str:
        """Run another shell command on a GPU already leased in this session."""
        lease = self._leases.get(lease_id)
        if lease is None:
            return f"No active lease {lease_id} in this session."
        res = self.agent.run(lease, command)
        return f"exit {res.get('code')}:\n{res.get('stdout') or res.get('stderr') or ''}"

    def end_lease(self, lease_id: int) -> str:
        """Release a leased GPU. The on-chain lease settles when its paid window ends."""
        lease = self._leases.pop(lease_id, None)
        if lease is None:
            return f"No active lease {lease_id} in this session."
        self.agent.end_lease(lease)
        return f"released lease {lease_id}"
