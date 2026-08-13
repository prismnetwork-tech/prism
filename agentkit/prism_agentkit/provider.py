import os
from typing import Any

from coinbase_agentkit import ActionProvider, WalletProvider, create_action
from coinbase_agentkit.network import Network
from prismnetwork import DEFAULT_IMAGE, Lease, PrismAgent
from pydantic import BaseModel, Field

DEFAULT_ESCROW = "0x62C042265991bEa17B07229322A01850974626dA"


class NoArgs(BaseModel):
    pass


class LeaseAndRunArgs(BaseModel):
    command: str = Field(description="Command to run on the rented GPU")
    duration_seconds: int = Field(600, description="How long to hold the lease, in seconds")
    min_vram_mib: int = Field(16000, description="Minimum GPU memory in MiB")
    image: str = Field(DEFAULT_IMAGE, description="Digest-pinned container image to boot")
    max_usdg: float = Field(1.0, description="Hard cap on the USDG this lease may cost")
    min_trust_class: str = Field(
        "open",
        description=(
            "Refuse suppliers below this trust class: open, isolated, attested or confidential. "
            "On an open supplier the host operator can read anything the workload touches."
        ),
    )


class RunArgs(BaseModel):
    lease_id: int = Field(description="A lease id returned by lease_and_run")
    command: str = Field(description="Command to run")


class LeaseIdArgs(BaseModel):
    lease_id: int = Field(description="A lease id from this session")


def _usdg(micros: int) -> str:
    return f"{int(micros) / 1_000_000:.6f} USDG"


class PrismActionProvider(ActionProvider[WalletProvider]):
    """Rent and run on real NVIDIA GPUs through Prism Network.

    The provider carries its own funded wallet (``PRISM_AGENT_KEY``) and settles
    onchain in USDG. It never touches the agent's primary wallet, so it works with
    any AgentKit wallet provider.
    """

    def __init__(self, agent: PrismAgent | None = None):
        super().__init__("prism", [])
        if agent is None:
            key = os.environ.get("PRISM_AGENT_KEY")
            if not key:
                raise ValueError("PRISM_AGENT_KEY is required (or pass agent=)")
            agent = PrismAgent(key, os.environ.get("PRISM_ESCROW", DEFAULT_ESCROW))
        self.agent = agent
        self._leases: dict[int, Lease] = {}

    @create_action(
        name="wallet",
        description="Show the Prism agent's wallet address and its USDG and ETH balances.",
        schema=NoArgs,
    )
    def wallet(self, args: dict[str, Any]) -> str:
        b = self.agent.balances()
        return f"address: {b['address']}\nusdg: {_usdg(b['usdg'])}\neth: {int(b['eth']) / 1e18:.6f}"

    @create_action(
        name="list_gpus",
        description=(
            "List GPUs available to rent right now, with model, VRAM, price per hour, and trust "
            "class. On an 'open' supplier the host operator can read anything the workload touches."
        ),
        schema=NoArgs,
    )
    def list_gpus(self, args: dict[str, Any]) -> str:
        offers = self.agent.offers()
        if not offers:
            return "No GPUs are online to rent right now."
        rows = []
        for o in offers:
            gpu = o.get("gpu", {})
            per_hr = int(o.get("rate_per_second", 0)) * 3600 / 1_000_000
            trust = o.get("trust_class", "open")
            rows.append(
                f"{gpu.get('model', 'GPU')} · {gpu.get('vram_mib', '?')} MiB · ${per_hr:.2f}/hr · {trust}"
            )
        return "\n".join(rows)

    @create_action(
        name="lease_and_run",
        description=(
            "Rent a GPU, run one command on it, and return the output. Pays onchain in USDG "
            "up to max_usdg. Blocks while the machine provisions (usually 1-4 minutes)."
        ),
        schema=LeaseAndRunArgs,
    )
    def lease_and_run(self, args: dict[str, Any]) -> str:
        p = LeaseAndRunArgs(**args)
        lease = self.agent.lease(
            image=p.image,
            duration_seconds=p.duration_seconds,
            min_vram_mib=p.min_vram_mib,
            max_deposit=int(p.max_usdg * 1_000_000),
            min_trust_class=p.min_trust_class,
        )
        self._leases[lease.lease_id] = lease
        res = self.agent.run(lease, p.command)
        out = res.get("stdout") or res.get("stderr") or ""
        return f"lease {lease.lease_id} funded onchain (tx {lease.funding_hash}), exit {res.get('code')}:\n{out}"

    @create_action(
        name="run",
        description="Run another command on a GPU already leased in this session.",
        schema=RunArgs,
    )
    def run(self, args: dict[str, Any]) -> str:
        p = RunArgs(**args)
        lease = self._leases.get(p.lease_id)
        if lease is None:
            return f"No active lease {p.lease_id} in this session."
        res = self.agent.run(lease, p.command)
        return f"exit {res.get('code')}:\n{res.get('stdout') or res.get('stderr') or ''}"

    @create_action(
        name="end_lease",
        description="Release a leased GPU's local session. The onchain lease settles when its term ends.",
        schema=LeaseIdArgs,
    )
    def end_lease(self, args: dict[str, Any]) -> str:
        p = LeaseIdArgs(**args)
        lease = self._leases.pop(p.lease_id, None)
        if lease is None:
            return f"No active lease {p.lease_id} in this session."
        self.agent.end_lease(lease)
        return f"released lease {p.lease_id}"

    def supports_network(self, network: Network) -> bool:
        return True


def prism_action_provider(agent: PrismAgent | None = None) -> PrismActionProvider:
    return PrismActionProvider(agent)
