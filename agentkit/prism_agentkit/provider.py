import os
from typing import Any

from coinbase_agentkit import ActionProvider, WalletProvider, create_action
from coinbase_agentkit.network import Network
from prismnetwork import DEFAULT_IMAGE, PrismAgent, PrismToolset
from prismnetwork.toolkit import UNSET
from pydantic import BaseModel, Field

DEFAULT_ESCROW = "0xfD4228eEEfC49e4b76A0CD40af9fdd546220B2FD"


class NoArgs(BaseModel):
    pass


class LeaseAndRunArgs(BaseModel):
    command: str = Field(description="Command to run on the rented GPU")
    duration_seconds: int = Field(600, description="How long to hold the lease, in seconds")
    min_vram_mib: int = Field(16000, description="Minimum GPU memory in MiB")
    image: str = Field(DEFAULT_IMAGE, description="Digest-pinned container image to boot")
    max_usdg: float | None = Field(
        None,
        description=(
            "Lower the operator's per-call spending cap for this one lease. It cannot raise it; "
            "left out, the operator's cap applies."
        ),
    )
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


class PrismActionProvider(ActionProvider[WalletProvider]):
    """Rent and run on real NVIDIA GPUs through Prism Network.

    The provider carries its own funded wallet (``PRISM_AGENT_KEY``) and settles
    onchain in USDG. It never touches the agent's primary wallet, so it works with
    any AgentKit wallet provider.

    Spending goes through the same ledger the MCP server and the Python SDK write.
    ``max_usdg`` is the model's request rather than the limit: ``PRISM_MAX_USDG``
    bounds every lease, ``PRISM_DAILY_BUDGET_USDG`` bounds the day, and one wallet
    has one daily ceiling however many clients are holding it. ``budget`` takes a
    :class:`~prismnetwork.Budget` or :class:`~prismnetwork.SpendLedger` for a caller
    that wants its own limits.
    """

    def __init__(self, agent: PrismAgent | None = None, budget=UNSET):
        super().__init__("prism", [])
        if agent is None:
            key = os.environ.get("PRISM_AGENT_KEY")
            if not key:
                raise ValueError("PRISM_AGENT_KEY is required (or pass agent=)")
            agent = PrismAgent(key, os.environ.get("PRISM_ESCROW", DEFAULT_ESCROW))
        self.agent = agent
        self.tools = PrismToolset(agent=agent, budget=budget)

    @create_action(
        name="budget",
        description=(
            "Show the spending limits in force and what this wallet has already spent in the last "
            "24 hours. Worth checking before a long job; a lease refused for budget reports the "
            "same numbers."
        ),
        schema=NoArgs,
    )
    def budget(self, args: dict[str, Any]) -> str:
        return self.tools.budget_status()

    @create_action(
        name="wallet",
        description="Show the Prism agent's wallet address and its USDG and ETH balances.",
        schema=NoArgs,
    )
    def wallet(self, args: dict[str, Any]) -> str:
        return self.tools.wallet()

    @create_action(
        name="list_gpus",
        description=(
            "List GPUs available to rent right now, with model, VRAM, price per hour, and trust "
            "class. On an 'open' supplier the host operator can read anything the workload touches."
        ),
        schema=NoArgs,
    )
    def list_gpus(self, args: dict[str, Any]) -> str:
        return self.tools.list_gpus()

    @create_action(
        name="lease_and_run",
        description=(
            "Rent a GPU, run one command on it, and return the output. Pays onchain in USDG within "
            "the operator's per-call and daily spending caps. Blocks while the machine provisions "
            "(usually 1-4 minutes)."
        ),
        schema=LeaseAndRunArgs,
    )
    def lease_and_run(self, args: dict[str, Any]) -> str:
        p = LeaseAndRunArgs(**args)
        return self.tools.lease_and_run(
            command=p.command,
            duration_seconds=p.duration_seconds,
            min_vram_mib=p.min_vram_mib,
            image=p.image,
            max_usdg=p.max_usdg,
            min_trust_class=p.min_trust_class,
        )

    @create_action(
        name="run",
        description="Run another command on a GPU already leased in this session.",
        schema=RunArgs,
    )
    def run(self, args: dict[str, Any]) -> str:
        p = RunArgs(**args)
        return self.tools.run(p.lease_id, p.command)

    @create_action(
        name="end_lease",
        description="Release a leased GPU. Billing stops at the release; settlement charges the seconds it was open and returns the rest of the deposit.",
        schema=LeaseIdArgs,
    )
    def end_lease(self, args: dict[str, Any]) -> str:
        p = LeaseIdArgs(**args)
        return self.tools.end_lease(p.lease_id)

    def supports_network(self, network: Network) -> bool:
        return True


def prism_action_provider(agent: PrismAgent | None = None, budget=UNSET) -> PrismActionProvider:
    return PrismActionProvider(agent, budget)
