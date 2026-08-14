from typing import Type

from crewai.tools import BaseTool
from prismnetwork import DEFAULT_IMAGE, PrismToolset
from pydantic import BaseModel, Field, PrivateAttr


class NoInput(BaseModel):
    pass


class ListGpusInput(BaseModel):
    min_trust: str = Field(
        "open",
        description="Only list suppliers at or above this trust class: open, isolated, attested or confidential.",
    )


class LeaseAndRunInput(BaseModel):
    command: str = Field(description="Shell command to run on the rented GPU, e.g. 'nvidia-smi'.")
    duration_seconds: int = Field(600, description="How long to hold the lease, in seconds.")
    min_vram_mib: int = Field(16000, description="Minimum GPU memory in MiB.")
    image: str = Field(DEFAULT_IMAGE, description="Digest-pinned container image to boot.")
    max_usdg: float = Field(1.0, description="Hard cap on the USDG this lease may cost.")
    min_trust_class: str = Field(
        "open",
        description=(
            "Refuse suppliers below this trust class. On an 'open' supplier the host "
            "operator can read anything the workload touches."
        ),
    )


class RunInput(BaseModel):
    lease_id: int = Field(description="A lease id returned by the lease tool.")
    command: str = Field(description="Shell command to run.")


class LeaseIdInput(BaseModel):
    lease_id: int = Field(description="A lease id from this session.")


class _PrismTool(BaseTool):
    _toolset: PrismToolset = PrivateAttr()

    def __init__(self, toolset: PrismToolset | None = None, **data):
        super().__init__(**data)
        self._toolset = toolset or PrismToolset()


class PrismWalletTool(_PrismTool):
    name: str = "Prism wallet"
    description: str = "Show the Prism wallet address and its USDG and gas balances on Robinhood Chain."
    args_schema: Type[BaseModel] = NoInput

    def _run(self) -> str:
        return self._toolset.wallet()


class PrismListGpusTool(_PrismTool):
    name: str = "List Prism GPUs"
    description: str = (
        "List GPUs available to rent right now on Prism Network: model, VRAM, "
        "price per hour in USDG, and trust class."
    )
    args_schema: Type[BaseModel] = ListGpusInput

    def _run(self, min_trust: str = "open") -> str:
        return self._toolset.list_gpus(min_trust)


class PrismLeaseAndRunTool(_PrismTool):
    name: str = "Rent a GPU and run a command"
    description: str = (
        "Rent a real GPU on Prism Network, run one shell command on it over SSH, and "
        "return the output. Funds an on-chain USDG escrow and blocks while the machine "
        "provisions, usually one to four minutes. The lease stays open for follow-up "
        "commands with the run tool."
    )
    args_schema: Type[BaseModel] = LeaseAndRunInput

    def _run(
        self,
        command: str,
        duration_seconds: int = 600,
        min_vram_mib: int = 16000,
        image: str = DEFAULT_IMAGE,
        max_usdg: float = 1.0,
        min_trust_class: str = "open",
    ) -> str:
        return self._toolset.lease_and_run(
            command, duration_seconds, min_vram_mib, image, max_usdg, min_trust_class
        )


class PrismRunTool(_PrismTool):
    name: str = "Run on a leased GPU"
    description: str = "Run another shell command on a GPU already leased in this session."
    args_schema: Type[BaseModel] = RunInput

    def _run(self, lease_id: int, command: str) -> str:
        return self._toolset.run(lease_id, command)


class PrismEndLeaseTool(_PrismTool):
    name: str = "End a GPU lease"
    description: str = "Release a leased GPU. The on-chain lease settles when its paid window ends."
    args_schema: Type[BaseModel] = LeaseIdInput

    def _run(self, lease_id: int) -> str:
        return self._toolset.end_lease(lease_id)


def prism_tools(toolset: PrismToolset | None = None) -> list[BaseTool]:
    """Build the Prism tool list for a CrewAI agent.

    All five tools share one toolset, so a lease opened by one is visible to the
    others. Pass a :class:`PrismToolset` to control the wallet, or let it read
    ``PRISM_AGENT_KEY`` (and optionally ``PRISM_ESCROW``) from the environment.
    """
    t = toolset or PrismToolset()
    return [
        PrismWalletTool(t),
        PrismListGpusTool(t),
        PrismLeaseAndRunTool(t),
        PrismRunTool(t),
        PrismEndLeaseTool(t),
    ]
