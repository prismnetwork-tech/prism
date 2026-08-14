"""Prism Network GPU tools for AutoGen-lineage agents.

The tools are plain typed functions, which is what both current frameworks
auto-wrap: AG2 v1 (``ag2``, ``Agent(tools=[...])``) and Microsoft AutoGen
(``autogen-agentchat``, ``AssistantAgent(tools=[...])``). No dependency on
either is taken here.

    from prism_autogen import prism_tools

    # AG2 v1
    agent = Agent("gpu_agent", prompt="...", config=..., tools=prism_tools())

    # autogen-agentchat
    agent = AssistantAgent(name="gpu_agent", model_client=..., tools=prism_tools())
"""

from prismnetwork import DEFAULT_IMAGE, PrismToolset

__all__ = ["prism_tools", "PrismToolset"]
__version__ = "0.1.0"


def prism_tools(toolset: PrismToolset | None = None) -> list:
    """Build the Prism tool list.

    All five tools share one toolset, so a lease opened by one is visible to the
    others. Pass a :class:`PrismToolset` to control the wallet, or let it read
    ``PRISM_AGENT_KEY`` (and optionally ``PRISM_ESCROW``) from the environment.
    """
    t = toolset or PrismToolset()

    def prism_wallet() -> str:
        """Show the Prism wallet address and its USDG and gas balances on Robinhood Chain."""
        return t.wallet()

    def prism_list_gpus(min_trust: str = "open") -> str:
        """List GPUs available to rent right now on Prism Network: model, VRAM, price
        per hour in USDG, and trust class (open, isolated, attested or confidential).
        On an 'open' supplier the host operator can read anything the workload touches."""
        return t.list_gpus(min_trust)

    def prism_lease_and_run(
        command: str,
        duration_seconds: int = 600,
        min_vram_mib: int = 16000,
        max_usdg: float = 1.0,
        min_trust_class: str = "open",
    ) -> str:
        """Rent a real GPU, run one shell command on it over SSH, and return the output.
        Funds an on-chain USDG escrow up to max_usdg and blocks while the machine
        provisions, usually one to four minutes. The lease stays open for follow-up
        commands with prism_run; release it with prism_end_lease."""
        return t.lease_and_run(command, duration_seconds, min_vram_mib, DEFAULT_IMAGE, max_usdg, min_trust_class)

    def prism_run(lease_id: int, command: str) -> str:
        """Run another shell command on a GPU already leased in this session."""
        return t.run(lease_id, command)

    def prism_end_lease(lease_id: int) -> str:
        """Release a leased GPU. The on-chain lease settles when its paid window ends."""
        return t.end_lease(lease_id)

    return [prism_wallet, prism_list_gpus, prism_lease_and_run, prism_run, prism_end_lease]
