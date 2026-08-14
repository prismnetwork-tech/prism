"""Prism Network tools for LangChain and LangGraph agents.

Five tools over one funded wallet: see capacity and prices, rent a real GPU,
run commands on it over SSH, release it. Payment settles on-chain in USDG on
Robinhood Chain; every lease ends in a verifiable receipt.

    from langgraph.prebuilt import create_react_agent
    from prism_langchain import get_prism_tools

    agent = create_react_agent(model, get_prism_tools())
"""

from langchain_core.tools import StructuredTool
from prismnetwork import PrismToolset

__all__ = ["get_prism_tools", "PrismToolset"]
__version__ = "0.1.0"


def get_prism_tools(toolset: PrismToolset | None = None) -> list[StructuredTool]:
    """Build the Prism tool list.

    Pass a :class:`PrismToolset` to control the wallet and escrow, or let it
    read ``PRISM_AGENT_KEY`` (and optionally ``PRISM_ESCROW``) from the
    environment. Leases opened by one tool call are visible to the others, so
    an agent can lease once and keep running commands on the same machine.
    """
    t = toolset or PrismToolset()
    return [
        StructuredTool.from_function(t.wallet, name="prism_wallet"),
        StructuredTool.from_function(t.list_gpus, name="prism_list_gpus"),
        StructuredTool.from_function(t.lease_and_run, name="prism_lease_and_run"),
        StructuredTool.from_function(t.run, name="prism_run"),
        StructuredTool.from_function(t.end_lease, name="prism_end_lease"),
    ]
