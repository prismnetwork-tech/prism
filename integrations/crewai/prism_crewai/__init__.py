"""Prism Network GPU tools for CrewAI agents.

    from crewai import Agent
    from prism_crewai import prism_tools

    researcher = Agent(role="...", goal="...", backstory="...", tools=prism_tools())
"""

from ._tools import (
    PrismEndLeaseTool,
    PrismLeaseAndRunTool,
    PrismListGpusTool,
    PrismRunTool,
    PrismWalletTool,
    prism_tools,
)

__all__ = [
    "prism_tools",
    "PrismWalletTool",
    "PrismListGpusTool",
    "PrismLeaseAndRunTool",
    "PrismRunTool",
    "PrismEndLeaseTool",
]
__version__ = "0.1.0"
