"""A LangGraph agent that rents a GPU on Prism and runs a command on it.

    export PRISM_AGENT_KEY=0x...   # funded with USDG + gas on Robinhood Chain
    export OPENAI_API_KEY=sk-...
    python langgraph_gpu_agent.py
"""

from coinbase_agentkit import (
    AgentKit,
    AgentKitConfig,
    EthAccountWalletProvider,
    EthAccountWalletProviderConfig,
)
from coinbase_agentkit_langchain import get_langchain_tools
from eth_account import Account
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from prism_agentkit import prism_action_provider

# Prism settles with its own wallet (PRISM_AGENT_KEY). AgentKit still needs a
# wallet provider in its config; Prism ignores it, so a throwaway one is fine.
placeholder = EthAccountWalletProvider(
    EthAccountWalletProviderConfig(account=Account.create(), chain_id="8453", rpc_url="https://mainnet.base.org")
)

kit = AgentKit(AgentKitConfig(wallet_provider=placeholder, action_providers=[prism_action_provider()]))
agent = create_react_agent(ChatOpenAI(model="gpt-4o-mini"), get_langchain_tools(kit))

prompt = "Rent a GPU with at least 24GB of VRAM for five minutes and run nvidia-smi on it."
for step in agent.stream({"messages": [("user", prompt)]}, stream_mode="values"):
    step["messages"][-1].pretty_print()
