# prism-agentkit

A [Coinbase AgentKit](https://github.com/coinbase/agentkit) action provider that lets an agent rent and run on real NVIDIA GPUs through [Prism Network](https://prismnetwork.tech). One `pip install` gives your AgentKit agent GPU actions that work in LangChain, LangGraph, and any other AgentKit adapter.

The provider carries its own funded wallet (`PRISM_AGENT_KEY`) and settles onchain in USDG. It never touches the agent's primary wallet, so it composes with any AgentKit wallet provider you already run.

## Install

```bash
pip install prism-agentkit
```

## Actions

- `wallet` - the Prism agent's address and USDG/ETH balances.
- `list_gpus` - GPUs available to rent now, with model, VRAM, and price per hour.
- `lease_and_run` - rent a GPU, run a command, return the output (one shot, pays onchain up to `max_usdg`).
- `run` - run another command on a GPU already leased this session.
- `end_lease` - release a lease's local session.

## Use

```python
import os
from coinbase_agentkit import (
    AgentKit, AgentKitConfig,
    EthAccountWalletProvider, EthAccountWalletProviderConfig,
)
from coinbase_agentkit_langchain import get_langchain_tools
from eth_account import Account
from prism_agentkit import prism_action_provider

# Prism pays with its own wallet (PRISM_AGENT_KEY). AgentKit still wants a wallet
# provider in its config; Prism ignores it, so pass whichever you already use.
wallet = EthAccountWalletProvider(EthAccountWalletProviderConfig(
    account=Account.create(), chain_id="8453", rpc_url="https://mainnet.base.org"))

kit = AgentKit(AgentKitConfig(
    wallet_provider=wallet,
    action_providers=[prism_action_provider()],
))
tools = get_langchain_tools(kit)
```

`tools` are standard LangChain tools; hand them to a LangGraph agent (see `examples/langgraph_gpu_agent.py`), a Vercel AI agent, or any AgentKit adapter.

## Configure

Set the Prism agent's wallet:

```bash
export PRISM_AGENT_KEY=0x...   # agent wallet private key, funded with USDG + gas on Robinhood Chain
export PRISM_ESCROW=0x62C042265991bEa17B07229322A01850974626dA   # optional, this is the default
```

The wallet needs USDG (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`) and Robinhood-Chain ETH for gas. See the [Prism SDK](https://github.com/winter0x/prism) for how to fund a fresh wallet.

## Notes

- `lease_and_run` blocks while the machine provisions, usually one to four minutes. Give your agent a long tool-call timeout.
- AgentKit emits a harmless `cca-lite.coinbase.com` analytics warning when it runs offline; it does not affect the actions.
