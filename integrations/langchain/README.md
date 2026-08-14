# prism-langchain

Prism Network GPU tools for LangChain and LangGraph agents. The agent sees live
GPU capacity and prices, rents a machine with an on-chain USDG payment on
Robinhood Chain, runs commands on it over SSH, and releases it. Every lease
settles with a verifiable receipt.

```sh
pip install prism-langchain langgraph langchain-openai
```

The package itself depends only on `langchain-core`; the example below also
needs LangGraph and a model provider.

```python
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from prism_langchain import get_prism_tools

agent = create_react_agent(ChatOpenAI(model="gpt-4o-mini"), get_prism_tools())
agent.invoke({"messages": [("user", "Rent a GPU with 24GB of VRAM and run nvidia-smi.")]})
```

## Tools

| Tool | What it does |
| --- | --- |
| `prism_wallet` | wallet address, USDG and gas balances |
| `prism_list_gpus` | live capacity: model, VRAM, price per hour, trust class |
| `prism_lease_and_run` | rent a GPU, run one command, keep the lease open |
| `prism_run` | run another command on an open lease |
| `prism_end_lease` | release a lease |

## Configuration

`PRISM_AGENT_KEY`: private key of a wallet holding USDG and gas on Robinhood
Chain (chain id 4663, RPC rpc.mainnet.chain.robinhood.com). `PRISM_ESCROW`:
optional; defaults to the live lease escrow. Without a key the read-only tools
still answer from the public API. Or construct
`PrismToolset(agent=PrismAgent(...))` yourself and pass it to
`get_prism_tools`.

`prism_lease_and_run` takes `max_usdg` (default 1.0), a hard cap on what a
single lease may cost. Set it deliberately when raising duration.

Trust classes run open < isolated < attested < confidential. On an `open`
supplier the host operator can read anything the workload touches; raise
`min_trust_class` for anything sensitive.

Prism is pre-production and unaudited. Do not lease with a wallet or workload
you cannot lose.
