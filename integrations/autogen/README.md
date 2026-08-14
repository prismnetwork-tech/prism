# prism-autogen

Prism Network GPU tools for AG2 and Microsoft AutoGen agents. The agent sees
live GPU capacity and prices, rents a machine with an on-chain USDG payment on
Robinhood Chain, runs commands on it over SSH, and releases it. Every lease
settles with a verifiable receipt.

The tools are plain typed functions, so they work unchanged with both lineages:

```sh
pip install prism-autogen
```

AG2 v1 (`pip install 'ag2[openai]'`):

```python
import asyncio
from ag2 import Agent
from ag2.config import OpenAIConfig
from prism_autogen import prism_tools

agent = Agent(
    "gpu_agent",
    prompt="You rent GPUs on Prism Network when a task needs one.",
    config=OpenAIConfig(model="gpt-4o-mini"),
    tools=prism_tools(),
)

async def main():
    reply = await agent.ask("Rent a GPU with 24GB of VRAM and run nvidia-smi.")
    print(reply.body)

asyncio.run(main())
```

Microsoft AutoGen (`autogen-agentchat`):

```python
from autogen_agentchat.agents import AssistantAgent
from prism_autogen import prism_tools

agent = AssistantAgent(name="gpu_agent", model_client=..., tools=prism_tools())
```

## Configuration

`PRISM_AGENT_KEY`: private key of a wallet holding USDG and gas on Robinhood
Chain (chain id 4663, RPC rpc.mainnet.chain.robinhood.com). `PRISM_ESCROW`:
optional; defaults to the live lease escrow. Without a key the read-only tools
still answer from the public API. `prism_lease_and_run` takes `max_usdg`
(default 1.0), a hard cap on what a single lease may cost.

Trust classes run open < isolated < attested < confidential. On an `open`
supplier the host operator can read anything the workload touches; raise
`min_trust_class` for anything sensitive.

Prism is pre-production and unaudited. Do not lease with a wallet or workload
you cannot lose.
