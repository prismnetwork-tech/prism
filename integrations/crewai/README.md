# prism-crewai

Prism Network GPU tools for [CrewAI](https://github.com/crewAIInc/crewAI) agents.
A crew member sees live GPU capacity and prices, rents a machine with an on-chain
USDG payment on Robinhood Chain, runs commands on it over SSH, and releases it.
Every lease settles with a verifiable receipt.

```sh
pip install prism-crewai
```

```python
from crewai import Agent, Crew, Task
from prism_crewai import prism_tools

researcher = Agent(
    role="Compute researcher",
    goal="Benchmark models on real GPUs at the lowest price",
    backstory="You rent GPUs only when a job needs one, and you cap what a lease may cost.",
    tools=prism_tools(),
)

task = Task(
    description="Rent a GPU with at least 24GB of VRAM and report what nvidia-smi shows.",
    expected_output="The GPU model, VRAM, and driver version.",
    agent=researcher,
)

Crew(agents=[researcher], tasks=[task]).kickoff()
```

## Tools

`prism_tools()` returns five tools sharing one wallet and lease table: wallet
balances, live GPU listings, lease-and-run, run-on-open-lease, and end-lease.
The lease tool takes `max_usdg` (default 1.0), a hard cap on what a single lease
may cost.

## Configuration

`PRISM_AGENT_KEY` — private key of a wallet holding USDG and gas on Robinhood
Chain (chain id 4663). `PRISM_ESCROW` — optional; defaults to the live lease
escrow. Or build `PrismToolset(agent=PrismAgent(...))` yourself and pass it to
`prism_tools`.

Trust classes run open < isolated < attested < confidential. On an `open`
supplier the host operator can read anything the workload touches; raise
`min_trust_class` for anything sensitive.

Prism is pre-production and unaudited. Do not lease with a wallet or workload
you cannot lose.
