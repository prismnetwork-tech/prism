# @prismnetwork/game-plugin

Virtuals Protocol GAME plugin for Prism Network. A GAME agent gets a worker
whose action space is renting real NVIDIA GPUs: see live capacity and prices,
lease with an on-chain USDG payment on Robinhood Chain, run commands over SSH,
release. Every lease settles with a verifiable receipt.

```sh
npm i @prismnetwork/game-plugin @virtuals-protocol/game
```

```ts
import { GameAgent } from "@virtuals-protocol/game";
import { PrismGamePlugin } from "@prismnetwork/game-plugin";

const prism = new PrismGamePlugin();

const agent = new GameAgent(process.env.GAME_API_KEY, {
  name: "Compute buyer",
  goal: "Rent a GPU only when a task needs one, at the best available price.",
  description: "An agent that buys GPU time on Prism Network and accounts for every USDG it spends.",
  workers: [prism.getWorker()],
});

await agent.init();
await agent.run(60, { verbose: true });
```

The worker's functions: `list_gpus`, `wallet`, `lease_and_run`, `run`,
`end_lease`. `lease_and_run` takes `max_usdg` (default 1), a hard cap on what a
single lease may cost. The worker environment carries live capacity, so the
planner sees what is rentable before it acts.

## Configuration

Browsing capacity needs nothing. Leasing needs `PRISM_AGENT_KEY`, the private
key of a wallet holding USDG and gas on Robinhood Chain (chain id 4663);
`PRISM_ESCROW` is optional and defaults to the live lease escrow. `ssh` and
`ssh-keygen` must be on `PATH`.

Trust classes run open < isolated < attested < confidential. On an `open`
supplier the host operator can read anything the workload touches.

Prism is pre-production and unaudited. Do not lease with a wallet or workload
you cannot lose.
