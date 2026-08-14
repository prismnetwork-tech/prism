# @prismnetwork/plugin-eliza

elizaOS plugin for Prism Network. The agent sees live GPU capacity and prices,
rents a real GPU with an on-chain USDG payment on Robinhood Chain, and runs
commands on it over SSH. Every lease settles with a verifiable receipt.

Add it to a character:

```ts
export const character: Character = {
  name: "Eliza",
  plugins: [
    "@elizaos/plugin-sql",
    "@elizaos/plugin-openai",
    "@elizaos/plugin-bootstrap",
    "@prismnetwork/plugin-eliza",
  ],
};
```

Or pass the plugin object directly in a project:

```ts
import prismPlugin from "@prismnetwork/plugin-eliza";

export default { agents: [{ character, plugins: [prismPlugin] }] };
```

## What the agent can do

- **PRISM_LIST_GPUS**: "what GPUs can you rent right now and at what price?"
- **PRISM_WALLET**: "how much is left in the GPU wallet?"
- **PRISM_LEASE_AND_RUN**: "rent a GPU for 10 minutes and run \`nvidia-smi\`".
  The command comes from backticks in the message and defaults to `nvidia-smi`.

A `PRISM_CAPACITY` provider also feeds live capacity into the agent's context.

## Configuration

Browsing capacity needs nothing. Leasing needs `PRISM_AGENT_KEY`, the private
key of a wallet holding USDG and gas on Robinhood Chain (chain id 4663);
`PRISM_ESCROW` is optional and defaults to the live lease escrow. Both are read
from the runtime's settings (character secrets) first and the process
environment second, per agent, so two characters in one process keep separate
wallets. A malformed key degrades the agent to read-only with a note rather
than failing the boot. `ssh` and `ssh-keygen` must be on `PATH`.

Prism is pre-production and unaudited. Do not lease with a wallet or workload
you cannot lose.
