# @prismnetwork/agentkit

Prism GPU leasing as [Coinbase AgentKit](https://github.com/coinbase/agentkit)
actions. One provider gives an agent five tools: see what capacity is live,
rent a GPU, run commands on it over SSH, and release it. The lease is funded
from a wallet and settles onchain.

Works anywhere AgentKit does, so the same provider reaches the Vercel AI SDK
and LangChain without a second integration.

## Install

```sh
npm install @prismnetwork/agentkit @coinbase/agentkit viem zod
```

## Use

```js
import { AgentKit, ViemWalletProvider } from "@coinbase/agentkit";
import { getVercelAITools } from "@coinbase/agentkit-vercel-ai-sdk";
import { PrismActionProvider } from "@prismnetwork/agentkit";
import { createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";

// AgentKit requires a wallet provider. Prism pays for leases with its own
// wallet on Robinhood Chain, so this one is never spent from.
const walletProvider = new ViemWalletProvider(
  createWalletClient({
    account: privateKeyToAccount(process.env.PLACEHOLDER_KEY),
    chain: base,
    transport: http(),
  }),
);

const agentkit = await AgentKit.from({
  walletProvider,
  actionProviders: [new PrismActionProvider()],
});

const tools = await getVercelAITools(agentkit);
```

`PrismActionProvider` reads `PRISM_AGENT_KEY` and `PRISM_ESCROW` from the
environment. Pass a configured `PrismAgent` instead if you would rather hold
the key yourself:

```js
import { PrismAgent } from "@prismnetwork/agent-sdk";

new PrismActionProvider(new PrismAgent({ privateKey, escrow }));
```

For LangChain, swap `getVercelAITools` for `getLangChainTools` from
`@coinbase/agentkit-langchain`. The tools are identical.

## Tools

| Tool | Needs funds | Does |
| --- | --- | --- |
| `prism_wallet` | no | Wallet address, USDG balance, gas balance |
| `prism_list_gpus` | no | Live capacity: model, memory, price per hour, trust class |
| `prism_lease_and_run` | yes | Funds a lease onchain, boots the machine, runs one command |
| `prism_run` | no | Another command on a lease this session opened |
| `prism_end_lease` | no | Releases the machine; the lease settles when its window ends |

The two read-only tools work with an empty wallet, which makes the integration
easy to try before funding anything.

`prism_lease_and_run` takes `maxUsdg` as a hard cap on what the lease may cost
and `minTrustClass` to refuse suppliers weaker than the workload needs. All
capacity live today is `open`, which means the host operator can read anything
the workload touches: keep credentials, private datasets and model weights off
it. The [security model](https://github.com/prismnetworkdottech/prism/blob/main/docs/SECURITY_MODEL.md)
sets out what each class does and does not promise.

## Known upstream issue

`@coinbase/agentkit` 0.10.4 posts an analytics event on every tool invocation
and throws when that request fails, which surfaces as an unhandled rejection
from `sendAnalyticsEvent` rather than anything to do with the tool you called.
It is not specific to this provider.

## Pre-production

Prism is unaudited and pre-production. Do not lease with a wallet or a workload
you cannot afford to lose.

Apache-2.0.
