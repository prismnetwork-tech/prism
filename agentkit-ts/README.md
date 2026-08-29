# @prismnetwork/agentkit

Prism GPU compute as [Coinbase AgentKit](https://github.com/coinbase/agentkit) actions.

Two providers, and they differ in whose money moves:

- **`prismX402ActionProvider()`** pays per call from **the wallet AgentKit already gave the agent**, in USDC on Base over [x402](https://www.x402.org/). No account, no API key, nothing to provision. Start here.
- **`prismActionProvider(agent)`** leases a whole GPU box and pays in USDG on Robinhood Chain from **its own funded wallet**. Use it when the agent needs a machine rather than an answer.

## Install

```bash
npm install @prismnetwork/agentkit
```

`@coinbase/agentkit`, `viem` and `zod` are peer dependencies.

## Pay per call

```typescript
import { AgentKit, ViemWalletProvider } from "@coinbase/agentkit";
import { prismX402ActionProvider } from "@prismnetwork/agentkit";

const agentkit = await AgentKit.from({
  walletProvider: new ViemWalletProvider(walletClient), // any EVM wallet on Base
  actionProviders: [prismX402ActionProvider()],
});
```

| Action | Cost | What it does |
|--------|------|--------------|
| `prism_get_models` | free | Models, prices, and whether a GPU is warm |
| `prism_run_inference` | 0.003–0.012 USDC | One generation on a rented GPU |
| `prism_run_batch` | scales with prompts | Many prompts in one paid call, with a Merkle receipt over the set |
| `prism_run_gpu_command` | 0.03 USDC | Lease a GPU and run one shell command |
| `prism_get_gpu_job` | free | Status and output of a queued command |

### Spending is bounded before anything is signed

Prism prices inference by the token cap requested, so a large cap on a large batch is the one way an agent can spend more than it meant to. Any payment option quoted above the ceiling is dropped before the wallet is asked to sign:

```typescript
prismX402ActionProvider({
  maxPaymentUsdc: 1,                            // default
  apiBase: "https://api.prismnetwork.tech",     // default
});
```

### A cold pool costs nothing

Prism leases GPUs on demand, so the first call after an idle period may arrive before one is warm. Those calls take no payment and come back as `{"charged": false, "retryAfterSeconds": 300}` rather than an error, so an agent waits instead of reporting an outage.

### Batches carry an audit path

`prism_run_batch` spreads prompts across every GPU the gateway holds and returns one settlement plus a Merkle receipt over the whole set. Each answer arrives with its own commitment hash and an audit path, so any single answer checks against the batch root without revealing the others.

## Lease a whole GPU

```typescript
import { PrismAgent } from "@prismnetwork/agent-sdk";
import { prismActionProvider } from "@prismnetwork/agentkit";

const provider = prismActionProvider(new PrismAgent({ privateKey: process.env.PRISM_AGENT_KEY }));
```

`prism_wallet`, `prism_list_gpus`, `prism_lease_and_run`, `prism_run`, `prism_end_lease`. The wallet needs USDG and a little ETH for gas on Robinhood Chain (chain id 4663). `prism_lease_and_run` takes a `maxUsdg` cap and a `minTrustClass`; on an `open` supplier the host operator can read anything the workload touches.

## Networks

Prism quotes payment on Base (USDC) and Robinhood Chain (USDG). Any EVM wallet provider works with the x402 actions; a wallet funded with USDC on Base mainnet is the usual setup.

## License

Apache-2.0
