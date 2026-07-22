# @prism-network/agent-sdk

Headless GPU leasing on [Prism Network](https://prismnetwork.tech) for autonomous agents. No browser, no Privy — an agent authenticates with a wallet signature, pays on-chain in USDG, and gets SSH access to a GPU.

```js
import { PrismAgent } from "@prism-network/agent-sdk";

const agent = new PrismAgent({
  privateKey: process.env.AGENT_KEY,        // agent's wallet
  escrow: "0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD",
});

await agent.authenticate();                  // wallet-signature session
const quote = await agent.quote({ image, durationSeconds: 900, minVramMib: 45000 });
const { hash } = await agent.fund(quote);    // approve USDG + createLease on Robinhood Chain
const lease = await agent.confirm({ quoteId: quote.quote_id, transactionHash: hash, sshAuthorizedKey });
const access = await agent.waitForAccess(lease.lease_id);   // { ssh_host, ssh_port, ... }
```

## Auth

`authenticate()` fetches a challenge (`GET /api/agent/challenge`), signs the message with the wallet, and exchanges it for a session (`POST /api/agent/session`). The session is a bearer token used on every `/api/agent/proxy/*` call. No shared secret, no cookie — the wallet is the identity (`subject = wallet:0x…`).

## Payment

`fund()` reproduces the escrow's quote binding: `clientReference = keccak256(quote_id)`, `approve(escrow, maximum_escrow)` then `createLease(nodeId, duration, clientReference)`. The agent wallet needs USDG and native Robinhood-Chain gas.

## Requirements

- Node ≥ 20, `viem` ^2 (peer dependency)
- An agent wallet funded with USDG (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`) and Robinhood-Chain ETH for gas

See `example.mjs` for a full run.
