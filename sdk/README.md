# @prismnetwork/agent-sdk

Headless GPU leasing on [Prism Network](https://prismnetwork.tech) for autonomous agents. No browser, no Privy. An agent authenticates with a wallet signature, pays on-chain in USDG, and gets SSH access to a GPU.

## Install

```
npm install @prismnetwork/agent-sdk viem
```

`viem` is a peer dependency.

## Use

```js
import { PrismAgent, DEFAULT_IMAGE } from "@prismnetwork/agent-sdk";

const agent = new PrismAgent({
  privateKey: process.env.AGENT_KEY,        // agent's wallet
  escrow: "0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD",
});

await agent.authenticate();
const lease = await agent.lease({ image: DEFAULT_IMAGE, durationSeconds: 900, minVramMib: 16000 });
const out = await agent.run(lease, "nvidia-smi");
console.log(out.stdout);
agent.endLease(lease);
```

`image` must be an immutable digest-pinned reference (`repo@sha256:...`). `DEFAULT_IMAGE` is one; a plain tag is rejected.

## Vault

Cards, identity documents, API credentials and recovery codes go in the vault
rather than on a leased box. Items are sealed here, on your machine, under a
key derived from a wallet signature that is never transmitted, so Prism stores
ciphertext and holds no way to read it.

```js
await agent.vault.unlock();

const card = await agent.vault.put({ pan: "4111111111111111" }, { label: "billing" });
const value = await agent.vault.get(card.item_id, { json: true });
```

`unlock()` derives the key from a signature over a fixed statement. Ethereum's
ECDSA is deterministic, so the same wallet reproduces the same vault on any
machine — no recovery copy is held anywhere. Pass `{ passphrase }` to require a
second factor beyond the wallet.

Every item carries the weakest workspace trust class it may ever be released
into. New items default to `confidential`, which is above anything the network
serves today, so `releaseInto` refuses rather than exposing a secret to a host
that can read it:

```js
await agent.vault.releaseInto(lease, card.item_id, { json: true }); // throws on open capacity
```

Lowering an item's floor is deliberate and reseals the item. Allowed releases
are recorded and readable with `agent.vault.releases()`.

The account, item slot, version and trust floor are authenticated into the
ciphertext, so a service that moved an item between accounts, replayed an older
version, or lowered its floor would produce a failed decrypt rather than a
plausible wrong answer. See [docs/VAULT.md](../docs/VAULT.md).

## Auth

`authenticate()` fetches a challenge (`GET /api/agent/challenge`), signs the message with the wallet, and exchanges it for a session (`POST /api/agent/session`). The session is a bearer token used on every `/api/agent/proxy/*` call. No shared secret, no cookie. The wallet is the identity (`subject = wallet:0x...`).

## Payment

`lease()` (and the lower-level `fund()`) reproduce the escrow's quote binding: `clientReference = keccak256(quote_id)`, `approve(escrow, maximum_escrow)`, then `createLease(...)`, waiting 12 confirmations.

## Funding

The wallet needs two balances on Robinhood Chain (id 4663): USDG (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`, 6 decimals) for the lease deposit, and native ETH for gas. Bridge from L1 to fund a fresh wallet. `authenticate()`, `offers()`, and `quote()` need neither, so the read paths work before you fund anything.

## Requirements

Node >= 20, `viem` ^2 (peer), and `ssh` + `ssh-keygen` on PATH for `run()`.

See `example.mjs` for a full run.
