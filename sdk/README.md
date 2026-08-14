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
  escrow: "0x62C042265991bEa17B07229322A01850974626dA",
});

await agent.authenticate();
const lease = await agent.lease({ image: DEFAULT_IMAGE, durationSeconds: 900, minVramMib: 16000 });
const out = await agent.run(lease, "nvidia-smi");
console.log(out.stdout);
agent.endLease(lease);
```

`image` must be an immutable digest-pinned reference (`repo@sha256:...`). `DEFAULT_IMAGE` is one; a plain tag is rejected.

## Toolset

`@prismnetwork/agent-sdk/toolset` exports `PrismToolset`, the framework-neutral
tool surface the MCP server and the framework plugins (elizaOS, Virtuals GAME)
wrap: `wallet`, `listGpus`, `leaseAndRun`, `run`, `endLease`, each returning a
human-readable string. It holds the wallet, the open leases and the per-lease
spending cap in one place, reads `PRISM_AGENT_KEY`/`PRISM_ESCROW` from the
environment by default, and answers the read-only questions from the public API
when no wallet is configured.

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

## Workspaces

A lease destroys its machine, so training output, checkpoints and a working
directory need somewhere that outlives it. A workspace is that place: the SDK
archives a directory off the leased box, seals it here under a key derived from
your wallet, and uploads the ciphertext straight to object storage. Prism
records the version, the size and the hash, and holds nothing that opens it.

```js
await agent.workspace.unlock();

const ws = await agent.workspace.create("finetune-run");
const saved = await agent.workspace.save(lease, ws, "/root/out");

// On a later lease, onto a fresh machine.
await agent.workspace.restore(next, ws, "/root/out", { expectVersion: saved.version });
```

The workspace key comes from a different statement and a different salt than
the vault's, so opening one does not open the other. Pass `{ passphrase }` to
require a second factor beyond the wallet.

A restore hashes the downloaded ciphertext and compares it to the digest
recorded at save time before it decrypts anything, so bytes altered in storage
are reported as tampering rather than as a wrong key. The account, workspace,
version and trust floor are authenticated into the ciphertext, so a snapshot
served for the wrong workspace, or under a floor that has been rewritten, fails
to open rather than returning a plausible wrong answer.

An older snapshot is a different case worth being precise about: its own
associated data is genuine for its own version, so it decrypts cleanly and
nothing in the ciphertext gives it away. A restore therefore compares the
version it was granted against the version the record says is current, and
refuses a rollback on that basis. Pass `expectVersion` to pin a specific one,
and `expectTrustClass` to refuse a floor that has moved.

A restore names the lease it is landing on, and Prism refuses to issue the
download at all when that lease's trust class is below the workspace's floor.
The check is server-side deliberately: a client-side one would be a courtesy
that a modified client could skip.

Bulk data never passes through Prism. Uploads and downloads use presigned URLs
that live fifteen minutes, and they are used from your process, never handed to
the leased machine. The machine only ever sees `tar` and `base64`, which is all
this needs from it.

Snapshots travel over the lease's SSH channel, which caps a single save at 64
MiB of archive; a larger directory is refused on the machine before anything is
transferred. New workspaces default to the `open` trust floor, unlike vault
items: their contents are the files you are already handing to a rented box.
Raise it at creation when they deserve more:

```js
await agent.workspace.create("model-weights", { minTrustClass: "isolated" });
```

## Auth

`authenticate()` fetches a challenge (`GET /api/agent/challenge`), signs the message with the wallet, and exchanges it for a session (`POST /api/agent/session`). The session is a bearer token used on every `/api/agent/proxy/*` call. No shared secret, no cookie. The wallet is the identity (`subject = wallet:0x...`).

## Payment

`lease()` (and the lower-level `fund()`) reproduce the escrow's quote binding: `clientReference = keccak256(quote_id)`, `approve(escrow, maximum_escrow)`, then `createLease(...)`, waiting 12 confirmations.

## Funding

The wallet needs two balances on Robinhood Chain (id 4663): USDG (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`, 6 decimals) for the lease deposit, and native ETH for gas. Bridge from L1 to fund a fresh wallet. `authenticate()`, `offers()`, and `quote()` need neither, so the read paths work before you fund anything.

## Requirements

Node >= 20, `viem` ^2 (peer), and `ssh` + `ssh-keygen` on PATH for `run()` and
for workspace save and restore.

See `example.mjs` for a full run.
