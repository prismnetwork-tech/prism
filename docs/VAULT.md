# Vault

The vault stores cards, identity documents, API credentials and recovery codes
encrypted under a key derived on the renter's machine. Prism holds ciphertext.
It cannot read an item, and it cannot hand one to a host, because it never has
the key.

This is separate from a workspace on purpose. A workspace is rented hardware
someone else administers, and on today's capacity its operator can read
anything in it. A renter's data does not have to live there to be useful, and
the earlier guidance to keep private data off the network entirely came from
treating those as one question.

## What holds it up

Each item is sealed with a random AES-256-GCM data key, and that data key is
wrapped under a root key derived by HKDF-SHA256 from a wallet signature over a
fixed, domain-separated statement. Ethereum's ECDSA is deterministic (RFC
6979), so the same wallet reproduces the same root key on any machine: the
vault survives a lost laptop without Prism keeping a recovery copy. An optional
passphrase is mixed into the HKDF salt, so a stolen signature alone is not
enough.

GCM's associated data binds four fields alongside the ciphertext:

```
prism.vault.v1\0<subject>\0<item_id>\0<version>\0<trust_floor>\0
```

That turns three plausible attacks by the service itself into failed decrypts
rather than successful lies:

- **Moving an item between accounts or slots.** The subject and item id are
  authenticated, so a blob served in the wrong place does not open.
- **Rolling an item back.** The version is authenticated, and `open()` takes an
  `expectVersion` so a caller that recorded a version detects being served an
  older one.
- **Quietly lowering the trust floor.** The floor is a policy field the service
  must be able to read to enforce it, which normally means it can also edit it.
  Because it is authenticated, editing it breaks the seal. The policy is
  cryptographically bound, not merely stored.

`vault_associated_data` in `prism-protocol` and `associatedData` in the SDK
produce these bytes independently and are pinned to a shared test vector in
both languages.

## The trust floor

Every item carries the weakest trust class of workspace it may ever be shown
to. `releaseInto` is the only path that authorizes an item into a running
lease, and the control plane refuses when the lease's class sits below the
item's floor.

New items default to `confidential`, which is above `MAX_VERIFIABLE_TRUST_CLASS`
and therefore above anything the network can serve. The default is not
decoration: it means storing a card and then asking an agent to use it inside a
rented box fails loudly instead of leaking it. Lowering an item's floor is a
deliberate act that reseals the item.

The floor exists for the agent case specifically. A person who decrypts their
own card and pastes it into their own GPU box has made a choice. An autonomous
agent that does the same because a policy check was skipped has made a mistake,
and the refusal turns that mistake into an error message.

Every authorized release is recorded and readable at `GET /v1/vault/releases`,
so a renter can see afterwards exactly what an agent exposed and where. A
refused release records nothing; only real exposure is logged.

## What it does not do

The vault does not make a workspace confidential. Once an item is released into
a lease, that lease's trust class governs what happens to it, which is why the
default puts every new item out of reach of `open` capacity.

It does not protect against a compromised client. The key is derived where your
code runs; anything with that process's memory has the vault. Signing the vault
statement in untrusted software gives away every item, which is why the
statement says so in the text the wallet displays.

It does not hide item count, sizes, write times, or labels. A label is optional
and exists so a listing is navigable; leave it empty and the listing is opaque.

## API

All routes require an authenticated renter identity and act only on that
account's items.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/vault/items` | List sealed items, newest first |
| `GET` | `/v1/vault/items/{id}` | Fetch one sealed item |
| `PUT` | `/v1/vault/items/{id}` | Create, or replace via `previous_version` |
| `DELETE` | `/v1/vault/items/{id}` | Delete an item |
| `POST` | `/v1/vault/items/{id}/release` | Authorize an item into a lease |
| `GET` | `/v1/vault/releases` | Read the release history |

Writes are compare-and-set: omitting `previous_version` creates and fails on an
occupied slot, and supplying it replaces exactly that version. Two agents
writing the same item cannot silently drop one of the writes.

Ciphertext is capped at 160 KiB per item and 512 items per account.

## Use

```js
import { PrismAgent } from "@prismnetwork/agent-sdk";

const agent = new PrismAgent({ privateKey: process.env.AGENT_KEY, escrow });
await agent.vault.unlock();

const card = await agent.vault.put(
  { pan: "4111111111111111", exp: "09/29" },
  { label: "billing card" },
);

// Sealed at the default floor, so this refuses on today's open capacity
// instead of posting the card to a host that can read it.
await agent.vault.releaseInto(lease, card.item_id, { json: true });
```

Read it back on any machine holding the same wallet:

```js
await agent.vault.unlock();
const value = await agent.vault.get(card.item_id, { json: true });
```
