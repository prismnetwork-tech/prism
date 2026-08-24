# @prismnetwork/inference-gateway

Managed inference on Prism Network GPUs. The gateway keeps leased GPUs warm
with ollama and the configured models, and sells generations over HTTP for USDG
on Robinhood Chain via x402. Callers never touch a lease, an SSH key, or an
image digest: pay the quoted price, get the generation.

Ask for one prompt and one GPU answers it. Ask for a hundred and they go out
across every GPU the gateway holds at once, so the batch finishes in about the
time the slowest box needs rather than the sum of all of them.

The gateway is itself a renter. It leases through the same escrow as everyone
else with its own funded wallet, pays per second, and its leases settle with
the same public receipts.

## Run it

```sh
PRISM_AGENT_KEY=0x... \
PRISM_ESCROW=0x62C042265991bEa17B07229322A01850974626dA \
INFERENCE_PAY_TO=0x... \
npx -y @prismnetwork/inference-gateway
```

## Use it

```sh
curl -s -X POST http://localhost:8500/v1/inference \
  -H 'content-type: application/json' \
  -d '{"model": "llama3.2:3b", "prompt": "What is a prism?"}'
```

With no payment this answers `402` with the x402 requirements: the USDG price,
the `payTo` address, and the chain (`eip155:4663`). Pay it, sign the tx hash
with the paying wallet (`personal_sign`), and retry with
`X-PAYMENT: base64({txHash, signature})`. The response carries the generation,
token usage, and the id of the lease that served it.

The price scales with the request: each model has a base price plus a
per-token rate over the output cap you ask for (`options.num_predict`, up to
1024). The unpaid `402` quotes the exact figure for your request, and
`GET /v1/models` lists each model's rates next to `price_micros`, the highest
full-cap price, which always clears verification when paid.

## Rates

Prices are in USDG micros; both stablecoins carry six decimals, so the same
figure is the price on either rail.

| Model | Base | Per output token | A 256-token answer | Full 1024-token answer |
| --- | --- | --- | --- | --- |
| `llama3.2:3b` | 3000 | 3 | $0.003768 | $0.006072 |
| `llama3.1:8b` | 6000 | 6 | $0.007536 | $0.012144 |

The base covers the warm window. Keeping a GPU leased costs 222 micros a
second and the lease settles on the seconds the node ran, so an 1800-second
window is 399,600 micros that are spent whether or not anyone calls. The
per-token rate covers the lease time the tokens themselves burn, measured end
to end under ollama: about 2.5 micros a token for `llama3.2:3b` and 5.1 for
`llama3.1:8b` on hardware slower than anything the network offers.

Set `options.num_predict` to what you actually want. The quote is priced on the
cap, not on what the model happens to produce, so an uncapped request for a
one-line answer pays for 1024 tokens.

A payment is consumed only when a response is served. If the box is still
warming or the generation fails, the answer is `503` and the same `X-PAYMENT`
header works on the retry. `GET /v1/stats` reports generations served, tokens,
revenue, and leases warmed since boot.

The first paid request on a cold gateway waits through provisioning, usually
one to four minutes. `POST /v1/warm` (free) starts the warmup early, and
`POST /v1/warm?slots=N` brings N boxes up at once, which is what a batch
needs: a box leased after the prompts are already moving arrives too late to
take any of them. `GET /v1/models` reports the models, price, current state,
and how many GPUs are warm behind the endpoint.

## Batches

`POST /v1/batch` takes a list of prompts and one payment:

```sh
curl -s -X POST http://localhost:8500/v1/batch \
  -H 'content-type: application/json' \
  -d '{"model": "llama3.2:3b", "prompts": ["What is a prism?", "What is a GPU?"]}'
```

The price is the single-request price times the number of prompts, and the
unpaid `402` quotes the exact figure. Every prompt runs whole on one GPU, the
same way a single request does; what the batch adds is that they run on all the
gateway's GPUs at once, and a box still warming joins the work as it comes up
rather than after the batch has finished without it. A batch is all or nothing:
if a prompt cannot be answered even after a retry on another box, the answer is
`503` and the same payment header works on the retry.

### The receipt

A batch comes back with a Merkle receipt over the set:

```json
{
  "version": 1,
  "algorithm": "rfc6962-sha256",
  "model": "llama3.2:3b",
  "count": 2,
  "merkle_root": "sha256:...",
  "lease_ids": [1041, 1042],
  "payer": "0x...",
  "paid_micros": "30480",
  "settlement_tx": "0x...",
  "issued_at": "2026-08-24T09:00:00.000Z"
}
```

Each item carries the `commitment` its leaf was hashed over and the
`merkle_proof` from that leaf to the root, so one answer can be shown to belong
to the batch without disclosing any of the other prompts:

```js
import { verifyItem } from "@prismnetwork/inference-gateway/receipt";

verifyItem(item.commitment, item.merkle_proof, batch.receipt.merkle_root);
```

The tree is the RFC 6962 construction: a leaf is
`sha256(0x00 || canonical_json)`, an interior node is
`sha256(0x01 || left || right)`, and an odd node is promoted to the next level
rather than hashed against a copy of itself. The canonical JSON is the
`commitment` object with its fields in the order `index`, `model`, `prompt`,
`response`, `prompt_tokens`, `completion_tokens`, `lease_id`, where `prompt`
and `response` are `sha256:` digests of the text. `lease_ids` names the leases
that did the work, and those settle on-chain with their own public receipts, so
the chain runs batch root to item to lease to settlement.

## Configuration

| Variable | Meaning |
| --- | --- |
| `PRISM_AGENT_KEY` / `PRISM_ESCROW` | The wallet and escrow the gateway leases with. |
| `INFERENCE_PAY_TO` | Address paid generations must reach. |
| `INFERENCE_MODELS` | Comma list of ollama models to preload (default `llama3.2:3b`). |
| `INFERENCE_PRICE_MICROS` | Base price in USDG micros for every model, overriding the table above. Per-token rates are unaffected. |
| `INFERENCE_PRICING` | Per-model JSON overriding both, e.g. `{"llama3.2:3b":{"base":3000,"per_token":3}}`. |
| `INFERENCE_WARM_SECONDS` | Lease length per warm window (default 1800). |
| `INFERENCE_IDLE_SECONDS` | Idle time before a box is allowed to lapse (default 600). |
| `INFERENCE_POOL_MAX` | How many GPUs the gateway may hold at once (default 1). |
| `INFERENCE_BATCH_MAX_ITEMS` | Prompts allowed in one batch (default 64). |
| `INFERENCE_BATCH_ITEMS_PER_BOX` | Prompts a batch must carry before it is worth another GPU (default 25). |
| `INFERENCE_PORT` / `INFERENCE_TUNNEL_PORT` | HTTP port (8500) and local ollama tunnel port (11435). |
| `INFERENCE_PAYMENTS_FILE` | Consumed-payment ledger (default `./inference-consumed.log`). |

Generations are capped at 1024 output tokens and prompts at 32 KiB, so the
price bounds what one request can spend of the warm window. `ssh` must be on
`PATH`; each box's ollama is reachable only through its own tunnel, on
`INFERENCE_TUNNEL_PORT` plus the slot number.

Every GPU in the pool is a separate prepaid lease running whether or not
anything asks for it, which is why the default pool is one. Raise
`INFERENCE_POOL_MAX` when there is batch traffic to pay for it; a batch small
enough to run on the GPUs already warm never leases another.

Prism is pre-production and unaudited. The gateway wallet should hold only
what you are prepared to lose.
