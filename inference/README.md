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

A second class of model is not served here at all. Those requests are relayed to
a Phala GPU TEE, which signs a receipt over the bytes it received and the bytes
it returned, and the caller can encrypt the prompt so that the relay carries
ciphertext. See [Confidential generations](#confidential-generations).

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
the `payTo` address, and the chain (`eip155:4663`). Pay it, then `personal_sign`
the transfer together with the request it buys and retry with
`X-PAYMENT: base64({txHash, signature})`:

```
message = "prism-x402:v2\n" + txHash.toLowerCase() + "\n" + sha256hex(request body)
```

The response carries the generation, token usage, and the id of the lease that
served it. Binding the payment to the body is what stops anyone who reads the
header in flight from redeeming it against a prompt of their own; the gateway
hashes the bytes that arrived and checks them against what was signed.
`@prismnetwork/agent-sdk` does this for you, and so does the Python SDK's
`payment_header`.

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

A payment is consumed only when a response is served. If no GPU is warm yet the
answer is `429`. If one could not be brought up for the request, or took it and
could not answer, the answer is `503`. Either way the same `X-PAYMENT` header
works on the retry.
`GET /v1/stats` reports generations served, tokens, revenue, and leases warmed
since boot.

The first paid request on a cold gateway waits through provisioning, usually
one to four minutes. `POST /v1/warm` (free) starts that early, before there is
a payment waiting on it.

A `429 warming_up` carries `state` and `retry_after_seconds`. The estimate is
minutes because a cold start leases a GPU onchain, waits for confirmations,
boots the box and pulls the model. `GET /v1/models` reports the same state for
free, so a caller that wants to avoid paying into a cold start can check there
first and only pay once a GPU is warm.

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
unpaid `402` quotes the exact figure. For the two-prompt call above that is
`2 x (3000 + 3 x 1024) = 12144` micros: a `llama3.2:3b` base of 3000 plus 3 per
token over the 1024-token cap, which is the default when the request names no
`num_predict`. Every prompt runs whole on one GPU, the
same way a single request does; what the batch adds is that they run on all the
gateway's GPUs at once, and a box still warming joins the work as it comes up
rather than after the batch has finished without it. A batch is all or nothing:
if a prompt cannot be answered even after a retry on another box, the answer is
`503`, and the same payment header works on the retry.

### Reproducing the Merkle root

The receipt is a Merkle tree in the RFC 6962 style, so an independent verifier
can recompute the root from the items it received. Four details decide whether
the leaf hash comes out right, and none of them are guessable:

1. **The leaf is a fixed field order**, not whatever order your object happens
   to have. Serialise exactly these keys, in this order, as compact JSON with
   no spaces:

   ```
   index, model, prompt, response, prompt_tokens, completion_tokens, lease_id
   ```

2. **`prompt` and `response` are digests, and they keep their `sha256:`
   prefix.** Each is `sha256:` followed by the lowercase hex SHA-256 of the
   UTF-8 text. The prefix is part of the bytes that get hashed. Stripping it
   changes the leaf.

3. **Absent values are `null`, never omitted.** `prompt_tokens`,
   `completion_tokens` and `lease_id` are always present as keys; when unknown
   they serialise as `null`.

4. **Leaves and interior nodes are hashed under different prefixes**, so no
   interior node can be replayed as a leaf:

   ```
   leaf   = SHA-256(0x00 || utf8(canonical_item))
   node   = SHA-256(0x01 || left_hash || right_hash)
   ```

   Both prefixes are single raw bytes, not the text `"0x00"`.

Pairs combine left to right at each level. **An odd node at the end of a level
is promoted unchanged to the next level; it is not duplicated or paired with
itself.** `merkle_root` and every hash in an audit path are rendered as
`sha256:` plus lowercase hex.

To check one item: hash its canonical form into a leaf, then fold the audit
path, applying each sibling on the side its `side` field names, and compare the
result with `merkle_root`.

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
  "paid_micros": "12144",
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

## Confidential generations

There is a second class of model on this gateway that Prism does not serve. A
confidential request is relayed to Phala's attested gateway, where the model
runs inside an Intel TDX enclave on an NVIDIA GPU, and the enclave signs a
receipt over the exact bytes of your request and the exact bytes of its answer.
You pay Prism the same way you pay for anything else here, and you can check the
work yourself rather than take our word for it.

```sh
curl -s -X POST http://localhost:8500/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
        "model": "phala/gemma-4-26b-a4b-uncensored",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "What is a prism?"}]
      }'
```

The body and the response are the OpenAI chat-completions shape. With no payment
this answers `402` with the price for the `max_tokens` you asked for, exactly
like `/v1/inference`. `max_tokens` is required on this route: your bytes go
upstream unchanged, so a cap the gateway cannot rewrite is a cap you have to
state.

Set `stream` to `true` and the answer comes back as server-sent events, each
frame written the moment the enclave produces it. The receipt covers the whole
stream, framing included, so hash the bytes you read off the wire from the first
frame to the last. Two things differ from a buffered answer. The payment settles
after the final frame rather than before the body, so a streamed response
carries no `PAYMENT-RESPONSE` header. And a stream that stops before its
terminator closes with one error frame naming the truncation: the status was
sent long before the enclave stopped and cannot be withdrawn, nothing is
charged, and the same payment header buys the retry. Add
`stream_options.include_usage` if you want the token counts; a stream carries
none without it.

The response carries `X-Receipt-Id`, the enclave's `X-ACI-Version` and
`X-ACI-Keyset-Digest`, and any `X-E2EE-*` headers it set. Fetch the receipt
promptly; upstream keeps them in memory and a restart loses them.

### What the gateway reads

Three fields, `model`, `max_tokens` and `stream`, taken with a parse that never
touches the buffer it forwards. Your request reaches the enclave as the bytes
you sent, and the enclave's answer reaches you as the bytes it returned. That
is the whole contract of this route: any re-serialization, however faithful,
would change a hash the signed receipt commits to, and every check you can run
on it would fail. Message content is never logged; the log line for a
confidential request carries the model, the token counts, the upstream cost,
and the receipt id.

Send the five `X-E2EE-*` headers and the gateway passes them straight through.
Message content is then encrypted to the enclave's public key, which is bound
into the attested keyset, and the relay carries ciphertext it cannot read. The
[E2EE v2 specification](https://github.com/Dstack-TEE/private-ai-gateway) defines
the envelope; the Prism SDK implements it.

### Checking the work

Four free endpoints, unauthenticated and rate limited:

| Endpoint | What it gives you |
| --- | --- |
| `GET /v1/attestation?nonce=` | The TDX quote, the measured compose, and the workload keyset, bound to a nonce you choose (64 lowercase hex). |
| `GET /v1/receipts/{id}` | The signed receipt for one completion: the hash of the request bytes the enclave received, the hash of the response bytes it returned, and the upstream GPU verification outcome. |
| `GET /v1/sessions` and `GET /v1/sessions/{id}` | The attested upstream sessions currently serving, with the evidence each receipt cites. |
| `GET /v1/gpu-evidence?model=` | The GPU evidence in the shape NVIDIA's attestation service takes as a request body, so the GPU leg can be verified by NVIDIA rather than by us. |

Receipts are owned upstream by whoever paid for the completion, which is this
gateway. Relaying them under our key is what makes yours reachable.

### The trust boundary

What the attestation proves: a genuine Intel TDX enclave, running the measured
compose whose source commit the report names, holding the keys that signed your
receipt, in front of a GPU that NVIDIA attests with secure boot on and debug
off. What it does not prove: that TLS terminates inside that enclave, or who
holds the keys at rest. The protocol publishes no custody evidence today, and
the TLS key pin shows only that you reached the right terminator. End-to-end
encryption is the part that does not depend on either: with it on, the enclave's
key is the only one that can read your message content, and this gateway carries
bytes it cannot open.

Prism operates the relay and the verification tooling. Prism hardware does not
run these models. The `phala/` model ids are not pinned to a build upstream: the
attestation binds the workload that serves them, not the weights behind the
name.

### Rates

| Model | Base | Per output token | A 256-token answer | Full 1024-token answer |
| --- | --- | --- | --- | --- |
| `phala/gemma-4-26b-a4b-uncensored` | 10000 | 5 | $0.011280 | $0.015120 |
| `phala/qwen3.6-35b-a3b-uncensored` | 20000 | 10 | $0.022560 | $0.030240 |

These cover what the upstream charges rather than what a lease burns, at roughly
eight times the upstream catalog price at the caps this route enforces: a 32 KiB
body and 1024 output tokens.

`GET /v1/provider/models` (free) publishes the same rates as a provider
catalogue, in the model-discovery format inference aggregators poll: the base
price as a per-request charge, the per-token rate as a completion price, the
output cap and the request-body limit, and a daily request ceiling worked out
from the spend cap below. Only the confidential tier appears there. The open
tier leases a GPU per request, and a cold start reads as unavailability to
anything scoring the endpoint.

The daily cap is `INFERENCE_CONFIDENTIAL_DAILY_USD`. A request is counted
against it before it is relayed: the gateway holds the request's own quoted
price against the day while the call is in flight, then replaces that figure
with the upstream's `usage.cost` once a response carries one. A response with no
cost keeps the held figure, and the gateway logs once that the upstream stopped
reporting. A request the day's remaining room cannot cover answers `429` with
`retry-after: 3600` and nothing charged, so set the cap above the full-cap price
of one call.

A confidential payment is consumed only when a response is served, the same rule
as everywhere else here. An upstream that is out of quota, rate limited, or down
answers `503` and leaves your payment header good for the retry. One that did
serve replays its own answer byte for byte, marked with `X-Prism-Replayed`, so a
lost connection costs you nothing.

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
| `INFERENCE_HOST` / `INFERENCE_TOKEN` | Listen address (default `127.0.0.1`) and the credential any wider address requires. See below. |
| `INFERENCE_PAYMENTS_FILE` | Consumed-payment ledger (default `./inference-consumed.log`). |
| `INFERENCE_CONFIDENTIAL` | Turns the confidential class on. JSON, see below. Unset leaves those routes answering 404. |
| `INFERENCE_CONFIDENTIAL_DAILY_USD` | Upstream spend the confidential relay may commit in a UTC day, in-flight requests included (default 1.0). Set it above one call's full-cap price. |
| `PHALA_API_KEY` | The upstream bearer, named by `key_env`. Server-side only. |

```json
{
  "upstream": "https://tee.redpill.ai/v1",
  "key_env": "PHALA_API_KEY",
  "models": { "phala/gemma-4-26b-a4b-uncensored": {} }
}
```

`models` is the allowlist: a model that is not listed is refused before anything
is charged. An empty object per model takes the shipped rates above, and
`{"base_micros": 12000, "per_token_micros": 6}` overrides them. `legacy_upstream`
moves the GPU evidence host off its `https://api.redpill.ai/v1` default.

The upstream key belongs in the deployment's environment file and nowhere else.
It is read once at boot, never returned by any route, and never written to a
log line. Callers reach the upstream only through the endpoints above, and the
free ones are rate limited so the gateway does not become an open proxy for a
key it pays for.

Generations are capped at 1024 output tokens and prompts at 32 KiB, so the
price bounds what one request can spend of the warm window. `ssh` and
`ssh-keyscan` must be on `PATH`; each box's ollama is reachable only through its
own tunnel, on `INFERENCE_TUNNEL_PORT` plus the slot number. Every prompt crosses
that tunnel, so the box on the far end is checked against the SSH host key the
lease publishes before it carries anything. Where the lease publishes none, which
is every box brokered from a public cloud, the key is taken on first sight and
held for the rest of the lease.

Every GPU in the pool is a separate prepaid lease running whether or not
anything asks for it, which is why the default pool is one. Raise
`INFERENCE_POOL_MAX` when there is batch traffic to pay for it; a batch small
enough to run on the GPUs already warm never leases another.

## Reaching it from another machine

The gateway holds the operator's own funded wallet: warming leases a GPU against
it, and the free routes name the leases and the takings. None of that sits behind
an account, so it listens on `127.0.0.1` and refuses to start on a wider address
unless you give it a credential:

```
INFERENCE_HOST=0.0.0.0
INFERENCE_TOKEN=<at least 16 random characters>
```

Callers then send `Authorization: Bearer <token>` on every route, `/healthz`
included, so a liveness probe needs the header too. A public deployment puts a
reverse proxy in front and has the proxy hold the credential, which leaves the
front door as the only way in while the paid endpoints stay open to anyone who
pays. In Caddy that is one line on the route:

```
reverse_proxy inference:8500 {
	header_up Authorization "Bearer {$PRISM_INFERENCE_TOKEN}"
}
```

Prism is pre-production and unaudited. The gateway wallet should hold only
what you are prepared to lose.
