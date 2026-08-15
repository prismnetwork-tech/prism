# @prismnetwork/inference-gateway

Managed inference on Prism Network GPUs. The gateway keeps a leased GPU warm
with ollama and the configured models, and sells single generations over HTTP
for USDG on Robinhood Chain via x402. Callers never touch a lease, an SSH key,
or an image digest: pay the quoted price, get the generation.

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

A payment is consumed only when a response is served. If the box is still
warming or the generation fails, the answer is `503` and the same `X-PAYMENT`
header works on the retry.

The first paid request on a cold gateway waits through provisioning, usually
one to four minutes. `POST /v1/warm` (free) starts the warmup early, and
`GET /v1/models` reports the models, price, and current state.

## Configuration

| Variable | Meaning |
| --- | --- |
| `PRISM_AGENT_KEY` / `PRISM_ESCROW` | The wallet and escrow the gateway leases with. |
| `INFERENCE_PAY_TO` | Address paid generations must reach. |
| `INFERENCE_MODELS` | Comma list of ollama models to preload (default `llama3.2:3b`). |
| `INFERENCE_PRICE_MICROS` | Price per generation in USDG micros (default 10000 = 0.01 USDG). |
| `INFERENCE_WARM_SECONDS` | Lease length per warm window (default 1800). |
| `INFERENCE_IDLE_SECONDS` | Idle time before the box is allowed to lapse (default 600). |
| `INFERENCE_PORT` / `INFERENCE_TUNNEL_PORT` | HTTP port (8500) and local ollama tunnel port (11435). |
| `INFERENCE_PAYMENTS_FILE` | Consumed-payment ledger (default `./inference-consumed.log`). |

Generations are capped at 1024 output tokens and prompts at 32 KiB, so the
flat price bounds what one request can spend of the warm window. `ssh` must be
on `PATH`; the box's ollama is reachable only through the gateway's tunnel.

Prism is pre-production and unaudited. The gateway wallet should hold only
what you are prepared to lose.
