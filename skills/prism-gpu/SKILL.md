---
name: prism-gpu
description: Use when the user wants GPU compute, an LLM generation without an API key, or wants to run a command on a rented GPU, and when an agent needs to pay for compute over HTTP 402 / x402. Covers Prism Network's paid endpoints, how they are priced, and what the payment rails are.
license: MIT
metadata:
  author: prism-network
  version: "0.1.0"
---

# Prism Network GPU compute

Prism rents GPUs by the second and sells two things over HTTP. There is no
account and no API key: a request is authorised by paying for it.

Every paid endpoint answers an unpaid request with `402 Payment Required` and
the exact price. The caller signs an EIP-3009 authorisation for that amount and
retries with the payment header. The authorisation is broadcast by Prism, so the
caller needs no gas on either chain.

## Routing

| User intent | Endpoint | Reference |
| --- | --- | --- |
| One LLM generation, no API key | `POST /inference/v1/inference` | [inference.md](references/inference.md) |
| Which models are available | `GET /inference/v1/models` | [inference.md](references/inference.md) |
| Run a shell command on a GPU | `POST /x402/run` | [run.md](references/run.md) |
| How to actually pay a 402 | any of the above | [paying.md](references/paying.md) |
| What the network sells, machine readable | `GET /.well-known/x402.json` | [paying.md](references/paying.md) |

Base URL for all of them: `https://api.prismnetwork.tech`

## Before paying anything

Read the 402 first. It carries the price for this specific request, and the
price depends on what was asked for, so a quote from an earlier call is not
binding on this one. Show the caller the amount and the network before signing.

`GET /inference/v1/models` is free and needs no payment at all. Use it to check
what is available rather than guessing a model name and paying for a rejection.

## What the caller is charged

Nothing until they get something back.

- A payment is consumed only when a response is served. A request that fails
  before the work is done charges nothing.
- `503 warming_up` means a GPU is being leased and the models are being pulled.
  Nothing was charged. Retry with the same payment header; it is still valid.
- A consumed payment replays its own result. Sending the same header again
  returns the same response rather than charging a second time.
- `POST /x402/run` charges only if the command exits zero.

## Payment rails

Two, and the caller picks by choosing which offer in `accepts` to sign:

- USDC on Base, `eip155:8453`
- USDG on Robinhood Chain, `eip155:4663`, which is where the GPU lease itself
  settles

Both use the `exact` scheme with EIP-3009, and both offers carry the EIP-712
domain the signer needs in `extra`. Neither requires the caller to hold gas.

## Do not

- Do not invent a model name. Read `GET /inference/v1/models`.
- Do not retry a paid request with a *new* payment header after a `503`. The
  first one was not consumed, and signing a second authorisation risks paying
  twice for one answer.
- Do not treat a quote as fixed. Re-read the 402 for each new request.
