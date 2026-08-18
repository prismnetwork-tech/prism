# Managed inference

One LLM generation on a rented GPU, priced per request. The caller does not
lease a machine or hold one open; Prism keeps a warm GPU and bills per call.

## Models

    GET https://api.prismnetwork.tech/inference/v1/models

Free, no payment. Returns the list currently served, and the rate card:

    {"models": ["llama3.2:3b", "llama3.1:8b"],
     "pricing": {"llama3.2:3b": {"base_micros": 5000, "per_token_micros": 10,
                                 "full_cap_micros": "15240"},
                 "llama3.1:8b": {"base_micros": 10000, "per_token_micros": 25,
                                 "full_cap_micros": "35600"}},
     "state": "warm"}

This is the cheapest way to plan a call. The price of a generation is
`base_micros + per_token_micros * num_predict`, so the cost is known before
anything is signed, and `full_cap_micros` is the worst case at the maximum
output cap. `state` says whether a GPU is already warm, which is the difference
between an answer in seconds and one after a lease and a model pull.

## Asking for a generation

    POST https://api.prismnetwork.tech/inference/v1/inference
    Content-Type: application/json

    {"model": "llama3.2:3b", "prompt": "...", "options": {"num_predict": 64}}

`model` and `prompt` are required. `options.num_predict` caps the output length
and is worth setting, because the price is the model's base rate plus its
per-token rate over the cap you ask for. A smaller cap is a smaller quote.

Unpaid, this answers `402` with the price on each rail. Paid, it answers `200`
with the generation:

    {"model": "llama3.2:3b", "response": "...",
     "usage": {"prompt_tokens": 33, "completion_tokens": 5, "duration_ms": 3656},
     "lease_id": 1074}

`lease_id` identifies the onchain GPU lease that served the request. It settles
publicly and can be read back from the receipt feed at
`https://api.prismnetwork.tech/proof/index.json`.

## Warm-up

A cold network needs to lease a GPU and pull the models, which takes minutes.
While that happens the endpoint answers:

    503 {"error": "warming_up", "state": "warming", "retry_after_seconds": 90,
         "retry": "nothing was charged; send the same payment header again."}

Nothing was charged. Wait and send the same header again. Do not sign a new
authorisation: the first one is unconsumed and still valid, and signing another
risks paying twice for one answer.

If warm-up fails outright the state is `cold` and the endpoint says how long it
is holding off before trying again. That is a cooldown after a failure, not a
refusal to serve, and it clears on its own.

## Pricing, concretely

The 402 carries a `quote` alongside the payment options:

    "quote": {"model": "llama3.2:3b", "output_cap": 1024, "price_micros": "15240"}

`price_micros` is in millionths of a dollar, and both stablecoins carry six
decimals, so the figure is the same number of atomic units on either rail. A
24-token cap on `llama3.2:3b` quoted 5240 micros, which is 0.00524 of either
stablecoin.
