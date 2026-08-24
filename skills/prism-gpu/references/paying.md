# Paying a Prism endpoint

Prism speaks x402. An unpaid request returns `402` with one or more payment
options; the caller signs one and retries with the payment header. There is no
API key anywhere in the flow, because the signature is the authorisation.

If the agent already has an x402 client, use it. MetaMask Agent Wallet ships one
that handles both rails, and any client supporting the `exact` scheme on EVM
will work. The rest of this file is what such a client needs to know, and what
to do if you are constructing the payment yourself.

## Reading the 402

Protocol v2 puts the challenge in the `PAYMENT-REQUIRED` response header and the
payment in `PAYMENT-SIGNATURE` on the retry. v1 puts the challenge in the body
and the payment in `X-PAYMENT`. Prism serves both; a client that sends neither
header gets v2.

Each entry in `accepts` is one option:

    {"scheme": "exact",
     "network": "eip155:4663",
     "amount": "3072",
     "asset": "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168",
     "payTo": "0xEcaaE714912C38fA7e0dAF78afa7C54DbeD11039",
     "maxTimeoutSeconds": 60,
     "extra": {"name": "Global Dollar", "version": "1",
               "assetTransferMethod": "eip3009"}}

`extra.name` and `extra.version` are the EIP-712 domain for that token. Sign
against those rather than reading the domain off-chain or assuming it from the
symbol: USDC on Base uses the name `USD Coin`, and USDG uses `Global Dollar`.
Signing against a guessed domain produces a well-formed signature the token
rejects, and the failure does not say why.

## The two rails

| Network | Token | Where the lease settles |
| --- | --- | --- |
| `eip155:8453` Base | USDC | no |
| `eip155:4663` Robinhood Chain | USDG | yes |

Pick either. Base is convenient for agents already holding dollars on a major
L2. Robinhood Chain is where the GPU lease itself settles, so paying there keeps
the whole transaction on one chain.

## Signing

`exact` on EVM means an EIP-3009 `TransferWithAuthorization`: an off-chain
signature permitting a pull of exactly `amount` to `payTo`, valid for a window.
The caller broadcasts nothing and needs no native gas on either chain. Prism
broadcasts the authorisation when it settles.

Types are the standard EIP-3009 set: `from`, `to`, `value`, `validAfter`,
`validBefore`, `nonce`. The domain is `{name, version, chainId, verifyingContract}`
where name and version come from `extra` and `verifyingContract` is `asset`.

## Retrying

The retry carries the base64 payment envelope in `PAYMENT-SIGNATURE` (v2) or
`X-PAYMENT` (v1), and repeats the original method and body unchanged. A
different body is a different request and the payment will not match it.

On success the response carries `PAYMENT-RESPONSE` with the settlement:

    {"success": true, "transaction": "0x...", "network": "eip155:4663",
     "payer": "0x..."}

That transaction hash is real and readable on the chain named beside it.

## Discovery

    GET https://api.prismnetwork.tech/.well-known/x402.json

Lists what the network sells, with prices and the payment options for each.
Free, and the right place to start if you are deciding whether to call anything
at all.
