# @prismnetwork/x402

Pay-per-job GPU compute on [Prism Network](https://prismnetwork.tech) over HTTP 402. An agent submits a command, pays a stablecoin, and gets the output. No lease management, no wallet-signature session.

Payment is accepted in **USDC on Base** or USDG on Robinhood Chain. Base is there because that is what x402 clients actually hold: an endpoint quoting only Robinhood Chain cannot be paid by any of them.

## Flow

```
POST /run  { "command": "nvidia-smi" }
  -> 402 { accepts: [ { network: "eip155:8453", asset: USDC, payTo, maxAmountRequired },
                      { network: "eip155:4663", asset: USDG, payTo, maxAmountRequired } ] }
```

Pick an entry, pay `maxAmountRequired` of its `asset` to its `payTo`. Then `personal_sign` the payment with the paying wallet and send it as the payment header. What you sign is the transfer and the request it buys together:

```
message   = "prism-x402:v2\n" + txHash.toLowerCase() + "\n" + sha256hex(request body bytes)
X-PAYMENT = base64(JSON({ txHash, signature, network }))

POST /run  { "command": "nvidia-smi" }   header X-PAYMENT: <base64 envelope>
  -> 202 { job_id, token, poll: "/jobs/<id>" }

GET /jobs/<id>?token=<token>
  -> { status: "completed", exit_code, stdout, stderr }
```

`@prismnetwork/agent-sdk/x402` exports `boundMessage` and `hashRequest`, and the Python SDK exports `bound_message` and `hash_request`, so a client does not have to spell the message out. The job token is also accepted as `Authorization: Bearer <token>` when the listener has no token of its own.

The signature binds the payment to you and to the command it buys. Someone who reads your header off the wire can neither claim the job nor spend the transfer on a command of their own. The server recomputes the digest over the exact bytes that arrived, so sign the body you are about to send rather than one built again for the signature. It then verifies the on-chain `Transfer` to `payTo` (amount >= price, 12 confirmations, sent by the signer, not already used), leases a GPU with its own wallet, runs the command, returns the output, and releases the lease. If the lease or run fails, it refunds the payment.

## Run

```
PRISM_AGENT_KEY=0x..     \    # server wallet that funds leases (needs USDG + gas)
PRISM_ESCROW=0x71Df..    \
X402_PAY_TO=0x..         \    # collects USDG on Robinhood Chain
X402_BASE_PAY_TO=0x..    \    # collects USDC on Base; omit to not offer Base
X402_BASE_RPC_URL=https://mainnet.base.org \
X402_PRICE_MICROS=300000       # 0.30 of either stablecoin per job
                               # must cover the lease deposit for the
                               # configured duration: rate_per_second x
                               # X402_DURATION_SECONDS. The service checks
                               # this at boot against live offers and says
                               # so if the price is short.
node server.mjs
```

A payer who is refunded is refunded on the network they paid on, so the server
wallet needs a USDC and gas balance on Base as well to honour a Base payment
that fails. When a refund cannot be sent, the job record carries `refund_owed`
with the address, amount and network rather than losing it to a log line.

Install with `npm install @prismnetwork/x402`, or run it directly with `npx @prismnetwork/x402`.

Other env: `X402_PORT` (8402), `X402_DURATION_SECONDS` (300), `X402_MIN_VRAM_MIB` (16000), `X402_PAYMENTS_FILE`, `PRISM_API_BASE`, `PRISM_RPC_URL`. The consumed-payments file makes replay protection survive a restart; a multi-instance deployment needs a shared store instead.

`PRISM_X402_ALLOW_UNBOUND_PAYMENT=1` also accepts the older signature over the bare tx hash, for the length of a migration. That is the replay the binding closes, so turn it off again.

## Reaching it from another machine

The server holds a wallet that funds leases, settles for callers, and hands back the output of jobs, and none of that sits behind an account. So it listens on `127.0.0.1` and refuses to start on a wider address unless you give it a credential:

```
X402_HOST=0.0.0.0
X402_TOKEN=<at least 16 random characters>
```

Callers then send `Authorization: Bearer <token>` on every route, `/healthz` and `/jobs` included, so a liveness probe needs the header too and a job is polled with `?token=<job token>`. Behind a reverse proxy, the proxy holds the credential and adds the header.
