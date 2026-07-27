# @prismnetwork/x402

Pay-per-job GPU compute on [Prism Network](https://prismnetwork.tech) over HTTP 402. An agent submits a command, pays a stablecoin, and gets the output. No lease management, no wallet-signature session.

Payment is accepted in **USDC on Base** or USDG on Robinhood Chain. Base is there because that is what x402 clients actually hold: an endpoint quoting only Robinhood Chain cannot be paid by any of them.

## Flow

```
POST /run  { "command": "nvidia-smi" }
  -> 402 { accepts: [ { network: "eip155:8453", asset: USDC, payTo, maxAmountRequired },
                      { network: "eip155:4663", asset: USDG, payTo, maxAmountRequired } ] }
```

Pick an entry, pay `maxAmountRequired` of its `asset` to its `payTo`. Then sign the tx hash (`personal_sign`) with the paying wallet and send it as the payment header:

```
X-PAYMENT: base64(JSON({ txHash, signature, network }))

POST /run  { "command": "nvidia-smi" }   header X-PAYMENT: <base64 envelope>
  -> 202 { job_id, token, poll: "/jobs/<id>" }

GET /jobs/<id>   header Authorization: Bearer <token>
  -> { status: "completed", exit_code, stdout, stderr }
```

The signature binds the payment to you, so a third party who sees your tx hash cannot claim the job. The server verifies the on-chain USDG `Transfer` to `payTo` (amount >= price, 12 confirmations, sent by the signer, not already used), then leases a GPU with its own wallet, runs the command, returns the output, and releases the lease. If the lease or run fails, it refunds the payment.

## Run

```
PRISM_AGENT_KEY=0x..     \    # server wallet that funds leases (needs USDG + gas)
PRISM_ESCROW=0x71Df..    \
X402_PAY_TO=0x..         \    # collects USDG on Robinhood Chain
X402_BASE_PAY_TO=0x..    \    # collects USDC on Base; omit to not offer Base
X402_BASE_RPC_URL=https://mainnet.base.org \
X402_PRICE_MICROS=300000       # 0.30 of either stablecoin per job
node server.mjs
```

A payer who is refunded is refunded on the network they paid on, so the server
wallet needs a USDC and gas balance on Base as well to honour a Base payment
that fails. When a refund cannot be sent, the job record carries `refund_owed`
with the address, amount and network rather than losing it to a log line.

Install with `npm install @prismnetwork/x402`, or run it directly with `npx @prismnetwork/x402`.

Other env: `X402_PORT` (8402), `X402_DURATION_SECONDS` (900), `X402_MIN_VRAM_MIB` (16000), `X402_PAYMENTS_FILE`, `PRISM_API_BASE`, `PRISM_RPC_URL`. The consumed-payments file makes replay protection survive a restart; a multi-instance deployment needs a shared store instead.
