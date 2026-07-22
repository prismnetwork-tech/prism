# @prism-network/x402

Pay-per-job GPU compute on [Prism Network](https://prismnetwork.tech) over HTTP 402. An agent submits a command, pays USDG on Robinhood Chain, and gets the output. No lease management, no wallet-signature session.

## Flow

```
POST /run  { "command": "nvidia-smi" }
  -> 402 { accepts: [{ scheme, network, asset, payTo, maxAmountRequired }] }
```

Pay `maxAmountRequired` USDG to `payTo` on Robinhood Chain. Then sign the tx hash (`personal_sign`) with the paying wallet and send it as the payment header:

```
X-PAYMENT: base64(JSON({ txHash, signature }))

POST /run  { "command": "nvidia-smi" }   header X-PAYMENT: <base64 envelope>
  -> 202 { job_id, token, poll: "/jobs/<id>" }

GET /jobs/<id>   header Authorization: Bearer <token>
  -> { status: "completed", exit_code, stdout, stderr }
```

The signature binds the payment to you, so a third party who sees your tx hash cannot claim the job. The server verifies the on-chain USDG `Transfer` to `payTo` (amount >= price, 12 confirmations, sent by the signer, not already used), then leases a GPU with its own wallet, runs the command, returns the output, and releases the lease. If the lease or run fails, it refunds the payment.

## Run

```
PRISM_AGENT_KEY=0x..   \    # server wallet that funds leases (needs USDG + gas)
PRISM_ESCROW=0x71Df..  \
X402_PAY_TO=0x..       \    # address that collects payment
X402_PRICE_MICROS=300000    # 0.30 USDG per job
node server.mjs
```

Install from the repo (not yet on npm): `cd prism-public/x402 && npm install`.

Other env: `X402_PORT` (8402), `X402_DURATION_SECONDS` (900), `X402_MIN_VRAM_MIB` (16000), `X402_PAYMENTS_FILE`, `PRISM_API_BASE`, `PRISM_RPC_URL`. The consumed-payments file makes replay protection survive a restart; a multi-instance deployment needs a shared store instead.
