# @prism-network/x402

Pay-per-job GPU compute on [Prism Network](https://prismnetwork.tech) over HTTP 402. An agent submits a command, pays USDG on Robinhood Chain, and gets the output — no lease management, no wallet-signature session.

## Flow

```
POST /run  { "command": "nvidia-smi" }
  -> 402 { accepts: [{ asset, payTo, maxAmountRequired, network }] }

# pay maxAmountRequired USDG to payTo on Robinhood Chain, then:

POST /run  { "command": "nvidia-smi" }   header X-PAYMENT: <txHash>
  -> 202 { job_id, poll: "/jobs/<id>" }

GET /jobs/<id>
  -> { status: "completed", exit_code, stdout, stderr }
```

The server verifies the on-chain USDG `Transfer` to `payTo` (amount ≥ price, not reused), then leases a GPU with its own wallet, runs the command, returns the output, and releases the lease.

## Run

```
PRISM_AGENT_KEY=0x..  \    # server wallet that funds leases
PRISM_ESCROW=0x71Df..  \
X402_PAY_TO=0x..  \        # address that collects payment
X402_PRICE_MICROS=300000 \ # 0.30 USDG per job
node server.mjs
```

Env: `X402_PORT` (8402), `PRISM_API_BASE`, `PRISM_RPC_URL`, `PRISM_DEFAULT_IMAGE`.
