# Confidential inference demo

An agent buys one generation from a model running inside a Phala GPU TEE, then
checks the evidence itself before it trusts the answer. Everything on screen is
the agent's own work, with no human step in it.

The run has five parts: the confidential catalog with its prices, a paid call
whose prompt is encrypted to the enclave, the answer with what it cost and the
receipt it came with, the table of checks the agent ran, and the source commit
the serving workload was measured against.

Prism sells and relays the call, and ships the tooling that verifies it. The
model runs on Phala hardware.

## Run it

```sh
PRISM_AGENT_KEY=0x<agent wallet private key> \
PRISM_INFERENCE_URL=https://api.prismnetwork.tech/inference \
node agent-demo.mjs
```

Any funded wallet works. It needs USDG for the call and native Robinhood Chain
gas for the transfer. One run is about one and a half cents on the cheaper model
at the rates this endpoint ships, and the endpoint quotes the exact price for
the request before anything is paid. `PRISM_MAX_USDG` (default 0.05) refuses a
quote above the cap before any money moves, and the run stops early when the
wallet is short of either balance. The demo imports the SDK from the tree next
to it, so run `pnpm install` at the repo root once before the first run.

Both variables above are required and the script stops without them. The rest
are optional: `PRISM_MODEL` picks a model other than the first confidential one
the endpoint lists, `PRISM_DEMO_PACE` sets the pause between sections in
milliseconds (0 removes it), and `PRISM_ESCROW` overrides the lease escrow
address the SDK is constructed with.

`./demo-session.sh` is the wrapper used for recording. It checks the endpoint
and the wallet key before anything reaches the screen, then clears and runs the
demo at a pace a viewer can follow.

## What the checks establish

- The workload runs on Intel TDX hardware. Its quote chains to Intel's root and
  its TCB level is current.
- The workload's published keyset is bound into that quote, so the receipt
  signing key and the encryption key belong to the measured workload.
- The launch configuration replays to the measurement inside the quote, and it
  names the launcher image and the repository the SDK pins. The demo prints the
  measured source at the end.
- The receipt is signed by a key from the keyset and carries a hash of the exact
  response bytes the agent received.
- NVIDIA attests the GPU: measurements match, secure boot on, debug disabled.

One property sits outside the table: that the prompt was sealed to a key from
the attested keyset. The SDK settles it before it encrypts, by verifying the
quote and the workload the measured compose names and refusing to send anything
when either fails. It holds by construction, so no row re-establishes it after
the fact.

On encrypted calls the request-hash check reproduces the plaintext the workload
hashed and compares it to the receipt. Bytes the agent cannot reproduce leave
that check unestablished, and the run reports `incomplete`. A reproduction that
disagrees is a failure. The response hash binds the answer either way.

## What it leaves open

Two checks report `skip` here, and the table says so on screen. Both are
documented gaps in the protocol rather than evidence that went missing, so a run
carrying only these two still reports `verified`. Any other skip reports
`incomplete`, and the demo names which one had nothing to run against.

Key custody has no evidence in the protocol today. A verifier can see which keys
a measured workload published, and it cannot see where the private halves are
held. The TLS key pin is the second. The verifier needs a socket to read the
server certificate from and `fetch` gives it none, so the check reports `skip`.
Even where it passes, it shows you reached the terminator the keyset names and
says nothing about whether TLS ends inside the TEE.

End-to-end encryption is what closes both gaps in practice. The prompt is
encrypted to a key the attested workload published, so everything between the
agent and the enclave, Prism's relay included, handles ciphertext. Model ids on
this endpoint are not pinned to a digest upstream, so the measured evidence
covers the serving stack rather than the weights behind the id.

The workload pin the SDK ships is a snapshot of a known-good deployment: it
names the launcher image and the repository the measured compose has to agree
with, and it needs updating when Phala publishes a new launcher. It establishes
which code the enclave was launched from. It does not establish that the code
was built reproducibly from that repository.

Prism is pre-production and unaudited. Run this with a wallet you can afford to
lose.
