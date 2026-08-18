# One command on a GPU

    POST https://api.prismnetwork.tech/x402/run
    Content-Type: application/json

    {"command": "nvidia-smi"}

Runs a single shell command on a rented GPU and returns its output. Use this
when the user wants the machine rather than a model: checking what hardware is
available, running a short CUDA job, or executing a script they have already
staged.

Read the 402 for the exact request schema. It is published in the challenge
itself under `extensions.bazaar`, which is authoritative and versioned with the
endpoint, unlike this file.

## Charged only if it works

The command's exit code decides whether the payment is taken. A command that
exits non-zero costs nothing, so a typo or a missing binary is not billable.
This is the difference from `/inference/v1/inference`, where the charge follows
a served response rather than an exit code.

That also means the caller should not treat a `200` as proof the command did
what they wanted, only that it exited zero. Read the output.

## What the machine is

A GPU leased from the network for the duration of the call, not a persistent
box. Nothing survives between calls: no files, no processes, no state. A command
that expects something from a previous call will not find it.

If the user needs state across commands, they want a lease rather than this
endpoint, and that is a different flow.

## Payment

Identical to inference. Two rails, `exact` scheme, EIP-3009, no gas needed by
the caller. See [paying.md](paying.md).
