# PyTorch Lightning on Prism

Lease a GPU on Prism with a wallet signature, then run a real
[PyTorch Lightning](https://github.com/Lightning-AI/pytorch-lightning) `Trainer`
job on it over SSH — an autonomous agent training on rented, metered compute.

`train.py` is ordinary Lightning (a tiny autoencoder on synthetic data);
`lease-and-train.mjs` leases the GPU, ships the script to the box, installs
Lightning, runs it, prints the output, and releases the lease.

## Run it

```sh
npm install
PRISM_AGENT_KEY=0x<agent wallet private key> \
PRISM_ESCROW=0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD \
PRISM_IMAGE=<repo@sha256:...> \
node lease-and-train.mjs
```

`PRISM_IMAGE` must be a **digest-pinned CUDA + PyTorch image** — Prism rejects
plain tags. Resolve a digest for the tag you want, for example:

```sh
docker buildx imagetools inspect pytorch/pytorch:2.4.0-cuda12.1-cudnn9-runtime
```

`torch` comes from that image; the script installs `lightning` at runtime.

**Prerequisites:** Node 20+, `ssh`/`ssh-keygen` on `PATH`, and an agent wallet
funded with USDG and native Robinhood-Chain gas (see the
[SDK funding notes](../../sdk/README.md)). The packages are not yet on npm, so
this installs the SDK from the repository via a `file:` dependency.

## Before you point it at real funds

Prism is pre-production and unaudited; mainnet escrow is paused pending a funded
canary and physical-hardware validation. Run against a development deployment,
and do not lease with a wallet or workload you cannot afford to lose. A
permissionless supplier is not a trusted computing environment.

---

PyTorch Lightning is Apache-2.0 software by Lightning AI. This example uses it to
run a workload on Prism and is not affiliated with or endorsed by Lightning AI.
