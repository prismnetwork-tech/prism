# An image on a rented GPU

Lease a GPU on Prism with a wallet signature, generate an image on it, and bring
the PNG home before the machine is destroyed. No account, no cloud console, no
card: a wallet in, a picture out.

`render.py` is ordinary [diffusers](https://github.com/huggingface/diffusers)
running SD-Turbo. `lease-and-render.mjs` leases the GPU, ships the script over
SSH, installs diffusers on top of the image's PyTorch, renders, and writes
`rendered.png` next to itself.

The image comes back in the command output rather than over a second channel,
because the machine it was made on is about to stop existing.

## Run it

```sh
npm install
PRISM_AGENT_KEY=0x<agent wallet private key> \
PRISM_ESCROW=0x62C042265991bEa17B07229322A01850974626dA \
PRISM_IMAGE=<repo@sha256:...> \
node lease-and-render.mjs "a glass prism splitting light"
```

`PRISM_IMAGE` must be a **digest-pinned CUDA + PyTorch image**; Prism rejects
plain tags. Resolve a digest for the tag you want:

```sh
docker buildx imagetools inspect pytorch/pytorch:2.4.0-cuda12.1-cudnn9-runtime
```

The wallet needs USDG and native Robinhood-Chain gas. A twenty-minute lease at
the current rate is about 0.27 USDG.

Set `PRISM_MODEL` to render with something other than `stabilityai/sd-turbo`.
Anything larger will spend more of the lease pulling weights, so give it a
longer window.

## What it costs you in time

Most of the wall clock is provisioning and the model download, not the render.
SD-Turbo is distilled to a single denoising step, so the picture itself takes
about a second on an L40S.

## Pre-production

Prism is unaudited and pre-production. All capacity live today is `open` class,
which means the host operator can read anything the workload touches: do not
send prompts, weights or datasets you would mind being read.
