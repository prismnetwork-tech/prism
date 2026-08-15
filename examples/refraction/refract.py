"""Stage four of Refraction: find the beam that lands clean.

A search over 32-bit integers for one whose refraction lands exactly on zero.
Checking a single candidate is a handful of integer operations, so anyone can
verify a winner in a millisecond. Finding one takes billions of tries, and the
work is identical across every candidate, which is the shape a GPU is built for
and a laptop is not.

Deliberately not a hash: this is a small ARX permutation with no cryptographic
claim attached to it. Nothing here mines anything.
"""
import argparse
import sys
import time

MASK = 0xFFFFFFFF
ROUNDS = 24


def rotl(value, bits):
    return ((value << bits) | (value >> (32 - bits))) & MASK


def refract(seed, candidate):
    """The reference implementation. The page verifies with exactly this."""
    a = (seed ^ 0x9E3779B9) & MASK
    b = (candidate ^ 0x85EBCA6B) & MASK
    for _ in range(ROUNDS):
        a = (a + b) & MASK
        b = rotl(b, 13) ^ a
        a = rotl(a, 7) + (b & 0xFFFF) & MASK
    return a


def search_gpu(seed, start, batch, device):
    import torch

    a0 = (seed ^ 0x9E3779B9) & MASK
    offset = torch.arange(batch, dtype=torch.int64, device=device)
    found = None
    scanned = 0
    began = time.time()
    base = start
    while found is None:
        candidates = (base + offset) & MASK
        a = torch.full((batch,), a0, dtype=torch.int64, device=device)
        b = candidates ^ 0x85EBCA6B
        for _ in range(ROUNDS):
            a = (a + b) & MASK
            b = (((b << 13) | (b >> 19)) & MASK) ^ a
            a = ((((a << 7) | (a >> 25)) & MASK) + (b & 0xFFFF)) & MASK
        hit = (a == 0).nonzero()
        scanned += batch
        if hit.numel() > 0:
            found = int(candidates[hit[0, 0]].item())
            break
        base = (base + batch) & MASK
        if base < start and scanned > MASK:
            break
    rate = scanned / max(time.time() - began, 1e-9)
    return found, scanned, rate


def main():
    parser = argparse.ArgumentParser(description="Refraction stage four")
    parser.add_argument("--seed", type=lambda v: int(v, 0), required=True)
    parser.add_argument("--start", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--batch", type=lambda v: int(v, 0), default=1 << 22)
    arguments = parser.parse_args()

    try:
        import torch
    except ImportError:
        sys.exit("torch is not installed; this stage wants a GPU")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    if device == "cuda":
        print(f"gpu: {torch.cuda.get_device_name(0)}", flush=True)
    else:
        print("no CUDA device; this will take a while on a CPU", flush=True)

    found, scanned, rate = search_gpu(arguments.seed, arguments.start, arguments.batch, device)
    print(f"scanned {scanned:,} candidates at {rate/1e6:,.1f}M/s", flush=True)
    if found is None:
        sys.exit("no candidate in this range")
    assert refract(arguments.seed, found) == 0, "reference check failed"
    print(f"REFRACTION_ANSWER={found}", flush=True)


if __name__ == "__main__":
    main()
