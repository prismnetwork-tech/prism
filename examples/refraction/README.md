# Refraction, stage four

The first three stages are lookups. This one is work.

Find the smallest whole number that refracts to zero for seed `0x5052`.
Checking one candidate is a handful of integer operations; finding the right
one takes millions of tries. Every candidate is independent, which is the shape
a GPU is built for.

On a rented GPU it takes seconds. On a laptop, minutes.

## On a Prism lease

```sh
npm install @prismnetwork/agent-sdk viem
PRISM_AGENT_KEY=0x<your wallet key> node lease-and-refract.mjs
```

## Anywhere with CUDA

```sh
python refract.py --seed 0x5052
```

It prints `REFRACTION_ANSWER=<number>`. That number is the fourth answer.

The search is a small ARX permutation with no cryptographic claim attached to
it, chosen because it is cheap to verify and parallel to search. Nothing here
mines anything.
