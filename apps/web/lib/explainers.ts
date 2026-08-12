/// The explainer index, kept in one place so the listing page, the sitemap and
/// the cross-links cannot disagree about what exists.
export const explainers = [
  {
    slug: "trust-classes",
    title: "What a GPU supplier can actually promise",
    dek: "“Secure” means nothing until somebody says who can read what. Prism grades every offer, and the grade comes from evidence the network can check.",
    description:
      "Rented GPUs come with vague security claims. Trust classes state what each supplier protects, where the grade comes from, and what today's capacity actually gives you.",
  },
  {
    slug: "how-a-lease-settles",
    title: "What happens between renting a GPU and paying for it",
    dek: "A quote, an escrow, a readiness check, a per-second meter, and a receipt. Where the money sits at each step, and what happens when a step fails.",
    description:
      "How a GPU lease on Prism moves from quote to settlement: what the escrow holds, when billing starts, how the charge is split, and what happens when provisioning fails.",
  },
  {
    slug: "what-an-agent-needs",
    title: "What an AI agent needs to rent a GPU",
    dek: "An identity, a balance, and a workload. No browser, no signup form, no API key for anyone to rotate.",
    description:
      "What an autonomous agent needs to rent GPU compute on its own: a wallet as identity, a stablecoin balance, a digest-pinned image, and one of three ways in.",
  },
  {
    slug: "confidential-gpu-compute",
    title: "Why confidential GPU compute needs specific hardware",
    dek: "Encryption on the way in does nothing once the machine decrypts the data to compute on it. Hiding a workload from its host takes silicon, and most GPUs lack it.",
    description:
      "Keeping a workload private from the machine running it needs a trusted execution environment on the CPU and the GPU. Which hardware can do it, why zero-knowledge proofs do not solve it, and what that means today.",
  },
] as const;

export type Explainer = (typeof explainers)[number];

export function explainer(slug: string) {
  return explainers.find((entry) => entry.slug === slug);
}
