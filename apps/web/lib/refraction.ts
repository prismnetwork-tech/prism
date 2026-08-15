export const REFRACTION_PRIZE = "0xD19474BC75A65a2a8faa59f93CF0f014cBF8C771";
export const EXPLORER = "https://robinhoodchain.blockscout.com";

export type Stage = {
  index: number;
  title: string;
  prompt: string;
  hint: string;
  /// The page checks a normalised answer against this digest, so no stage
  /// answer sits in the bundle as plain text. Only the final combination,
  /// hashed again, is what the prize contract accepts.
  digest: string;
};

/// Normalising before hashing is what stops a right answer being rejected for
/// its spacing. Case, whitespace and punctuation carry no meaning here.
export function normalise(answer: string) {
  return answer.toLowerCase().replace(/[^a-z0-9]/g, "");
}

export async function digestOf(answer: string) {
  const bytes = new TextEncoder().encode(`prism.refraction.v1\0${normalise(answer)}`);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const STAGES: Stage[] = [
  {
    index: 1,
    title: "Read a receipt",
    prompt:
      "Every settled lease on Prism publishes a receipt. Find the one for transaction 0x06f378be25ee204c18ea9fa2bdf054f75a956f04b626f11d6050e8f92ab75c23. Which GPU served it?",
    hint: "The receipts page lists them. The answer is a model name.",
    digest: "f35e6d8f1711c24ff276aafdf28005f094b0049dd944a176e37653c6a82135c6",
  },
  {
    index: 2,
    title: "Open the settlement",
    prompt: "That same transaction settled in which block?",
    hint: "Any block explorer will tell you. A number.",
    digest: "5f82232fe2d4b818a5c0a117cf588467466f323f0a22493511da1fc235ef21e6",
  },
  {
    index: 3,
    title: "Ask the escrow",
    prompt:
      "A settled lease can be disputed for a while before it finalises. Ask the escrow contract how many seconds that window is.",
    hint: "DISPUTE_WINDOW on the lease escrow. Read it on the explorer. A number of seconds.",
    digest: "dc85aa1256cf0fca992cb3d8e8998ba7c1cf7d6f44f0200b03139c25475b1bc0",
  },
  {
    index: 4,
    title: "Rent a GPU",
    prompt:
      "The last one is work rather than a lookup. Find the smallest whole number that refracts to zero, seeded with 0x5052. A laptop takes minutes; a rented GPU takes seconds.",
    hint: "Run the searcher on a Prism lease. It prints the number.",
    digest: "75509cedda4b2b1cb950b3fa7cd31cfd99059ec89ced29ea5a8bbc8d5682f549",
  },
];
