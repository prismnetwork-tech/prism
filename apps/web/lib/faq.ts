/// The questions people actually ask before renting, answered once so the page
/// and the structured data cannot drift apart. Every figure here is stated
/// somewhere else on the site or enforced in a contract; nothing is rounded up
/// for the sake of a better answer.
export const faq = [
  {
    question: "What payment methods do you accept?",
    answer:
      "Stablecoins. We do not take cards or bank transfer. A lease is funded in USDG on Robinhood Chain, and one-off jobs over x402 accept USDC on Base or USDG on Robinhood Chain. You also need a small amount of native ETH on Robinhood Chain for gas, which is separate from the compute cost.",
  },
  {
    question: "Do I need the PRISM token to use the network?",
    answer:
      "No. Compute is priced and settled in stablecoins, and you can rent a GPU without ever holding the token.",
  },
  {
    question: "What does GPU compute cost?",
    answer:
      "L40S capacity is 0.7992 USDG per hour, displayed as $0.80, metered per second. Billing starts only after GPU, pricing and access-readiness checks pass. A lease can run for at most six funded hours and escrow is capped at 50 USDG, with unused escrow returned when settlement finalizes.",
  },
  {
    question: "Which GPUs can I rent?",
    answer:
      "Currently NVIDIA L40S, RTX 6000 Ada, RTX 5880 Ada, RTX A6000 and A40, depending on what is online. Offers reflect real-time capacity, and a quote states the exact GPU before you fund anything.",
  },
  {
    question: "Can the operator of the machine see my data?",
    answer:
      "On the capacity available today, yes. Every offer carries a trust class, and all current capacity is open class, which means the company hosting the machine can read what runs on it. Anything that must stay private belongs in your vault instead, where it is encrypted under a key derived on your own machine.",
  },
  {
    question: "What is a trust class?",
    answer:
      "A statement of what a supplier protects, running open, isolated, attested and confidential from weakest to strongest. The network works the class out from evidence it can check, and a request can require a minimum.",
  },
  {
    question: "How does the vault keep data private?",
    answer:
      "Items are sealed on your machine with a key derived from a wallet signature that is never transmitted, so Prism stores ciphertext and holds no means of reading it. Each item names the weakest class of workspace it may be released into, and a release into anything below that floor is refused.",
  },
  {
    question: "Do I need an account to rent a GPU?",
    answer:
      "A wallet is the identity. Agents authenticate by signing a challenge and never touch a browser, using the SDK, the MCP server, or pay-per-job over x402. There is a console for people who prefer one.",
  },
  {
    question: "What happens if a workspace never becomes ready?",
    answer:
      "You are not charged for capacity you never received. Billing begins only after readiness checks pass, and a lease that fails to provision inside the ten-minute window can be expired by anyone, which refunds the renter and frees the machine.",
  },
  {
    question: "How do I supply GPUs and what do I earn?",
    answer:
      "Providers receive 90% of the confirmed charge on a finalized lease, with 10% going to Prism as the service fee. Capacity has to be bonded and device-signed before it can be matched, and the provider program for operator-owned infrastructure is in technical onboarding.",
  },
  {
    question: "Is Prism audited?",
    answer:
      "No. The contracts are deployed and non-upgradeable but have not received an independent audit, and the network is unaudited pre-production infrastructure. Per-lease escrow is capped at 50 USDG, which bounds what any single lease can cost you.",
  },
] as const;
