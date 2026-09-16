import type { Metadata } from "next";
import { InformationPage, InformationSection } from "@/components/information-page";

export const metadata: Metadata = {
  title: "About",
  description: "How Prism runs metered GPU infrastructure for agents: readiness-based billing, usage-based settlement, renter-held encryption, and a stated security scope.",
  alternates: { canonical: "/about" },
};

export default function AboutPage() {
  return (
    <InformationPage
      eyebrow="Company / About"
      title="Metered GPU infrastructure, built for agents."
      description="Prism provides on-demand GPU capacity an agent rents with its wallet, billed per second against an upfront escrow limit."
    >
      <InformationSection index="01" title="Platform">
        <p>
          Prism connects customers to GPU capacity, begins billing after workspace-readiness
          checks pass, measures runtime by the second, and settles usage through USDG escrow on
          Robinhood Chain.
        </p>
        <p>
          Access is built for autonomous agents as well as people. An agent authenticates with
          its wallet, leases a GPU, and pays in USDG without a console or an API key, through an
          open SDK, an MCP server, and pay-per-job settlement over x402.
        </p>
        <p>
          The current service provides live NVIDIA capacity across several card classes, sourced
          from vetted providers. Operator-owned hardware is not part of the service today, so every
          machine a customer rents is brokered, and the trust class on each offer says so.
        </p>
      </InformationSection>

      <InformationSection index="02" title="Operating principles">
        <h3>Readiness-based billing</h3>
        <p>Billing begins only after GPU, pricing, and access-readiness checks pass.</p>
        <h3>Usage-based settlement</h3>
        <p>Maximum cost is escrowed up front. Confirmed runtime is charged and unused escrow is returned.</p>
        <h3>Privacy-preserving records</h3>
        <p>Public receipts prove settlement state without publishing wallet identity, terminal contents, notebooks, or files.</p>
        <h3>Renter-held encryption</h3>
        <p>Vault items are sealed under a key derived on the renter&apos;s machine and never sent. Prism stores ciphertext and holds no means of reading it.</p>
        <h3>Defined security scope</h3>
        <p>Workspaces are fresh containers, not confidential computing, so the infrastructure provider remains inside their trust boundary. Each vault item names the weakest workspace class it may be released into, and the default is above what the network can currently serve.</p>
      </InformationSection>

      <InformationSection index="03" title="What PRISM does on the network">
        <p>
          PRISM is the network&apos;s access token, not its currency. Compute is quoted and paid
          in USDG or USDC, so a renter never has to hold PRISM to buy a GPU. What PRISM buys is a
          cheaper rate on part of the fleet.
        </p>
        <h3>Staking unlocks discounted capacity</h3>
        <p>
          Operators can reserve a machine for stakers. Those offers are marked{" "}
          <code>staker_only</code> and priced below open capacity: today they run at 177 base
          units per second against 222 elsewhere, about 20 percent lower, and a wallet that has
          not staked is refused rather than charged the higher rate. Stake matures before it
          counts and unwinds through a cooldown, both enforced by the contract.
        </p>
        <h3>Where to check it</h3>
        <p>
          The token is{" "}
          <a href="https://robinhoodchain.blockscout.com/token/0x0A1e0Cc751f77C2C93760FC957CC8E4E779b2bC8">
            0x0A1e0Cc7
          </a>{" "}
          and the staking contract is{" "}
          <a href="https://robinhoodchain.blockscout.com/address/0x7c4060e0b1f6954a90ea92Ee81C14b3b70D1be7c">
            0x7c4060e0
          </a>
          , both on Robinhood Chain. The staking contract is source-verified and has no owner, no
          pause and no upgrade path, so the terms it was deployed with are the terms it keeps.
          Live capacity and which offers are staker-only are published on the{" "}
          <a href="https://api.prismnetwork.tech/v1/offers">offers endpoint</a>.
        </p>
      </InformationSection>

      <InformationSection index="04" title="Open-source infrastructure">
        <p>
          Prism&apos;s protocol, smart contracts, service architecture, and application code are
          developed in the open. Architecture and operational contracts are
          documented alongside the source for independent technical review.
        </p>
        <p>
          Read the <a href="https://docs.prismnetwork.tech">developer documentation</a> for the
          architecture, the operational contracts and the API reference.
        </p>
      </InformationSection>
    </InformationPage>
  );
}
