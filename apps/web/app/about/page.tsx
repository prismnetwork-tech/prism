import type { Metadata } from "next";
import { InformationPage, InformationSection } from "@/components/information-page";

export const metadata: Metadata = {
  title: "About",
  description: "Prism Network provides metered GPU infrastructure with verifiable onchain settlement.",
  alternates: { canonical: "/about" },
};

export default function AboutPage() {
  return (
    <InformationPage
      eyebrow="Company / About"
      title="Metered GPU infrastructure with verifiable settlement."
      description="Prism provides on-demand GPU capacity with per-second billing, upfront escrow limits, and public settlement records."
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
          The current service provides managed NVIDIA L40S capacity in private beta. A provider
          program for operator-owned infrastructure is in technical onboarding and is not yet
          available for production leases.
        </p>
      </InformationSection>

      <InformationSection index="02" title="Operating principles">
        <h3>Readiness-based billing</h3>
        <p>Billing begins only after GPU, pricing, and access-readiness checks pass.</p>
        <h3>Usage-based settlement</h3>
        <p>Maximum cost is escrowed up front. Confirmed runtime is charged and unused escrow is returned.</p>
        <h3>Privacy-preserving records</h3>
        <p>Public receipts prove settlement state without publishing wallet identity, terminal contents, notebooks, or files.</p>
        <h3>Defined security scope</h3>
        <p>The beta uses fresh container workspaces, not confidential computing. The infrastructure provider remains inside the trust boundary.</p>
      </InformationSection>

      <InformationSection index="03" title="Open-source infrastructure">
        <p>
          Prism&apos;s protocol, smart contracts, service architecture, and application code are
          developed in the open. Architecture and operational contracts are
          documented alongside the source for independent technical review.
        </p>
        <p>
          Review the{" "}
          <a href="https://github.com/prismnetwork-tech/prism" target="_blank" rel="noopener noreferrer">
            Prism source repository
          </a>{" "}
          or read the <a href="https://docs.prismnetwork.tech">developer documentation</a>.
        </p>
      </InformationSection>
    </InformationPage>
  );
}
