import type { Metadata } from "next";
import { InformationPage, InformationSection } from "@/components/information-page";

export const metadata: Metadata = {
  title: "About",
  description: "Why Prism Network is building accountable, metered GPU infrastructure.",
  alternates: { canonical: "/about" },
};

export default function AboutPage() {
  return (
    <InformationPage
      eyebrow="Company / About"
      title="Compute should account for itself."
      description="Prism is building a GPU marketplace where access, usage, payment, and refunds share one verifiable lifecycle."
    >
      <InformationSection index="01" title="What we are building">
        <p>
          Prism connects renters to GPU capacity, admits a workspace only after infrastructure
          checks pass, meters usable runtime by the second, and settles the result through USDG
          escrow on Robinhood Chain.
        </p>
        <p>
          The current launch product is an L40S cloud beta. Independently operated hardware is a
          separate supplier track and remains release-gated until its stronger isolation and
          network path is production-ready.
        </p>
      </InformationSection>

      <InformationSection index="02" title="Operating principles">
        <h3>Meter after readiness</h3>
        <p>Billing begins only after GPU, cost, and access-endpoint admission checks pass.</p>
        <h3>Settle exact usage</h3>
        <p>Maximum cost is escrowed up front. Confirmed runtime is charged and unused escrow is returned.</p>
        <h3>Expose proof, not workloads</h3>
        <p>Public receipts prove settlement state without publishing wallet identity, terminal contents, notebooks, or files.</p>
        <h3>State the trust boundary</h3>
        <p>The beta uses fresh container workspaces, not confidential computing. The upstream host remains inside the trust boundary.</p>
      </InformationSection>

      <InformationSection index="03" title="Built in public">
        <p>
          The protocol, control plane, workers, contracts, deployment configuration, and web
          application are developed in the open. Architecture and operational contracts are
          documented alongside the source so claims can be checked against implementation.
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
