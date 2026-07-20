import type { Metadata } from "next";
import { InformationPage, InformationSection } from "@/components/information-page";

export const metadata: Metadata = {
  title: "Security",
  description: "Prism Network security controls, trust boundaries, and vulnerability reporting.",
  alternates: { canonical: "/security" },
};

export default function SecurityPage() {
  return (
    <InformationPage
      eyebrow="Trust / Security"
      title="Know exactly what the beta protects."
      description="Prism secures funding, lifecycle state, access credentials, and settlement evidence. It does not claim the upstream GPU host is confidential."
    >
      <InformationSection index="01" title="Enforced controls">
        <ul>
          <li>Same-site, HTTP-only authenticated sessions and same-origin mutation checks.</li>
          <li>Wallet-control challenges with replay protection before account linkage.</li>
          <li>Bounded request bodies, rate limits, concurrency limits, and risk holds.</li>
          <li>GPU, provider-cost, and access-endpoint admission before billable time starts.</li>
          <li>Encrypted temporary access credentials with revocation at lease close.</li>
          <li>Durable lifecycle and settlement jobs designed for safe retry after failure.</li>
          <li>Maximum escrow, maximum duration, dispute window, and emergency pause enforced onchain.</li>
        </ul>
      </InformationSection>

      <InformationSection index="02" title="Trust boundaries">
        <p>
          Cloud workspaces run in fresh containers with temporary direct access. This limits
          accidental persistence between leases, but the upstream provider controls the physical
          host and may be able to observe workload data.
        </p>
        <p>
          Do not place private keys, production credentials, regulated data, proprietary model
          weights, or other confidential material in a beta workspace. Prism does not currently
          provide a hardware-backed trusted execution environment, confidential GPU memory,
          durable storage, or a service-level agreement.
        </p>
      </InformationSection>

      <InformationSection index="03" title="Contracts and governance">
        <p>
          Lease funding and settlement execute through deployed Robinhood Chain contracts.
          Configuration changes pass through a 48-hour timelock, while the governance Safe holds
          emergency and dispute authority. The initial contracts are unaudited beta software.
        </p>
        <p>
          Contract addresses, roles, state transitions, settlement calculations, and operational
          release gates are published in the{" "}
          <a href="https://docs.prismnetwork.tech/#contracts">developer documentation</a>.
        </p>
      </InformationSection>

      <InformationSection index="04" title="Report a vulnerability">
        <p>
          Send security reports to{" "}
          <a href="mailto:security@prismnetwork.tech">security@prismnetwork.tech</a> or use{" "}
          <a
            href="https://github.com/prismnetwork-tech/prism/security/advisories/new"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub private vulnerability reporting
          </a>.
        </p>
        <p>
          Include the affected component, impact, reproduction steps, and a safe proof of concept.
          Do not test against mainnet user funds, disrupt public capacity, access other users&apos;
          data, or publish an unresolved vulnerability.
        </p>
      </InformationSection>
    </InformationPage>
  );
}
