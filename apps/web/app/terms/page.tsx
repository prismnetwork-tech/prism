import type { Metadata } from "next";
import { LegalPage, LegalSection } from "@/components/legal-page";

export const metadata: Metadata = {
  title: "Terms of service",
  description: "Terms governing access to the Prism Network website, console, marketplace, and contracts.",
  alternates: { canonical: "/terms" },
};

export default function TermsPage() {
  return (
    <LegalPage
      title="Terms of service"
      description="Terms governing access to the Prism website, console, compute marketplace, and associated smart contracts."
      effective="July 20, 2026"
    >
      <LegalSection index="01" title="Acceptance and eligibility">
        <p>
          By accessing or using Prism, you agree to these terms and the Privacy Policy. You must
          have legal capacity to enter this agreement and must not use Prism where doing so is
          prohibited by applicable law, sanctions, export controls, or an agreement binding you.
          If you use Prism for an organization, you represent that you are authorized to bind it.
        </p>
      </LegalSection>

      <LegalSection index="02" title="The service">
        <p>
          Prism is an unaudited marketplace for metered GPU compute. It matches renter
          requests with independent or third-party capacity, coordinates temporary access, and
          uses USDG escrow on Robinhood Chain for funding and settlement. Features, limits,
          pricing, providers, supported chains, and availability may change or be suspended.
        </p>
        <p>
          Prism does not provide confidential computing, guaranteed workload correctness,
          durable storage, a service-level agreement, investment services, custody, or control
          of your wallet. Blockchain transactions are initiated and approved by you.
        </p>
      </LegalSection>

      <LegalSection index="03" title="Accounts and wallets">
        <ul>
          <li>Keep authentication methods, passkeys, wallets, and recovery channels secure.</li>
          <li>Provide accurate information and maintain control of linked wallets.</li>
          <li>Review chain, contract, amount, and calldata before approving a transaction.</li>
          <li>Notify Prism promptly if you suspect account or wallet compromise.</li>
          <li>Do not share sessions, bypass restrictions, or impersonate another person.</li>
        </ul>
        <p>
          You are responsible for wallet transactions and network fees you authorize. Prism
          cannot recover wallet keys, reverse final blockchain transactions, or guarantee
          recovery of assets sent to an incorrect address or contract.
        </p>
      </LegalSection>

      <LegalSection index="04" title="Workloads and acceptable use">
        <p>You must not use Prism to:</p>
        <ul>
          <li>Break the law, violate sanctions, or infringe intellectual-property or privacy rights.</li>
          <li>Deploy malware, phishing, credential theft, denial-of-service, botnet, or unauthorized mining workloads.</li>
          <li>Probe, exploit, disrupt, or bypass Prism, providers, other renters, rate limits, or security controls.</li>
          <li>Access data or systems without authorization, or process unlawful or harmful content.</li>
          <li>Place secrets, regulated data, or confidential material into a workspace.</li>
          <li>Misrepresent usage, manipulate metering, replay identities, or interfere with settlement evidence.</li>
          <li>Resell access without written authorization or use capacity for sanctioned end users or destinations.</li>
        </ul>
        <p>
          Prism may reject images, stop provisioning, revoke access, preserve evidence, suspend
          accounts, pause new leases, or cooperate with providers and authorities when reasonably
          necessary to enforce these terms or protect users and infrastructure.
        </p>
      </LegalSection>

      <LegalSection index="05" title="Provider and workload risk">
        <p>
          GPU operators and cloud providers are independent parties within the execution trust
          boundary. They may control the host, observe workload data, experience outages, or
          terminate capacity. Container and sandbox isolation reduce some risks but do not make
          the host trusted or confidential.
        </p>
        <p>
          You are responsible for selecting a suitable image, maintaining backups, validating
          outputs, securing SSH keys, complying with software and dataset licenses, and ensuring
          that your workload is safe and lawful. Workspace storage is ephemeral and may be
          destroyed without recovery when a lease closes.
        </p>
      </LegalSection>

      <LegalSection index="06" title="Pricing, escrow, and settlement">
        <p>
          A quote states the rate per second, funded duration, and maximum USDG escrow. Quotes
          expire and do not reserve capacity. A lease begins only after the required approval,
          escrow transaction, chain finality, quote verification, provisioning, and workspace
          readiness.
        </p>
        <ul>
          <li>Billing starts only after the service confirms GPU and access readiness.</li>
          <li>Usage is capped by funded duration and contract limits.</li>
          <li>Finalized charges allocate 90% to the provider and a 10% platform fee.</li>
          <li>Unused escrow is refunded when settlement is finalized.</li>
          <li>A 24-hour dispute window applies before ordinary settlement finalization.</li>
          <li>Network gas, wallet, or third-party fees may be separate and non-refundable.</li>
        </ul>
      </LegalSection>

      <LegalSection index="07" title="Failures, refunds, and disputes">
        <p>
          Prism attempts to refund escrow when provisioning fails before billable access or when
          the contract&apos;s refund conditions apply. Provider loss, chain congestion, RPC
          failure, contract defects, wallet errors, or third-party insolvency may delay or prevent
          an expected outcome. Do not submit duplicate funding transactions while confirmation is
          pending.
        </p>
        <p>
          Settlement disputes may be reviewed through the protocol dispute process.
          Preserve transaction hashes, request IDs, timestamps, and relevant non-secret evidence.
          Governance decisions remain constrained by the deployed contracts and available
          evidence.
        </p>
      </LegalSection>

      <LegalSection index="08" title="Intellectual property">
        <p>
          You retain rights in workloads and materials you submit and grant Prism and its
          providers the limited rights necessary to transmit, execute, secure, and support them.
          You represent that you have the rights required for your images, software, models,
          datasets, and outputs. Prism names, marks, interface design, and non-open-source service
          materials may not be used to imply endorsement.
        </p>
        <p>
          Repository source is licensed under the license files accompanying that source. Open
          source licenses govern the code they cover and are not replaced by these service terms.
        </p>
      </LegalSection>

      <LegalSection index="09" title="Availability and changes">
        <p>
          Prism may impose capacity, duration, escrow, geographic, wallet, risk, or concurrency
          limits; modify or discontinue features; rotate providers; deploy security fixes; or
          pause the service. Availability is not guaranteed. Planned governance changes may
          be timelocked, while emergency pause and security containment may be immediate.
        </p>
      </LegalSection>

      <LegalSection index="10" title="Disclaimers">
        <p>
          To the maximum extent permitted by law, Prism is provided &quot;as is&quot; and &quot;as
          available.&quot; Prism disclaims implied warranties of merchantability, fitness for a
          particular purpose, non-infringement, accuracy, uninterrupted availability, security,
          workload correctness, and provider reliability. Nothing in these terms excludes a
          warranty that cannot legally be excluded.
        </p>
      </LegalSection>

      <LegalSection index="11" title="Limitation of liability">
        <p>
          To the maximum extent permitted by law, Prism and its contributors, maintainers, and
          service providers will not be liable for indirect, incidental, special, consequential,
          exemplary, or punitive damages; loss of profits, data, credentials, models, goodwill,
          or opportunity; provider conduct; or blockchain and wallet failures. Any aggregate
          liability relating to a claim is limited to the platform fees you paid for the affected
          lease, except where applicable law prohibits that limitation.
        </p>
      </LegalSection>

      <LegalSection index="12" title="Termination and general terms">
        <p>
          You may stop using Prism at any time. Prism may suspend or terminate access for breach,
          security risk, abuse, legal requirements, provider constraints, or discontinuation.
          Provisions that by nature should survive—including payment, intellectual property,
          disclaimers, liability limits, and dispute records—continue after termination.
        </p>
        <p>
          These terms and referenced policies form the agreement for the service unless a
          separate written agreement applies. Mandatory local consumer rights remain unaffected.
          If a provision is unenforceable, the remainder continues. Failure to enforce a provision
          is not a waiver. Material updates will be identified by a revised effective date.
          Questions may be sent to{" "}
          <a href="mailto:security@prismnetwork.tech">security@prismnetwork.tech</a>.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
