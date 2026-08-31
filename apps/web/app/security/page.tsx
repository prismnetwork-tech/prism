import type { Metadata } from "next";
import { InformationPage, InformationSection } from "@/components/information-page";

export const metadata: Metadata = {
  title: "Security",
  description: "Prism security controls and trust boundaries: what each workspace class protects, how renter data stays encrypted, and how to report a vulnerability.",
  alternates: { canonical: "/security" },
};

export default function SecurityPage() {
  return (
    <InformationPage
      eyebrow="Trust / Security"
      title="Security controls and service boundaries."
      description="Prism protects funding, lease state, access credentials, and settlement evidence. Infrastructure providers remain within the workload trust boundary."
    >
      <InformationSection index="01" title="Enforced controls">
        <ul>
          <li>Same-site, HTTP-only authenticated sessions and same-origin mutation checks.</li>
          <li>Wallet-control challenges with replay protection before account linkage.</li>
          <li>Bounded request bodies, rate limits, concurrency limits, and risk holds.</li>
          <li>GPU, provider-cost, and access-endpoint admission before billable time starts.</li>
          <li>Encrypted temporary access credentials with revocation at lease close.</li>
          <li>Idempotent lease and settlement processing with recovery after interruption.</li>
          <li>Maximum escrow, maximum duration, dispute window, and emergency pause enforced onchain.</li>
        </ul>
      </InformationSection>

      <InformationSection index="02" title="Trust boundaries">
        <p>
          Cloud workspaces run in fresh containers with temporary direct access. This limits
          accidental persistence between leases, but the infrastructure provider controls the physical
          host and may be able to observe workload data.
        </p>
        <p>
          Do not place private keys, production credentials, regulated data, proprietary model
          weights, or other confidential material in a rented workspace. A workspace has no durable
          storage and carries no service-level agreement.
        </p>
        <p>
          Confidential inference is the exception, and it is a different service. Those models run
          inside an Intel TDX enclave in front of a GPU that NVIDIA attests, the prompt is encrypted
          to a key the enclave&apos;s attestation quote commits to, and the quote is checked before the
          prompt is sent. That protection covers the inference endpoint. It does not extend to a
          rented workspace, where the infrastructure provider still controls the physical host.
        </p>
        <p>
          Clients pin the SSH host key of the machine they rent for the life of the lease. Where a
          node publishes its host key under its own device key, the session terminates on the key
          that machine named. Where capacity is brokered through a third-party cloud that generates
          the key and never publishes it, no honest pin exists: the lease is reported as unverified
          rather than presented as checked, and a client can refuse it.
        </p>
      </InformationSection>

      <InformationSection index="03" title="Contracts and governance">
        <p>
          Lease funding and settlement execute through deployed Robinhood Chain contracts, which are
          unaudited software. The contracts carrying live leases place every routine administrative
          change behind an enforced 48-hour timelock: changing the settlement signer, the attestor
          or the treasury is scheduled in public and cannot execute for two days. Only halting the
          market, freezing a bond under investigation, resuming service and resolving a disputed
          lease act without delay. Of those, only dispute resolution touches money, and it decides
          the split of a single contested lease within what that lease already escrowed.
          The earlier contracts, which were governed directly by a two-of-two Safe, are paused and
          hold no open leases.
        </p>
        <p>
          Contract addresses, roles, state transitions, settlement calculations, and operational
          parameters are published in the{" "}
          <a href="https://docs.prismnetwork.tech/#contracts">developer documentation</a>.
        </p>
      </InformationSection>

      <InformationSection index="04" title="Report a vulnerability">
        <p>
          Send security reports to{" "}
          <a href="mailto:security@prismnetwork.tech">security@prismnetwork.tech</a>.
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
