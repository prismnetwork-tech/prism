import type { Metadata } from "next";
import Link from "next/link";
import { InformationPage, InformationSection } from "@/components/information-page";

export const metadata: Metadata = {
  title: "Roadmap",
  description:
    "What Prism Network runs today and where the work is headed. Direction is stated here; the onchain receipts mark what has shipped.",
  alternates: { canonical: "/roadmap" },
};

export default function RoadmapPage() {
  return (
    <InformationPage
      eyebrow="Product / Roadmap"
      title="What is live, and what comes next."
      description="Prism is metered GPU compute that an autonomous agent rents with a wallet and settles onchain. This page tracks what the network does today and where the work is headed. We state direction here and let the onchain receipts mark what has shipped."
    >
      <InformationSection index="01" title="Available now">
        <p>
          These capabilities run on Robinhood Chain today. Because every lease and settlement is
          recorded onchain, the record of what works is public rather than asserted.
        </p>
        <h3>Wallet-native access</h3>
        <p>
          An agent proves control of a wallet with a signed challenge and replay protection. No
          account, password, or human console stands between it and a machine.
        </p>
        <h3>Python and TypeScript SDKs</h3>
        <p>
          Price capacity, fund a lease, provision a machine, and open a session in a few lines.
          Published on PyPI and npm.
        </p>
        <h3>Model Context Protocol server</h3>
        <p>
          Any MCP client, Claude included, can list capacity, rent a GPU, and run a command through
          Prism. Listed in the official MCP registry.
        </p>
        <h3>Onchain lease escrow and settlement</h3>
        <p>
          Funding, metered billing, and refunds execute through deployed contracts, bounded by a
          maximum deposit, a maximum duration, and a dispute window.
        </p>
        <h3>Verifiable receipts</h3>
        <p>
          Every finalized lease publishes a settlement receipt that anyone can confirm on a block
          explorer.
        </p>
        <h3>Concurrent multi-class GPU capacity</h3>
        <p>
          Supply sourced from vetted providers across several NVIDIA classes, including L40S, RTX
          A6000, RTX 6000 Ada and RTX 5880 Ada, and matched to a lease on demand. The network serves
          nine leases at once rather than one at a time.
        </p>
        <h3>A stated trust class per offer</h3>
        <p>
          Every offer, quote, lease, and receipt carries what the supplier protects, derived by the
          network from evidence it can check rather than asserted by the host. An agent can require
          a minimum class instead of reading a disclaimer. All capacity live today is the weakest
          one, and the <Link href="/security">security page</Link> states what that does and does
          not cover.
        </p>
      </InformationSection>

      <InformationSection index="02" title="In progress">
        <p>
          Work underway to widen where Prism reaches and to make provisioning dependable under real
          demand.
        </p>
        <h3>Coinbase AgentKit provider</h3>
        <p>
          The Prism action provider is published and installable today, so an agent built on
          AgentKit, LangGraph, or the Vercel AI SDK can rent a GPU with no custom integration.
          Inclusion in AgentKit itself is in review upstream.
        </p>
        <h3>Dependable on-demand provisioning</h3>
        <p>
          Matching a lease to live capacity across a volatile spot market, so a request placed at any
          moment resolves to a running machine. A funded lease now reaches a shell in about ninety
          seconds. The remaining work is holding that under load and when a provider hands back a
          host that will not boot.
        </p>
        <h3>Independent node operators</h3>
        <p>
          The relay a self-hosted machine reaches renters through now runs, so an operator&apos;s own
          GPU can be leased rather than only registered. What remains is the hardware validation that
          lets such a node advertise a stronger trust class than brokered capacity.
        </p>
      </InformationSection>

      <InformationSection index="03" title="Planned">
        <p>
          Directional commitments that widen what the network can be trusted to run. Each ships only
          when it meets the same onchain, verifiable standard as the rest of Prism.
        </p>
        <h3>Attested and confidential capacity</h3>
        <p>
          The two classes above what the network can verify today: a launch measurement checked
          against vendor roots, then hardware-backed trusted execution with encrypted GPU memory, so
          a workload and its data stay private from the infrastructure provider. Both need hardware
          the network does not have yet, not a software change.
        </p>
        <h3>Durable workspaces</h3>
        <p>Persistent state and storage that survive across leases, beyond today&apos;s ephemeral containers.</p>
        <h3>Service-level commitments</h3>
        <p>Availability and performance guarantees suitable for production workloads.</p>
        <h3>Wider settlement and framework reach</h3>
        <p>
          More agent frameworks and payment rails, so capacity is reachable from wherever an agent
          already runs.
        </p>
      </InformationSection>

      <InformationSection index="04" title="How we prioritize">
        <h3>Verifiable over asserted</h3>
        <p>
          Settlement is recorded onchain, so a claim about what the network did is checkable rather
          than taken on faith.
        </p>
        <h3>Agent-native by default</h3>
        <p>A wallet in, a machine out. Nothing on the critical path requires a dashboard, a card, or a person.</p>
        <h3>Honest boundaries</h3>
        <p>
          The <Link href="/security">security page</Link> states plainly what the network does not
          yet protect. This roadmap holds to the same standard.
        </p>
        <p>
          Track what has shipped in the live <Link href="/proof">receipts</Link>, in the{" "}
          <a href="https://docs.prismnetwork.tech" target="_blank" rel="noopener noreferrer">
            documentation
          </a>
          , and in the{" "}
          <a
            href="https://github.com/winter0x/prism"
            target="_blank"
            rel="noopener noreferrer"
          >
            source
          </a>
          .
        </p>
      </InformationSection>
    </InformationPage>
  );
}
