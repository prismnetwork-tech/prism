import type { Metadata } from "next";
import Link from "next/link";
import { InformationPage, InformationSection } from "@/components/information-page";
import { explainer } from "@/lib/explainers";

const entry = explainer("how-a-lease-settles")!;

export const metadata: Metadata = {
  title: entry.title,
  description: entry.description,
  alternates: { canonical: "/learn/how-a-lease-settles" },
};

export default function LeaseSettlementPage() {
  return (
    <InformationPage eyebrow="Learn / Settlement" title={entry.title} description={entry.dek}>
      <InformationSection index="01" title="The problem with paying up front">
        <p>
          Renting compute usually means one of two bad deals. You prepay a provider and hope the
          machine works, or you hand over a card and find out what it cost at the end of the month.
        </p>
        <p>
          A lease here holds the maximum in escrow, charges only for runtime that actually
          happened, and returns the rest. Nobody has to be trusted to do the arithmetic honestly,
          because the contract does it.
        </p>
      </InformationSection>

      <InformationSection index="02" title="Quote">
        <p>
          You ask for a GPU by memory, image and duration, and get back a rate, a maximum cost and
          an expiry. A quote lasts five minutes and does not reserve the machine, so a quote you
          sit on can go stale while somebody else takes the capacity.
        </p>
      </InformationSection>

      <InformationSection index="03" title="Fund">
        <p>
          You approve the maximum in USDG and open the lease onchain. That maximum is the rate multiplied by the full
          duration, so it is a ceiling rather than an estimate. Per-lease escrow is capped at 50 USDG, which bounds what any single mistake can cost you.
        </p>
      </InformationSection>

      <InformationSection index="04" title="Provision and readiness">
        <p>
          The network assigns capacity and prepares the workspace. Billing has not started. Charges
          begin only once the GPU, the pricing and the access path all pass their checks, so you do
          not pay for a machine that never became usable.
        </p>
        <p>
          If it never becomes ready, the lease can be expired by anyone after ten minutes. That
          refunds you and frees the machine, and it does not depend on us noticing.
        </p>
      </InformationSection>

      <InformationSection index="05" title="Meter">
        <p>
          Usage accrues per second for as long as the workspace is live, to a ceiling of six funded
          hours. Current L40S capacity runs at 0.7992 USDG an hour, displayed as $0.80.
        </p>
      </InformationSection>

      <InformationSection index="06" title="Settle">
        <p>
          When the lease ends, confirmed runtime is charged and the unused escrow goes back to you.
          The charge splits 90% to the provider and 10% to Prism. Wallet and network gas fees are
          separate and small.
        </p>
      </InformationSection>

      <InformationSection index="07" title="Receipt">
        <p>
          Settlement writes a public record: the GPU, the runtime, and the USDG charged. It records
          the cost and never the contents, so spend reconciles cleanly while the workspace stays
          private. The <Link href="/proof">receipts feed</Link> carries every finalized lease.
        </p>
        <p>
          The contracts are deployed and non-upgradeable, and they have not had an independent
          audit. The 50 USDG per-lease cap exists partly for that reason.
        </p>
      </InformationSection>
    </InformationPage>
  );
}
