import type { Metadata } from "next";
import { InformationPage, InformationSection } from "@/components/information-page";
import { PriceIndex } from "@/components/price-index";

export const metadata: Metadata = {
  title: "Pricing",
  description: "What GPU capacity costs on Prism, including a live index of what compute was sourced at and what leases actually settled for onchain.",
  alternates: { canonical: "/pricing" },
};

export default function PricingPage() {
  return (
    <InformationPage
      eyebrow="Product / Pricing"
      title="GPU compute at $0.80 per hour, and what it cost us."
      description="Per-second billing with a five-minute quote, a defined maximum escrow amount, and automatic return of unused funds after settlement. The index below is drawn from real purchases and onchain settlements rather than list prices."
    >
      <InformationSection index="01" title="Current rate">
        <dl className="information-metrics">
          <div><dt>Displayed rate</dt><dd>$0.80 / hr</dd></div>
          <div><dt>Exact rate</dt><dd>0.7992 USDG</dd></div>
          <div><dt>Metering</dt><dd>Per second</dd></div>
        </dl>
        <p>
          An offer charges 222 USDG base units per second, equal to 0.000222 USDG per second or
          0.7992 USDG per hour, which the interface rounds to $0.80. The rate is the same across
          every GPU class the network currently serves.
        </p>
      </InformationSection>

      <InformationSection index="02" title="What compute actually costs">
        <p>
          There is no public print of what an hour of a datacenter GPU trades for. Prices are
          quotes on landing pages, and what anyone paid stays private. Because every lease here
          settles onchain, this network produces the record as a side effect of operating, so it
          is published rather than kept.
        </p>
        <PriceIndex />
        <p>
          The gap between the two columns is the margin the network runs on, and it is visible
          for the same reason everything else is.
        </p>
      </InformationSection>

      <InformationSection index="03" title="Service limits">
        <ul>
          <li>Quotes expire after five minutes and do not reserve capacity.</li>
          <li>A lease may run for at most six funded hours.</li>
          <li>Maximum escrow is capped at 50 USDG per lease.</li>
          <li>Billing begins only after GPU, pricing, and access-readiness checks pass.</li>
          <li>Unused escrow is returned when settlement is finalized.</li>
          <li>Wallet and Robinhood Chain gas fees are separate.</li>
        </ul>
      </InformationSection>

      <InformationSection index="04" title="Provider economics">
        <p>
          Finalized usage allocates 90% of the confirmed charge to the provider and 10% to the
          Prism as the service fee. The funded maximum is not the final charge; settlement is
          based on confirmed runtime, subject to contract limits and the dispute process.
        </p>
        <p>
          Pricing is quote-based and may change with capacity and market conditions. Always review
          the exact rate, duration, escrow amount,
          chain, and contract before signing a funding transaction.
        </p>
      </InformationSection>
    </InformationPage>
  );
}
