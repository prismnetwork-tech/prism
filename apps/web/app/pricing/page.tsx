import type { Metadata } from "next";
import { InformationPage, InformationSection } from "@/components/information-page";

export const metadata: Metadata = {
  title: "Pricing",
  description: "Current Prism L40S beta pricing, escrow limits, and settlement economics.",
  alternates: { canonical: "/pricing" },
};

export default function PricingPage() {
  return (
    <InformationPage
      eyebrow="Product / Pricing"
      title="$0.80 per L40S GPU hour."
      description="A single metered launch tier with a per-second quote, bounded escrow, and a refund for unused funded time."
    >
      <InformationSection index="01" title="Launch rate">
        <dl className="information-metrics">
          <div><dt>Displayed rate</dt><dd>$0.80 / hr</dd></div>
          <div><dt>Exact rate</dt><dd>0.7992 USDG</dd></div>
          <div><dt>Metering</dt><dd>Per second</dd></div>
        </dl>
        <p>
          The registered launch offer charges 222 USDG base units per second, equal to
          0.000222 USDG per second or 0.7992 USDG per hour. The interface rounds that rate to
          $0.80. Capacity is offered only while a qualifying upstream L40S host is available.
        </p>
      </InformationSection>

      <InformationSection index="02" title="Escrow and limits">
        <ul>
          <li>Quotes expire after five minutes and do not reserve capacity.</li>
          <li>A lease may run for at most six funded hours.</li>
          <li>Maximum escrow is capped at 50 USDG per lease.</li>
          <li>Billing begins only after the workspace passes GPU, cost, and access admission.</li>
          <li>Unused escrow is returned when terminal settlement succeeds.</li>
          <li>Wallet and Robinhood Chain gas fees are separate.</li>
        </ul>
      </InformationSection>

      <InformationSection index="03" title="Settlement economics">
        <p>
          Finalized usage allocates 90% of the confirmed charge to the provider and 10% to the
          protocol platform account. The funded maximum is not the final charge: settlement is
          based on admitted runtime, subject to the contract cap and dispute process.
        </p>
        <p>
          Pricing is quote-based and may change when registered capacity, upstream economics, or
          governance configuration changes. Always review the exact rate, duration, escrow amount,
          chain, and contract before signing a funding transaction.
        </p>
      </InformationSection>
    </InformationPage>
  );
}
