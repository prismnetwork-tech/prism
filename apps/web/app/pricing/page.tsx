import type { Metadata } from "next";
import { InformationPage, InformationSection } from "@/components/information-page";

export const metadata: Metadata = {
  title: "Pricing",
  description: "Prism L40S pricing, escrow limits, billing terms, and provider economics.",
  alternates: { canonical: "/pricing" },
};

export default function PricingPage() {
  return (
    <InformationPage
      eyebrow="Product / Pricing"
      title="L40S compute at $0.80 per GPU hour."
      description="Per-second billing with a five-minute quote, a defined maximum escrow amount, and automatic return of unused funds after settlement."
    >
      <InformationSection index="01" title="Current rate">
        <dl className="information-metrics">
          <div><dt>Displayed rate</dt><dd>$0.80 / hr</dd></div>
          <div><dt>Exact rate</dt><dd>0.7992 USDG</dd></div>
          <div><dt>Metering</dt><dd>Per second</dd></div>
        </dl>
        <p>
          The current L40S offer charges 222 USDG base units per second, equal to
          0.000222 USDG per second or 0.7992 USDG per hour. The interface rounds that rate to
          $0.80. Quotes are available while qualifying L40S capacity is online.
        </p>
      </InformationSection>

      <InformationSection index="02" title="Service limits">
        <ul>
          <li>Quotes expire after five minutes and do not reserve capacity.</li>
          <li>A lease may run for at most six funded hours.</li>
          <li>Maximum escrow is capped at 50 USDG per lease.</li>
          <li>Billing begins only after GPU, pricing, and access-readiness checks pass.</li>
          <li>Unused escrow is returned when settlement is finalized.</li>
          <li>Wallet and Robinhood Chain gas fees are separate.</li>
        </ul>
      </InformationSection>

      <InformationSection index="03" title="Provider economics">
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
