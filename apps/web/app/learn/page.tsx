import type { Metadata } from "next";
import Link from "next/link";
import { InformationPage } from "@/components/information-page";
import { explainers } from "@/lib/explainers";

export const metadata: Metadata = {
  title: "Learn",
  description:
    "Short explainers on renting GPU compute: what a supplier can promise, how a lease settles onchain, what an agent needs to rent on its own, and what confidential compute requires.",
  alternates: { canonical: "/learn" },
};

export default function LearnPage() {
  return (
    <InformationPage
      eyebrow="Product / Learn"
      title="How renting a GPU actually works."
      description="Four explainers on the parts that are usually hand-waved: what a supplier can promise, where the money sits, what an agent needs, and what it takes to hide a workload from its host."
    >
      <div className="learn-list">
        {explainers.map((entry) => (
          <Link className="learn-item" href={`/learn/${entry.slug}`} key={entry.slug}>
            <h2>{entry.title}</h2>
            <p>{entry.dek}</p>
            <span>Read ↗</span>
          </Link>
        ))}
      </div>
    </InformationPage>
  );
}
