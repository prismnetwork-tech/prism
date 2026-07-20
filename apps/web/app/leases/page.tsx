import type { Metadata } from "next";
import { LeaseTable } from "@/components/lease-table";

export const metadata: Metadata = {
  title: "Leases",
  description: "Review GPU lease activity, funding transactions, workspace access, and settlement status.",
  robots: { index: false, follow: false },
};

export default function LeasesPage() {
  return (
    <section className="page-stack">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Compute activity</p>
          <h1>Leases</h1>
        </div>
        <span className="chip">USDG escrow</span>
      </div>
      <LeaseTable />
    </section>
  );
}
