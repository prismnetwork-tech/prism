import { LeaseTable } from "@/components/lease-table";

export default function LeasesPage() {
  return (
    <section className="page-stack">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Runtime ledger</p>
          <h1>Leases</h1>
        </div>
        <span className="chip">USDG escrow</span>
      </div>
      <LeaseTable />
    </section>
  );
}
