import Link from "next/link";

const metrics = [
  ["Available GPUs", "0", "Awaiting verified node enrollment"],
  ["Live capacity", "—", "No bonded nodes online"],
  ["Escrowed today", "—", "Contract deployment pending"],
  ["Network success", "—", "No finalized leases yet"],
] as const;

export function Dashboard() {
  return (
    <section className="page-stack">
      <div className="dashboard-hero">
        <div>
          <p className="eyebrow">GPU infrastructure</p>
          <h1>Compute with a clear settlement trail.</h1>
          <p className="hero-copy">
            Prism is being built for isolated GPU workspaces with metered USDG escrow. Availability and proof records appear only after verified nodes and onchain settlements exist.
          </p>
        </div>
        <div className="hero-actions">
          <Link className="button primary" href="/compute">View compute</Link>
          <Link className="button secondary" href="/nodes">Supply a GPU</Link>
        </div>
      </div>

      <div className="metric-grid">
        {metrics.map(([label, value, detail]) => (
          <article className="metric-card" key={label}>
            <p>{label}</p>
            <strong>{value}</strong>
            <span>{detail}</span>
          </article>
        ))}
      </div>

      <div className="dashboard-grid">
        <article className="panel capacity-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Network signal</p>
              <h2>Capacity will appear after enrollment</h2>
            </div>
            <span className="chip">No live offers</span>
          </div>
          <p className="muted">The beta will admit NVIDIA hosts only after preflight, sufficient USDG bonding and independent gateway connectivity checks are operational.</p>
          <Link className="text-link" href="/nodes">Review node requirements →</Link>
        </article>

        <article className="panel proof-preview">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Settlement proof</p>
              <h2>No published receipts</h2>
            </div>
            <span className="chip">Deployment pending</span>
          </div>
          <p className="muted">The proof feed will link platform-attested usage receipts to finalized onchain settlement events. It does not assert independent proof of hardware execution.</p>
          <Link className="text-link" href="/proof">Open proof feed →</Link>
        </article>
      </div>
    </section>
  );
}
