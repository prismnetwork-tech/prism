import Link from "next/link";

const metrics = [
  ["Cloud canary", "Passed", "L40S · 46 GB VRAM"],
  ["Beta price", "$0.80/h", "Per L40S GPU"],
  ["Available GPUs", "0", "Production deployment pending"],
  ["Escrowed today", "—", "Contract deployment pending"],
] as const;

export function Dashboard() {
  return (
    <section className="page-stack">
      <div className="dashboard-hero">
        <div>
          <p className="eyebrow">GPU infrastructure</p>
          <h1>Compute with a clear settlement trail.</h1>
          <p className="hero-copy">
            The L40S supply canary is verified. The direct-SSH broker lifecycle is wired, but Prism
            will not advertise live capacity until the production lease path passes.
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
              <h2>L40S supply verified</h2>
            </div>
            <span className="chip">Deployment pending</span>
          </div>
          <p className="muted">A live L40S instance reached CUDA-ready infrastructure with SSH access and was destroyed cleanly. Customer access remains gated until production deployment passes.</p>
          <Link className="text-link" href="/compute">Open compute console →</Link>
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
