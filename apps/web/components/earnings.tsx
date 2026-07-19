"use client";

import { useSupplierSummary } from "@/components/use-supplier-summary";
import { formatUsdg } from "@/lib/supplier";

export function Earnings() {
  const { auth, data, isPending, isError, refetch } = useSupplierSummary();
  const activeNodes = data?.nodes.filter((node) => node.offer.online && !node.suspended).length ?? 0;
  const reliability = data?.nodes.length
    ? data.nodes.reduce((total, node) => total + node.offer.reliability_bps, 0) / data.nodes.length / 100
    : null;

  return (
    <section className="page-stack">
      <div className="page-heading"><div><p className="eyebrow">Supply revenue</p><h1>Earnings</h1></div><span className="chip">90% provider share</span></div>
      {!auth.authenticated ? (
        <Empty title="Sign in to view supplier earnings" message="Settlement totals are scoped to your verified operator and payout wallets." />
      ) : isPending ? (
        <Empty title="Loading settlement history" />
      ) : isError || !data ? (
        <Empty title="Earnings are unavailable" message="The supplier settlement index could not be loaded." action={<button className="button secondary" type="button" onClick={() => void refetch()}>Retry</button>} />
      ) : (
        <>
          <div className="metric-grid">
            <Metric label="Provider paid" value={`${formatUsdg(data.total_provider_paid_base_units)} USDG`} detail="Finalized receipts" />
            <Metric label="Settled leases" value={String(data.total_finalized_leases)} detail="Onchain finality reached" />
            <Metric label="Active nodes" value={String(activeNodes)} detail={`${data.nodes.length} registered`} />
            <Metric label="Average reliability" value={reliability === null ? "—" : `${reliability.toFixed(2)}%`} detail="Across linked nodes" />
          </div>
          <article className="panel table-panel">
            <div className="table-wrap">
              <table>
                <thead><tr><th>Node</th><th>GPU</th><th>Finalized leases</th><th>Provider paid</th><th>Payout wallet</th></tr></thead>
                <tbody>
                  {data.nodes.map((node) => (
                    <tr key={node.offer.node_id}>
                      <td className="mono">{short(node.offer.node_id)}</td>
                      <td>{node.offer.gpu.model}</td>
                      <td>{node.finalized_leases}</td>
                      <td>{formatUsdg(node.provider_paid_base_units)} USDG</td>
                      <td className="mono">{short(node.offer.payout_wallet)}</td>
                    </tr>
                  ))}
                  {!data.nodes.length && <tr><td colSpan={5}>No supplier nodes are linked to a verified wallet.</td></tr>}
                </tbody>
              </table>
            </div>
          </article>
        </>
      )}
      <article className="panel proof-disclosure"><p className="eyebrow">Settlement policy</p><h2>Receipt-backed totals</h2><p>Only finalized proof receipts count toward provider-paid totals. Pending settlement, escrow deposits and USDG bonds are excluded.</p></article>
    </section>
  );
}

function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <article className="metric-card"><p>{label}</p><strong>{value}</strong><span>{detail}</span></article>;
}

function Empty({ title, message, action }: { title: string; message?: string; action?: React.ReactNode }) {
  return <article className="panel empty-state"><span className="empty-icon">◇</span><h2>{title}</h2>{message && <p>{message}</p>}{action}</article>;
}

function short(value: string) {
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}
