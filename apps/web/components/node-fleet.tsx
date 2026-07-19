"use client";

import { useSupplierSummary } from "@/components/use-supplier-summary";
import { formatUsdg } from "@/lib/supplier";

const checks = [
  "Ubuntu 24.04 x86-64",
  "NVIDIA GPU and driver",
  "IOMMU/VFIO enabled",
  "containerd and Kata runtime",
  "Outbound mTLS tunnel",
];

export function NodeFleet() {
  const { auth, data, isPending, isError, refetch } = useSupplierSummary();

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div><p className="eyebrow">Supply</p><h1>GPU nodes</h1></div>
        <span className="chip">Independent operators</span>
      </div>

      {!auth.authenticated ? (
        <Empty title="Sign in to manage nodes" message="Node inventory is scoped to wallets whose ownership your Prism account has verified." action={auth.configured ? <button className="button primary" type="button" onClick={auth.login}>Sign in</button> : null} />
      ) : isPending ? (
        <Empty title="Loading node inventory" />
      ) : isError ? (
        <Empty title="Node inventory is unavailable" message="The supplier index could not be loaded." action={<button className="button secondary" type="button" onClick={() => void refetch()}>Retry</button>} />
      ) : data.nodes.length ? (
        <>
          <div className="metric-grid">
            <Metric label="Registered nodes" value={String(data.nodes.length)} detail={`${data.nodes.filter((node) => node.offer.online && !node.suspended).length} online`} />
            <Metric label="Settled leases" value={String(data.total_finalized_leases)} detail="Finalized onchain" />
            <Metric label="Provider paid" value={`${formatUsdg(data.total_provider_paid_base_units)} USDG`} detail="Across linked payout wallets" />
            <Metric label="Verified wallets" value={String(data.linked_wallets.length)} detail="Ownership proven" />
          </div>
          <article className="panel table-panel">
            <div className="table-wrap">
              <table>
                <thead><tr><th>Node</th><th>GPU</th><th>Rate</th><th>Reliability</th><th>Certificate</th><th>Network</th></tr></thead>
                <tbody>
                  {data.nodes.map((node) => (
                    <tr key={node.offer.node_id}>
                      <td><span className="mono">{short(node.offer.node_id)}</span><br /><small className="muted">{short(node.offer.payout_wallet)}</small></td>
                      <td>{node.offer.gpu.model}<br /><small className="muted">{formatVram(node.offer.gpu.vram_mib)} · CUDA {node.offer.gpu.cuda_major}</small></td>
                      <td>{formatUsdg(node.offer.rate_per_second)} USDG/s</td>
                      <td>{(node.offer.reliability_bps / 100).toFixed(2)}%</td>
                      <td><span className={`status-badge ${node.certificate_status === "active" ? "active" : ""}`}>{node.certificate_status}</span>{node.certificate_expires_at && <><br /><small className="muted">expires {new Date(node.certificate_expires_at).toLocaleDateString()}</small></>}</td>
                      <td><span className={`status-badge ${node.offer.online && !node.suspended ? "active" : ""}`}>{node.suspended ? "suspended" : node.offer.online ? "online" : "offline"}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>
        </>
      ) : (
        <Empty title="No nodes linked to this account" message="Verify the operator or payout wallet used during enrollment, then run the host enrollment sequence." />
      )}

      <div className="dashboard-grid">
        <article className="panel checklist">
          <p className="eyebrow">Host baseline</p><h2>Preflight requirements</h2>
          <ul>{checks.map((item) => <li key={item}><span>✓</span>{item}</li>)}</ul>
        </article>
        <article className="panel code-panel">
          <p className="eyebrow">Enrollment sequence</p>
          <h2>Identity, enrollment and certificate</h2>
          <code>prismd preflight</code>
          <code>prismd create-identity --path /var/lib/prismd/device.json</code>
          <code>prismd enroll --identity /var/lib/prismd/device.json …</code>
          <code>prismd certificate --identity /var/lib/prismd/device.json …</code>
          <p className="muted">The node certificate is short-lived and bound to the enrolled device identity. The tunnel is rejected after expiry, revocation or node suspension.</p>
        </article>
      </div>
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

function formatVram(value: number) {
  return `${Math.round(value / 1024)} GB`;
}
