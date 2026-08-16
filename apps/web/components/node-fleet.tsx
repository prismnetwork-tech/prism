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

const REGISTRY = "0xDaE90914CCb3601ABdfAEf994CD07eE7676519Dc";
const RPC = "https://rpc.mainnet.chain.robinhood.com";
const GUIDE = "https://github.com/prismnetworkdottech/prism/blob/main/deploy/node/README.md";

export function NodeFleet() {
  const { auth, data, isPending, isError, refetch } = useSupplierSummary();

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div><p className="eyebrow">Provider infrastructure</p><h1>GPU nodes</h1></div>
        <span className="chip">Provider portal</span>
      </div>

      <article className="panel">
        <p className="eyebrow">Supply capacity</p>
        <h2>Put a GPU on the network</h2>
        <p>
          Prism pays 90% of confirmed usage to the payout wallet you nominate, settled in
          USDG against an onchain receipt. Joining takes a bond in PRISM, held by the
          registry while the node serves and returned when it retires.
        </p>
        <p className="muted">
          The bond scales with the rate a node charges. Ask the registry what yours costs
          before committing anything: the dry run below signs the registration and reports
          what would happen without spending.
        </p>
      </article>

      {auth.authenticated && (
        isPending ? (
          <Empty title="Loading node inventory" />
        ) : isError ? (
          <Empty title="Node inventory is unavailable" message="Provider records could not be loaded. Try again shortly." action={<button className="button secondary" type="button" onClick={() => void refetch()}>Retry</button>} />
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
          <Empty
            title="No nodes on this account"
            message="Nodes appear here once they are bonded and enrolled against a wallet you have verified. If a machine is already running, check that it was registered to one of your linked wallets."
            action={<a className="button secondary" href={GUIDE} target="_blank" rel="noopener noreferrer">Read the setup guide</a>}
          />
        )
      )}

      <div className="dashboard-grid">
        <article className="panel checklist">
          <p className="eyebrow">Host requirements</p><h2>Infrastructure baseline</h2>
          <ul>{checks.map((item) => <li key={item}><span>✓</span>{item}</li>)}</ul>
          <p className="muted">
            A host reached over the outbound tunnel and running the isolated stack is
            published above open capacity, which is the tier renters can require for
            workloads they will not place on a machine that can read guest memory.
          </p>
        </article>
        <article className="panel code-panel">
          <p className="eyebrow">Provider onboarding</p>
          <h2>Node registration</h2>
          <code>prismd preflight</code>
          <code>prismd create-identity --path /var/lib/prismd/device.json</code>
          <code>{`prismd register --identity /var/lib/prismd/device.json --rpc-url ${RPC} --registry ${REGISTRY} --rate-per-second 222 --dry-run`}</code>
          <code>prismd enroll --identity /var/lib/prismd/device.json …</code>
          <code>prismd certificate --identity /var/lib/prismd/device.json …</code>
          <p className="muted">
            Enrollment is permissionless: the control plane accepts any node whose device
            key signs the request and whose bond the registry confirms. The{" "}
            <a href={GUIDE} target="_blank" rel="noopener noreferrer">installation guide</a>{" "}
            covers the host baseline, the bond and the services in full.
          </p>
        </article>
      </div>

      {!auth.authenticated && auth.configured && (
        <Empty title="Already running a node?" message="Sign in with the operator or payout wallet used during enrollment to see its inventory, certificates and settled earnings." action={<button className="button primary" type="button" onClick={auth.login}>Sign in</button>} />
      )}
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
