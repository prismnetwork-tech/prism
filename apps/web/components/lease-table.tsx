"use client";

import { useEffect, useState } from "react";
import { usePrismAuth } from "@/components/providers";

type Lease = {
  lease_id: number;
  node_id: string;
  image: string;
  duration_seconds: number;
  maximum_escrow: number;
  funding_transaction_hash: string;
  state: string;
  created_at: string;
};

type LeaseAccess = {
  lease_id: number;
  token: string;
  gateway_host: string;
  relay_port: number;
  ssh_user: string;
  jupyter_path: string;
  jupyter_token: string;
  expires_at: string;
};

export function LeaseTable() {
  const auth = usePrismAuth();
  const [leases, setLeases] = useState<Lease[]>([]);
  const [status, setStatus] = useState<"idle" | "loading" | "ready" | "unavailable">("idle");
  const [access, setAccess] = useState<LeaseAccess | null>(null);
  const [accessStatus, setAccessStatus] = useState<"idle" | "loading" | "unavailable">("idle");

  useEffect(() => {
    if (!auth.authenticated) {
      setLeases([]);
      setStatus("idle");
      return;
    }
    const controller = new AbortController();
    setStatus("loading");
    void fetch("/api/app/leases", { cache: "no-store", signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error("lease history unavailable");
        const payload: unknown = await response.json();
        if (!Array.isArray(payload)) throw new Error("invalid lease history");
        return payload.filter(isLease);
      })
      .then((records) => {
        setLeases(records);
        setStatus("ready");
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setStatus("unavailable");
      });
    return () => controller.abort();
  }, [auth.authenticated]);

  if (!auth.authenticated) {
    return <Empty title="Sign in to view leases" message="Lease history is private to your Prism account." />;
  }
  if (status === "loading") {
    return <Empty title="Loading lease history" />;
  }
  if (status === "unavailable") {
    return <Empty title="Lease history is unavailable" message="The control plane could not load your indexed escrow leases." />;
  }
  if (!leases.length) {
    return <Empty title="No leases yet" message="A lease appears here after its quote-bound escrow transaction reaches finality." />;
  }

  return (
    <article className="panel table-panel">
      <div className="table-wrap">
        <table>
          <thead><tr><th>Lease</th><th>Image</th><th>Maximum</th><th>Created</th><th>Status</th><th>Funding</th><th>Access</th></tr></thead>
          <tbody>
            {leases.map((lease) => (
              <tr key={lease.lease_id}>
                <td><span className="mono">#{lease.lease_id}</span><br /><small className="muted">{short(lease.node_id)}</small></td>
                <td title={lease.image}>{shortImage(lease.image)}</td>
                <td>{formatUsdg(lease.maximum_escrow)} USDG</td>
                <td>{new Date(lease.created_at).toLocaleString()}</td>
                <td><span className={`status-badge ${lease.state}`}>{lease.state.replaceAll("_", " ")}</span></td>
                <td><a href={`https://robinhoodchain.blockscout.com/tx/${lease.funding_transaction_hash}`} target="_blank" rel="noreferrer">Explorer</a></td>
                <td>
                  {lease.state === "active" ? (
                    <button
                      className="button secondary compact"
                      type="button"
                      disabled={accessStatus === "loading"}
                      onClick={() => void loadAccess(lease.lease_id, setAccess, setAccessStatus)}
                    >
                      {accessStatus === "loading" ? "Loading…" : "Connect"}
                    </button>
                  ) : <span className="muted">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {accessStatus === "unavailable" && (
        <div className="access-panel"><p>Access credentials are unavailable. The grant may be rotating or the lease may be closing.</p></div>
      )}
      {access && <AccessPanel access={access} onClose={() => setAccess(null)} />}
    </article>
  );
}

function AccessPanel({ access, onClose }: { access: LeaseAccess; onClose: () => void }) {
  const relay = `prismd relay --gateway ${access.gateway_host}:${access.relay_port} --server-name ${access.gateway_host} --ca-certificate prism-ca.crt --token '${access.token}'`;
  return (
    <section className="access-panel" aria-label={`Access for lease ${access.lease_id}`}>
      <div className="section-heading">
        <div><p className="eyebrow">Lease #{access.lease_id}</p><h2>Private gateway access</h2></div>
        <button className="button secondary compact" type="button" onClick={onClose}>Close</button>
      </div>
      <p className="muted">Grant expires {new Date(access.expires_at).toLocaleString()}. Fetch a fresh grant here before it expires.</p>
      <label>SSH relay</label>
      <code>{`${relay} --service ssh --listen 127.0.0.1:2222`}</code>
      <code>{`ssh -p 2222 ${access.ssh_user}@127.0.0.1`}</code>
      <label>Jupyter relay</label>
      <code>{`${relay} --service jupyter --listen 127.0.0.1:8888`}</code>
      <code>{`http://127.0.0.1:8888${access.jupyter_path}?token=${access.jupyter_token}`}</code>
    </section>
  );
}

async function loadAccess(
  leaseId: number,
  setAccess: (value: LeaseAccess | null) => void,
  setStatus: (value: "idle" | "loading" | "unavailable") => void,
) {
  setStatus("loading");
  try {
    const response = await fetch(`/api/app/leases/${leaseId}/access`, { cache: "no-store" });
    if (!response.ok) throw new Error("lease access unavailable");
    const payload: unknown = await response.json();
    if (!isLeaseAccess(payload)) throw new Error("invalid lease access");
    setAccess(payload);
    setStatus("idle");
  } catch {
    setAccess(null);
    setStatus("unavailable");
  }
}

function Empty({ title, message }: { title: string; message?: string }) {
  return <article className="panel empty-state"><span className="empty-icon">◇</span><h2>{title}</h2>{message && <p>{message}</p>}</article>;
}

function isLease(value: unknown): value is Lease {
  if (!value || typeof value !== "object") return false;
  const lease = value as Partial<Lease>;
  return Number.isSafeInteger(lease.lease_id)
    && typeof lease.node_id === "string"
    && /^0x[0-9a-f]{64}$/i.test(lease.node_id)
    && typeof lease.image === "string"
    && typeof lease.duration_seconds === "number"
    && typeof lease.maximum_escrow === "number"
    && typeof lease.funding_transaction_hash === "string"
    && /^0x[0-9a-f]{64}$/i.test(lease.funding_transaction_hash)
    && typeof lease.state === "string"
    && typeof lease.created_at === "string";
}

function isLeaseAccess(value: unknown): value is LeaseAccess {
  if (!value || typeof value !== "object") return false;
  const access = value as Partial<LeaseAccess>;
  return Number.isSafeInteger(access.lease_id)
    && typeof access.token === "string"
    && access.token.length > 32
    && typeof access.gateway_host === "string"
    && typeof access.relay_port === "number"
    && typeof access.ssh_user === "string"
    && typeof access.jupyter_path === "string"
    && typeof access.jupyter_token === "string"
    && typeof access.expires_at === "string";
}

function short(value: string) {
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}

function shortImage(value: string) {
  const [repository, digest] = value.split("@");
  return `${repository.split("/").at(-1)}@${digest?.slice(0, 13)}…`;
}

function formatUsdg(value: number) {
  return (value / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 6 });
}
