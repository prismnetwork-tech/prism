"use client";

import { useCallback, useEffect, useState } from "react";
import { usePrismAuth } from "@/components/providers";
import {
  isAuditEvent,
  isOperatorDispute,
  operatorActions,
  type AuditEvent,
  type OperatorAction,
  type OperatorDispute,
} from "@/lib/operator";

export function OperatorConsole() {
  const auth = usePrismAuth();
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [disputes, setDisputes] = useState<OperatorDispute[]>([]);
  const [status, setStatus] = useState<"idle" | "loading" | "ready" | "forbidden" | "unavailable">("idle");
  const [action, setAction] = useState<OperatorAction>("node_suspend");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const [evidence, setEvidence] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [copyNotice, setCopyNotice] = useState<string | null>(null);

  const loadOperatorData = useCallback(async (signal?: AbortSignal) => {
    if (!auth.authenticated) return;
    setStatus("loading");
    try {
      const [auditResponse, disputesResponse] = await Promise.all([
        fetch("/api/app/operator/audit", { cache: "no-store", signal }),
        fetch("/api/app/operator/disputes", { cache: "no-store", signal }),
      ]);
      if (auditResponse.status === 403 || disputesResponse.status === 403) {
        setStatus("forbidden");
        return;
      }
      if (!auditResponse.ok || !disputesResponse.ok) throw new Error("operator data unavailable");
      const [auditPayload, disputesPayload]: unknown[] = await Promise.all([
        auditResponse.json(),
        disputesResponse.json(),
      ]);
      if (!Array.isArray(auditPayload) || !auditPayload.every(isAuditEvent)) throw new Error("operator audit response invalid");
      if (!Array.isArray(disputesPayload) || !disputesPayload.every(isOperatorDispute)) throw new Error("operator dispute response invalid");
      setAudit(auditPayload);
      setDisputes(disputesPayload);
      setStatus("ready");
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
      setStatus("unavailable");
    }
  }, [auth.authenticated]);

  useEffect(() => {
    const controller = new AbortController();
    void loadOperatorData(controller.signal);
    return () => controller.abort();
  }, [loadOperatorData]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setNotice(null);
    try {
      const response = await fetch("/api/app/operator/controls", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action_id: crypto.randomUUID(),
          action,
          target_id: target.trim(),
          reason: reason.trim(),
          evidence_hash: evidence.trim() || null,
        }),
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        const message = isApiError(payload) ? payload.message : "Operator control was rejected.";
        throw new Error(message);
      }
      if (!isAuditEvent(payload)) throw new Error("Operator control returned an invalid audit record.");
      setAudit((current) => [payload, ...current.filter((item) => item.event_id !== payload.event_id)]);
      setReason("");
      setEvidence("");
      setNotice("Control applied and recorded in the append-only audit log.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Operator control could not be applied.");
    } finally {
      setSubmitting(false);
    }
  }

  if (!auth.authenticated) {
    return <Shell><Empty title="Operator authentication required" message="Sign in with an explicitly allowlisted operator account." action={auth.configured ? <button className="button primary" type="button" onClick={auth.login}>Sign in</button> : null} /></Shell>;
  }
  if (status === "loading" || status === "idle") return <Shell><Empty title="Loading operator authorization" /></Shell>;
  if (status === "forbidden") return <Shell><Empty title="Operator access denied" message="This account is not present in the server-side operator allowlist." /></Shell>;
  if (status === "unavailable") return <Shell><Empty title="Operator controls are unavailable" action={<button className="button secondary" type="button" onClick={() => void loadOperatorData()}>Retry</button>} /></Shell>;

  return (
    <Shell>
      <div className="operator-layout">
        <form className="panel launch-form" onSubmit={(event) => void submit(event)}>
          <div><p className="eyebrow">Privileged mutation</p><h2>Apply control</h2></div>
          <label>Action<select value={action} onChange={(event) => setAction(event.target.value as OperatorAction)}>{operatorActions.map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label>
          <label>Target<input value={target} onChange={(event) => setTarget(event.target.value)} maxLength={255} required spellCheck="false" placeholder={action.startsWith("node_") || action === "slash_evidence_record" ? "0x… node ID" : "Privy account subject"} /></label>
          <label>Reason<textarea value={reason} onChange={(event) => setReason(event.target.value)} minLength={8} maxLength={512} required /></label>
          {action === "slash_evidence_record" && <label>Evidence hash<input value={evidence} onChange={(event) => setEvidence(event.target.value)} pattern="0x[0-9a-fA-F]{64}" required placeholder="0x…" /></label>}
          <button className="button primary full" type="submit" disabled={submitting}>{submitting ? "Applying…" : "Apply and audit"}</button>
          {notice && <p className="form-notice" role="status">{notice}</p>}
        </form>
        <article className="panel proof-disclosure"><p className="eyebrow">Control boundary</p><h2>Every mutation is attributable</h2><p>Account and node controls require a server-authorized operator subject. Action IDs are idempotent, session suspension revokes active sessions, and audit rows cannot be updated or deleted.</p></article>
      </div>
      <article className="panel dispute-queue">
        <div className="panel-heading">
          <div><p className="eyebrow">Safe resolution queue</p><h2>Disputed settlements</h2></div>
          <span className="chip">{disputes.length} open</span>
        </div>
        <p className="muted">Evidence is reduced to metering boundaries and hashes. Copying calldata does not submit a transaction; Safe owners must independently review and approve it.</p>
        <div className="dispute-list">
          {disputes.map((dispute) => (
            <article className="dispute-card" key={dispute.lease_id}>
              <div className="panel-heading">
                <div><p className="eyebrow">Lease #{dispute.lease_id}</p><h3>{dispute.evidence.gpu_model}</h3></div>
                <span className={`chip ${dispute.evidence.proposal_integrity_valid ? "success" : ""}`}>
                  {dispute.evidence.proposal_integrity_valid ? "Proposal verified" : "Manual review"}
                </span>
              </div>
              <dl className="detail-grid compact-details">
                <div><dt>Node</dt><dd className="mono">{short(dispute.node_id)}</dd></div>
                <div><dt>Telemetry</dt><dd>{dispute.evidence.telemetry_records} records</dd></div>
                <div><dt>Access window</dt><dd>{formatUnix(dispute.evidence.access_started_at)} – {formatUnix(dispute.evidence.access_ended_at)}</dd></div>
                <div><dt>Readiness</dt><dd>CUDA {formatUnix(dispute.evidence.cuda_ready_at)} · access {formatUnix(dispute.evidence.interactive_access_ready_at)}</dd></div>
                <div><dt>Deposit</dt><dd>{formatUsd(dispute.evidence.deposit_base_units)} USDG</dd></div>
                <div><dt>Proposed runtime</dt><dd>{dispute.proposal ? `${dispute.proposal.usage_seconds}s` : "Unavailable"}</dd></div>
              </dl>
              <div className="evidence-hashes">
                <span>Evidence <code>{dispute.evidence.evidence_hash}</code></span>
                {dispute.proposal && <span>Receipt <code>{dispute.proposal.receipt_hash}</code></span>}
                {dispute.proposal && <span>Proposal transaction <code>{dispute.proposal.transaction_hash}</code></span>}
              </div>
              {dispute.accept_proposal_transaction ? (
                <div className="safe-transaction">
                  <span>Safe target <code>{dispute.accept_proposal_transaction.to}</code></span>
                  <code>{dispute.accept_proposal_transaction.data}</code>
                  <button className="button secondary compact" type="button" onClick={() => void copyCalldata(dispute.accept_proposal_transaction!.data, setCopyNotice)}>Copy Safe calldata</button>
                </div>
              ) : (
                <p className="form-notice">No acceptance calldata is available. Verify the evidence hash and deployment configuration before resolving.</p>
              )}
            </article>
          ))}
          {!disputes.length && <div className="empty-inline"><span className="empty-icon">◇</span><p>No disputed settlements require review.</p></div>}
        </div>
        {copyNotice && <p className="form-notice" role="status">{copyNotice}</p>}
      </article>
      <article className="panel table-panel">
        <div className="table-wrap">
          <table>
            <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Reason</th><th>Actor</th></tr></thead>
            <tbody>
              {audit.map((event) => (
                <tr key={event.event_id}>
                  <td>{new Date(event.created_at).toLocaleString()}</td>
                  <td><span className="status-badge">{event.action.replaceAll("_", " ")}</span></td>
                  <td><span className="mono">{short(event.target_id)}</span><br /><small className="muted">{event.target_type}</small></td>
                  <td>{event.reason}{event.evidence_hash && <><br /><small className="mono">{short(event.evidence_hash)}</small></>}</td>
                  <td className="mono">{short(event.actor_subject)}</td>
                </tr>
              ))}
              {!audit.length && <tr><td colSpan={5}>No operator controls have been recorded.</td></tr>}
            </tbody>
          </table>
        </div>
      </article>
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return <section className="page-stack"><div className="page-heading"><div><p className="eyebrow">Restricted operations</p><h1>Operator controls</h1></div><span className="chip">Allowlist required</span></div>{children}</section>;
}

function Empty({ title, message, action }: { title: string; message?: string; action?: React.ReactNode }) {
  return <article className="panel empty-state"><span className="empty-icon">◇</span><h2>{title}</h2>{message && <p>{message}</p>}{action}</article>;
}

function isApiError(value: unknown): value is { message: string } {
  return Boolean(value) && typeof value === "object" && typeof (value as { message?: unknown }).message === "string";
}

function short(value: string) {
  if (value.length <= 18) return value;
  return `${value.slice(0, 9)}…${value.slice(-7)}`;
}

function formatUnix(value: number) {
  return new Date(value * 1_000).toLocaleString();
}

function formatUsd(baseUnits: number) {
  return (baseUnits / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 6 });
}

async function copyCalldata(data: string, setNotice: (notice: string) => void) {
  try {
    await navigator.clipboard.writeText(data);
    setNotice("Safe calldata copied. Review the target, value and decoded method before signing.");
  } catch {
    setNotice("Clipboard access failed. Copy the calldata directly from the dispute record.");
  }
}
