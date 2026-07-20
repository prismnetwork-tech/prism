"use client";

import { useEffect, useState } from "react";
import type { PublicProofIndex, PublicProofReceipt } from "@/lib/proof";

export function ProofFeed() {
  const [proof, setProof] = useState<PublicProofIndex | null>(null);
  const [status, setStatus] = useState<"loading" | "unavailable" | "ready">("loading");

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/proof", { cache: "no-store", signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error("proof feed unavailable");
        return response.json() as Promise<PublicProofIndex>;
      })
      .then((index) => {
        setProof(index);
        setStatus("ready");
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setStatus("unavailable");
      });
    return () => controller.abort();
  }, []);

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div><p className="eyebrow">Public verification</p><h1>Proof feed</h1></div>
        <span className="chip">{statusLabel(status, proof)}</span>
      </div>
      <article className="panel proof-disclosure"><strong>What this proves</strong><p>Published entries link a platform-attested usage receipt to an onchain settlement event. They do not independently verify hardware execution or contract correctness.</p></article>
      {status === "loading" && <article className="panel empty-state"><span className="empty-icon">◇</span><h2>Loading proof feed</h2></article>}
      {status === "unavailable" && <article className="panel empty-state"><span className="empty-icon">◇</span><h2>Proof feed is temporarily unavailable</h2><p>No receipt data is being shown while the publication endpoint is unavailable.</p></article>}
      {status === "ready" && proof?.receipts.length === 0 && <article className="panel empty-state"><span className="empty-icon">◇</span><h2>No receipts published yet</h2><p>The first receipt will appear after a funded lease reaches finalized settlement and its artifact passes chain verification.</p></article>}
      {status === "ready" && proof && proof.receipts.length > 0 && <article className="panel proof-list">{proof.receipts.map((receipt) => <Receipt key={receipt.receipt_id} receipt={receipt} />)}</article>}
    </section>
  );
}

function statusLabel(status: "loading" | "unavailable" | "ready", proof: PublicProofIndex | null) {
  if (status === "loading") return "Loading";
  if (status === "unavailable") return "Feed unavailable";
  return proof?.receipts.length ? "Live artifacts" : "Awaiting first receipt";
}

function Receipt({ receipt }: { receipt: PublicProofReceipt }) {
  return (
    <div className="receipt">
      <div><p className="eyebrow">{formatOutcome(receipt)}</p><h2>{receipt.gpu_model}</h2><span className="mono">{shortHash(receipt.receipt_hash)}</span></div>
      <div className="receipt-values"><span>{formatRuntime(receipt.runtime_seconds)} confirmed</span><span>{formatUsdg(receipt.charged_base_units)} USDG charged</span><span>{formatUsdg(receipt.provider_paid_base_units)} USDG paid</span><span>{formatUsdg(receipt.refunded_base_units)} USDG refunded</span></div>
      <a href={`https://robinhoodchain.blockscout.com/tx/${receipt.transaction_hash}`} target="_blank" rel="noreferrer">View settlement</a>
    </div>
  );
}

function shortHash(value: string) {
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function formatRuntime(seconds: number) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3_600) {
    const minutes = Math.floor(seconds / 60);
    const remaining = seconds % 60;
    return remaining ? `${minutes}m ${remaining}s` : `${minutes}m`;
  }
  return `${(seconds / 3_600).toFixed(1)}h`;
}

function formatUsdg(value: number) {
  return (value / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 6 });
}

function formatOutcome(receipt: PublicProofReceipt) {
  return (receipt.failure_class ?? receipt.outcome).replaceAll("_", " ");
}
