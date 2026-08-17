"use client";

import { useEffect, useState } from "react";
import { recomputeReceiptHash } from "@/lib/proof";
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
        <div><p className="eyebrow">Settlement receipts</p><h1>Receipts</h1></div>
        <span className="chip">{statusLabel(status, proof)}</span>
      </div>
      <article className="panel proof-disclosure"><strong>About these receipts</strong><p>{disclosure(proof)}</p></article>
      {status === "loading" && <article className="panel empty-state"><span className="empty-icon">◇</span><h2>Loading receipts</h2></article>}
      {status === "unavailable" && <article className="panel empty-state"><span className="empty-icon">◇</span><h2>Receipts are temporarily unavailable</h2><p>No receipts can be shown while the publication endpoint is unreachable.</p></article>}
      {status === "ready" && proof?.receipts.length === 0 && <article className="panel empty-state"><span className="empty-icon">◇</span><h2>No settlement receipts published</h2><p>Receipts are published after a funded lease reaches final settlement onchain.</p></article>}
      {status === "ready" && proof && proof.receipts.length > 0 && <article className="panel proof-list">{proof.receipts.map((receipt) => <Receipt key={receipt.receipt_id} receipt={receipt} />)}</article>}
    </section>
  );
}

function statusLabel(status: "loading" | "unavailable" | "ready", proof: PublicProofIndex | null) {
  if (status === "loading") return "Loading";
  if (status === "unavailable") return "Feed unavailable";
  return proof?.receipts.length ? "Live artifacts" : "Awaiting first receipt";
}

// The blanket wording stays exact for a feed where nothing was device verified.
// It stops being exact the moment one receipt carries a verdict, and an
// understatement is as wrong here as a claim.
function disclosure(proof: PublicProofIndex | null) {
  if (!proof?.receipts.some((receipt) => receipt.attestation)) {
    return "Each receipt links a platform-attested usage record to an onchain settlement. It does not independently attest hardware execution or contract correctness.";
  }
  return "Each receipt links a usage record to an onchain settlement. Where a receipt shows a verified device, a vendor-signed report identified the GPU that ran the lease and this network checked that signature against NVIDIA's root. That says nothing about which host software the machine booted, and no receipt attests contract correctness.";
}

function Receipt({ receipt }: { receipt: PublicProofReceipt }) {
  const recomputed = useRecomputedHash(receipt);
  return (
    <div className="receipt">
      <div><p className="eyebrow">{formatOutcome(receipt)}</p><h2>{receipt.gpu_model}</h2><span className="mono">{shortHash(receipt.receipt_hash)}</span></div>
      <div className="receipt-values"><span>{formatRuntime(receipt.runtime_seconds)} confirmed</span><span>{formatUsdg(receipt.charged_base_units)} USDG charged</span><span>{formatUsdg(receipt.provider_paid_base_units)} USDG paid</span><span>{formatUsdg(receipt.refunded_base_units)} USDG refunded</span>{receipt.trust_class && <span>{receipt.trust_class} class</span>}{receipt.attestation && <span className="mono">device verdict {shortHash(receipt.attestation.verdict_digest)}</span>}{recomputed !== "unchecked" && <span>{hashLabel(recomputed)}</span>}</div>
      <a href={`https://robinhoodchain.blockscout.com/tx/${receipt.transaction_hash}`} target="_blank" rel="noreferrer">View settlement</a>
    </div>
  );
}

type HashCheck = "checking" | "matches" | "differs" | "unchecked";

function useRecomputedHash(receipt: PublicProofReceipt): HashCheck {
  const [check, setCheck] = useState<HashCheck>("checking");
  useEffect(() => {
    let live = true;
    void recomputeReceiptHash(receipt)
      .then((hash) => {
        if (live) setCheck(hash === receipt.receipt_hash ? "matches" : "differs");
      })
      // SubtleCrypto is missing on an insecure origin. Saying nothing is the
      // honest answer there, since the reader learned nothing either way.
      .catch(() => {
        if (live) setCheck("unchecked");
      });
    return () => {
      live = false;
    };
  }, [receipt]);
  return check;
}

function hashLabel(check: HashCheck) {
  if (check === "checking") return "checking receipt hash";
  return check === "matches" ? "receipt hash matches" : "receipt hash does not match";
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
