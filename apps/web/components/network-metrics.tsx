"use client";

import { useEffect, useState } from "react";
import type { PublicOffer } from "@/app/api/offers/route";
import {
  type LiveCapacity,
  type SettledTotals,
  formatHours,
  formatUsdg,
  formatVram,
  liveCapacity,
  providerShare,
  settledTotals,
} from "@/lib/network";
import type { PublicProofIndex } from "@/lib/proof";

type Loaded = {
  totals: SettledTotals;
  capacity: LiveCapacity | null;
  generatedAt: string;
};

export function NetworkMetrics() {
  const [data, setData] = useState<Loaded | null>(null);
  const [status, setStatus] = useState<"loading" | "unavailable" | "ready">("loading");

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      const proofResponse = await fetch("/api/proof", { cache: "no-store", signal: controller.signal });
      if (!proofResponse.ok) throw new Error("proof feed unavailable");
      const proof = (await proofResponse.json()) as PublicProofIndex;
      // Capacity is the softer number of the two: the page is still worth
      // serving from settled receipts alone when the control plane is quiet.
      let capacity: LiveCapacity | null = null;
      try {
        const offersResponse = await fetch("/api/offers", { cache: "no-store", signal: controller.signal });
        if (offersResponse.ok) capacity = liveCapacity((await offersResponse.json()) as PublicOffer[]);
      } catch {
        capacity = null;
      }
      setData({ totals: settledTotals(proof.receipts), capacity, generatedAt: proof.generated_at });
      setStatus("ready");
    };
    void load().catch((error: unknown) => {
      if (error instanceof DOMException && error.name === "AbortError") return;
      setStatus("unavailable");
    });
    return () => controller.abort();
  }, []);

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Network metrics</p>
          <h1>Network</h1>
        </div>
        <span className="chip">{status === "ready" ? "Live" : status === "loading" ? "Loading" : "Unavailable"}</span>
      </div>

      <article className="panel proof-disclosure">
        <strong>Where these numbers come from</strong>
        <p>
          Every settled figure below is the sum of amounts written into settlement transactions on Robinhood Chain, taken
          from the same public feed that backs the receipts page. Capacity is what the marketplace is advertising right
          now. Nothing here is an internal counter.
        </p>
      </article>

      {status === "loading" && (
        <article className="panel empty-state">
          <span className="empty-icon">◇</span>
          <h2>Loading network metrics</h2>
        </article>
      )}

      {status === "unavailable" && (
        <article className="panel empty-state">
          <span className="empty-icon">◇</span>
          <h2>Metrics are temporarily unavailable</h2>
          <p>No figures can be shown while the publication endpoint is unreachable.</p>
        </article>
      )}

      {status === "ready" && data && (
        <>
          <article className="panel">
            <p className="eyebrow">Settled to date</p>
            <div className="receipt-values">
              <span>{data.totals.leases.toLocaleString()} leases settled</span>
              <span>{formatHours(data.totals.seconds)} of GPU time</span>
              <span>{formatUsdg(data.totals.charged)} USDG charged</span>
              <span>{formatUsdg(data.totals.paidToProviders)} USDG to suppliers</span>
              <span>{formatUsdg(data.totals.refunded)} USDG refunded</span>
              <span>{data.totals.refundedLeases} leases refunded</span>
            </div>
            {providerShare(data.totals) !== null && (
              <p>
                {Math.round((providerShare(data.totals) ?? 0) * 100)}% of everything charged went to the supplier that
                served the work.{" "}
                {data.totals.refundedLeases > 0
                  ? `${data.totals.refundedLeases} settled leases returned part of the deposit to the renter.`
                  : "No settled lease has returned a deposit: a lease the network cannot serve is refunded before it ever settles, so it is absent from these totals rather than counted as work."}
              </p>
            )}
          </article>

          {data.capacity && (
            <article className="panel">
              <p className="eyebrow">Rentable right now</p>
              <div className="receipt-values">
                <span>{data.capacity.offers} machines advertised</span>
                <span>{data.capacity.openToEveryone} open to any wallet</span>
                <span>{formatVram(data.capacity.vramMib)} of GPU memory</span>
                {data.capacity.lowRatePerHour !== null && (
                  <span>from {formatUsdg(data.capacity.lowRatePerHour, 2)} USDG per hour</span>
                )}
              </div>
              <p>
                {data.capacity.models.map((m) => `${m.count}x ${m.model}`).join(", ")}
                {data.capacity.offers > data.capacity.openToEveryone
                  ? ". Machines beyond the open count are reserved for stakers and will not match an unstaked wallet."
                  : "."}
              </p>
            </article>
          )}

          <article className="panel">
            <p className="eyebrow">By GPU</p>
            <div className="proof-list">
              {data.totals.models.map((model) => (
                <div className="receipt" key={model.model}>
                  <div>
                    <h2>{model.model}</h2>
                    <span className="mono">{model.leases} settled</span>
                  </div>
                  <div className="receipt-values">
                    <span>{formatHours(model.seconds)} served</span>
                    <span>{formatUsdg(model.charged)} USDG charged</span>
                    {model.refunded > 0 && <span>{formatUsdg(model.refunded)} USDG refunded</span>}
                  </div>
                </div>
              ))}
            </div>
          </article>

          <p className="mono">
            Receipts published {new Date(data.generatedAt).toISOString().replace("T", " ").slice(0, 16)} UTC
            {data.totals.escrows > 1
              ? `. Lease ids restart at one per escrow deployment, and these totals span ${data.totals.escrows}.`
              : "."}
          </p>
        </>
      )}
    </section>
  );
}
