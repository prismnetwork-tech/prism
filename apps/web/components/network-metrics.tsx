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

type Status = "loading" | "unavailable" | "ready";

const STATE_LABEL: Record<Status, string> = {
  loading: "Reading receipts",
  unavailable: "Unavailable",
  ready: "Live",
};

// The formatters carry their unit so a figure reads correctly in prose. Here the
// unit is set beside the number at its own size, so it gets split back off.
function split(formatted: string): [string, string] {
  const gap = formatted.lastIndexOf(" ");
  return gap === -1 ? [formatted, ""] : [formatted.slice(0, gap), formatted.slice(gap + 1)];
}

function Figure({ label, value, unit }: { label: string; value: string; unit?: string }) {
  return (
    <div className="network-figure">
      <span className="network-figure-label">{label}</span>
      <span className="network-figure-value">
        {value}
        {unit ? <em>{unit}</em> : null}
      </span>
    </div>
  );
}

function Pending({ labels }: { labels: string[] }) {
  return (
    <div className="network-figures">
      {labels.map((label) => (
        <div className="network-figure" key={label}>
          <span className="network-figure-label">{label}</span>
          <span className="network-figure-value pending" />
        </div>
      ))}
    </div>
  );
}

export function NetworkMetrics() {
  const [data, setData] = useState<Loaded | null>(null);
  const [status, setStatus] = useState<Status>("loading");

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

  const totals = data?.totals;
  const share = totals ? providerShare(totals) : null;
  const [hours, hoursUnit] = split(formatHours(totals?.seconds ?? 0));
  const capacity = data?.capacity;

  return (
    <>
      <div className="network-status">
        <span className={`network-state ${status}`}>{STATE_LABEL[status]}</span>
        {data ? (
          <span>Receipts published {new Date(data.generatedAt).toISOString().replace("T", " ").slice(0, 16)} UTC</span>
        ) : null}
      </div>

      {status === "unavailable" && (
        <section className="network-unavailable">
          <h2>Metrics are temporarily unavailable</h2>
          <p>
            The page could not reach the publication endpoint just now. No figures are shown rather than stale ones, and
            the settled record itself is unaffected.
          </p>
        </section>
      )}

      {status !== "unavailable" && (
        <section className="network-section">
          <header>
            <span>01</span>
            <h2>Settled to date</h2>
          </header>

          {totals ? (
            <>
              <div className="network-figures">
                <Figure label="Leases settled" value={totals.leases.toLocaleString()} />
                <Figure label="GPU time served" value={hours} unit={hoursUnit} />
                <Figure label="Charged" value={formatUsdg(totals.charged)} unit="USDG" />
                {share !== null && <Figure label="Share to suppliers" value={`${Math.round(share * 100)}%`} />}
              </div>

              <dl className="network-detail">
                <div>
                  <dt>Paid to suppliers</dt>
                  <dd>{formatUsdg(totals.paidToProviders)} USDG</dd>
                </div>
                <div>
                  <dt>Refunded</dt>
                  <dd>{formatUsdg(totals.refunded)} USDG</dd>
                </div>
                <div>
                  <dt>Leases refunded</dt>
                  <dd>{totals.refundedLeases.toLocaleString()}</dd>
                </div>
              </dl>

              {totals.leases > 0 && (
                <p className="network-note">
                  {totals.refundedLeases > 0
                    ? `${totals.refundedLeases} settled leases returned part of the deposit to the renter. Whatever the meter does not consume goes back automatically once a lease finalizes.`
                    : "No settled lease has returned a deposit. A lease the network cannot serve is refunded before it ever settles, so it stays out of these totals rather than counting as work."}
                </p>
              )}
            </>
          ) : (
            <Pending labels={["Leases settled", "GPU time served", "Charged", "Share to suppliers"]} />
          )}
        </section>
      )}

      {status !== "unavailable" && (
        <section className="network-section">
          <header>
            <span>02</span>
            <h2>Rentable right now</h2>
          </header>

          {capacity ? (
            <>
              <div className="network-figures">
                <Figure label="Machines advertised" value={capacity.offers.toLocaleString()} />
                <Figure label="Open to any wallet" value={capacity.openToEveryone.toLocaleString()} />
                <Figure label="GPU memory" value={split(formatVram(capacity.vramMib))[0]} unit="GB" />
                {capacity.lowRatePerHour !== null && (
                  <Figure label="Lowest open rate" value={formatUsdg(capacity.lowRatePerHour, 2)} unit="USDG / hr" />
                )}
              </div>

              <ul className="network-models">
                {capacity.models.map((entry) => (
                  <li key={entry.model}>
                    <b>{entry.count}×</b>
                    {entry.model}
                  </li>
                ))}
              </ul>

              {capacity.offers > capacity.openToEveryone && (
                <p className="network-note">
                  Machines beyond the open count are reserved for stakers and will not match an unstaked wallet.
                </p>
              )}
            </>
          ) : status === "loading" ? (
            <Pending labels={["Machines advertised", "Open to any wallet", "GPU memory", "Lowest open rate"]} />
          ) : (
            <p className="network-note">
              The marketplace is not reporting capacity just now. The settled record above is unaffected.
            </p>
          )}
        </section>
      )}

      {totals && totals.models.length > 0 && (
        <section className="network-section">
          <header>
            <span>03</span>
            <h2>By GPU</h2>
          </header>
          <div className="network-scroll">
            <table className="network-table">
              <thead>
                <tr>
                  <th scope="col">GPU</th>
                  <th className="network-num" scope="col">Leases</th>
                  <th className="network-num" scope="col">Hours served</th>
                  <th className="network-num" scope="col">USDG charged</th>
                  <th scope="col">Share of hours</th>
                </tr>
              </thead>
              <tbody>
                {totals.models.map((model) => {
                  const portion = totals.seconds > 0 ? model.seconds / totals.seconds : 0;
                  return (
                    <tr key={model.model}>
                      <td className="network-gpu">{model.model}</td>
                      <td className="network-num">{model.leases.toLocaleString()}</td>
                      <td className="network-num">{split(formatHours(model.seconds))[0]}</td>
                      <td className="network-num">{formatUsdg(model.charged)}</td>
                      <td className="network-share">
                        <span role="img" aria-label={`${Math.round(portion * 100)}% of settled GPU hours`}>
                          <i style={{ width: `${Math.max(portion * 100, 1)}%` }} />
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {totals && totals.escrows > 1 && (
        <p className="network-footnote">
          Lease ids restart at one per escrow deployment, and these totals span {totals.escrows}.
        </p>
      )}
    </>
  );
}
