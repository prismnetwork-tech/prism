"use client";

import { useEffect, useState } from "react";
import type { PriceIndex as PriceIndexPayload } from "@/app/api/price-index/route";

const dollars = (micros: number | null) =>
  micros === null ? "—" : `$${(micros / 1_000_000).toFixed(4)}`;

export function PriceIndex() {
  const [index, setIndex] = useState<PriceIndexPayload | null>(null);
  const [status, setStatus] = useState<"loading" | "unavailable" | "ready">("loading");

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/price-index", { cache: "no-store", signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error("price index unavailable");
        return response.json() as Promise<PriceIndexPayload>;
      })
      .then((payload) => {
        setIndex(payload);
        setStatus("ready");
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setStatus("unavailable");
      });
    return () => controller.abort();
  }, []);

  if (status === "loading") {
    return <p>Loading the current index.</p>;
  }
  if (status === "unavailable" || !index) {
    return <p>The price index is temporarily unavailable.</p>;
  }

  const priced = index.gpus.filter(
    (gpu) => gpu.sourced_median_micros_per_hour !== null || gpu.settled_mean_micros_per_hour !== null,
  );
  if (priced.length === 0) {
    return <p>No prices have been recorded yet.</p>;
  }

  return (
    <div className="price-index">
      <table>
        <thead>
          <tr>
            <th scope="col">GPU</th>
            <th scope="col">Sourced</th>
            <th scope="col">Range</th>
            <th scope="col">Settled</th>
            <th scope="col">Leases</th>
          </tr>
        </thead>
        <tbody>
          {priced.map((gpu) => (
            <tr key={gpu.gpu_model}>
              <th scope="row">{gpu.gpu_model}</th>
              <td>{dollars(gpu.sourced_median_micros_per_hour)}</td>
              <td>
                {gpu.sourced_low_micros_per_hour === null
                  ? "—"
                  : `${dollars(gpu.sourced_low_micros_per_hour)} to ${dollars(gpu.sourced_high_micros_per_hour)}`}
              </td>
              <td>{dollars(gpu.settled_mean_micros_per_hour)}</td>
              <td>{gpu.settled_leases}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="price-index-note">
        Per GPU hour in USDG. <strong>Sourced</strong> is what suppliers charged this network,
        median and range across recorded observations. <strong>Settled</strong> is what renters
        actually paid, averaged over leases that finalized onchain. Both series come out of running
        the marketplace rather than from a quote.
      </p>
    </div>
  );
}
