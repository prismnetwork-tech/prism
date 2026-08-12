import { NextResponse } from "next/server";

export const runtime = "nodejs";
const maxResponseBytes = 200_000;

type Entry = {
  gpu_model: string;
  sourced_low_micros_per_hour: number | null;
  sourced_high_micros_per_hour: number | null;
  sourced_median_micros_per_hour: number | null;
  sourced_observations: number;
  settled_mean_micros_per_hour: number | null;
  settled_leases: number;
  last_observed_at: string | null;
};

export type PriceIndex = {
  currency: string;
  unit: string;
  generated_at: string;
  gpus: Entry[];
};

function isEntry(value: unknown): value is Entry {
  if (typeof value !== "object" || value === null) return false;
  const entry = value as Record<string, unknown>;
  const optionalNumber = (key: string) =>
    entry[key] === null || typeof entry[key] === "number";
  return (
    typeof entry.gpu_model === "string" &&
    entry.gpu_model.length > 0 &&
    entry.gpu_model.length <= 64 &&
    optionalNumber("sourced_low_micros_per_hour") &&
    optionalNumber("sourced_high_micros_per_hour") &&
    optionalNumber("sourced_median_micros_per_hour") &&
    optionalNumber("settled_mean_micros_per_hour") &&
    typeof entry.sourced_observations === "number" &&
    typeof entry.settled_leases === "number"
  );
}

function isPriceIndex(value: unknown): value is PriceIndex {
  if (typeof value !== "object" || value === null) return false;
  const index = value as Record<string, unknown>;
  return (
    typeof index.currency === "string" &&
    typeof index.unit === "string" &&
    typeof index.generated_at === "string" &&
    Array.isArray(index.gpus) &&
    index.gpus.length <= 64 &&
    index.gpus.every(isEntry)
  );
}

export async function GET() {
  const source = process.env.PRISM_PRICE_INDEX_URL;
  if (!source) {
    return NextResponse.json({ error: "price_index_unavailable" }, { status: 503 });
  }

  let url: URL;
  try {
    url = new URL(source);
  } catch {
    return NextResponse.json({ error: "price_index_unavailable" }, { status: 503 });
  }
  if (url.protocol !== "https:") {
    return NextResponse.json({ error: "price_index_unavailable" }, { status: 503 });
  }

  try {
    const response = await fetch(url, {
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) throw new Error("invalid price response");
    const body = await response.arrayBuffer();
    if (body.byteLength > maxResponseBytes) throw new Error("price response is too large");
    const payload: unknown = JSON.parse(Buffer.from(body).toString("utf8"));
    if (!isPriceIndex(payload)) throw new Error("invalid price index");
    // Prices move on the order of minutes, so a short cache keeps the page
    // honest without asking the control plane on every visit.
    return NextResponse.json(payload, { headers: { "Cache-Control": "public, max-age=60" } });
  } catch {
    return NextResponse.json({ error: "price_index_unavailable" }, { status: 503 });
  }
}
