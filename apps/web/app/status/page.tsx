import type { Metadata } from "next";
import Link from "next/link";
import { InformationPage, InformationSection } from "@/components/information-page";
import { controlPlaneUrl } from "@/lib/control-plane";
import { isPublicProofIndex } from "@/lib/proof";
import { type Capacity, type LatestSettlement, incidents, since, summarize } from "@/lib/status";
import { siteUrl } from "@/lib/site";

export const metadata: Metadata = {
  title: "Status",
  description:
    "What Prism Network can do right now: capacity available to rent, the most recent settled lease, and a record of every incident that affected customers.",
  alternates: { canonical: "/status" },
};

// The page reports what is true at the moment it is asked. Caching it would
// make it report what was true earlier, which is the one thing a status page
// must never do.
export const dynamic = "force-dynamic";

async function readCapacity(): Promise<Capacity | null> {
  const base = process.env.PRISM_API_BASE_URL;
  if (!base) return null;
  const target = controlPlaneUrl(base, ["offers"]);
  if (!target) return null;
  try {
    const response = await fetch(target, { cache: "no-store", signal: AbortSignal.timeout(5_000) });
    if (!response.ok) return null;
    const offers: unknown = await response.json();
    if (!Array.isArray(offers)) return null;
    const models = new Set<string>();
    for (const offer of offers) {
      const model = (offer as { gpu?: { model?: unknown } })?.gpu?.model;
      if (typeof model === "string" && model.length > 0 && model.length <= 64) models.add(model);
    }
    return { offers: offers.length, gpuModels: [...models].sort() };
  } catch {
    return null;
  }
}

async function readLatestSettlement(): Promise<LatestSettlement | null> {
  const source = process.env.PRISM_PROOF_INDEX_URL;
  if (!source) return null;
  try {
    const response = await fetch(source, { cache: "no-store", signal: AbortSignal.timeout(5_000) });
    if (!response.ok) return null;
    const index: unknown = await response.json();
    if (!isPublicProofIndex(index)) return null;
    const last = index.receipts.at(-1);
    if (!last) return null;
    return {
      observedAt: index.generated_at,
      gpuModel: last.gpu_model,
      transactionHash: last.transaction_hash,
    };
  } catch {
    return null;
  }
}

export default async function StatusPage() {
  const [capacity, latest] = await Promise.all([readCapacity(), readLatestSettlement()]);
  const now = Date.now();
  const open = incidents.filter((incident) => incident.resolved === null);

  return (
    <InformationPage
      eyebrow="Network / Status"
      title="What the network can do right now."
      description={summarize(capacity, latest)}
    >
      <InformationSection index="01" title="Right now">
        {open.length > 0 && (
          <p>
            <strong>There is an open incident.</strong> Details are in the record below.
          </p>
        )}
        <h3>Capacity you can rent</h3>
        {capacity === null ? (
          <p>
            Live capacity could not be read just now. That is a fault in this page rather than a
            statement about the network, so treat it as unknown rather than as an outage.
          </p>
        ) : capacity.offers === 0 ? (
          <p>
            No machines are available to rent at the moment. Supply is drawn from providers as
            demand arrives, so an empty marketplace is normal at quiet times and is not by itself a
            fault.
          </p>
        ) : (
          <p>
            {capacity.offers} {capacity.offers === 1 ? "machine" : "machines"} available across{" "}
            {capacity.gpuModels.join(", ")}. Availability changes minute to minute as leases start
            and end.
          </p>
        )}

        <h3>Most recent settled lease</h3>
        {latest === null ? (
          <p>The settlement record could not be read just now.</p>
        ) : (
          <p>
            Published {since(latest.observedAt, now)}, on {latest.gpuModel}. Every finalized lease
            leaves a receipt anyone can check on a block explorer, and the full list is on the{" "}
            <Link href={new URL("/proof", siteUrl).href}>receipts page</Link>. A quiet period here
            means no leases have finished recently, which is not the same as the network being
            unable to serve one.
          </p>
        )}
      </InformationSection>

      <InformationSection index="02" title="Incident record">
        <p>
          Every incident that affected a customer is listed here, including the ones nobody
          reported. Entries are kept in the public source of this site, so the history is reviewed
          like any other change and cannot be quietly revised later.
        </p>
        {incidents.length === 0 ? (
          <p>No incidents recorded.</p>
        ) : (
          incidents.map((incident) => (
            <div key={incident.started}>
              <h3>{incident.title}</h3>
              <p>
                <strong>
                  {new Date(incident.started).toISOString().slice(0, 16).replace("T", " ")} UTC
                  {incident.resolved
                    ? ` to ${new Date(incident.resolved).toISOString().slice(11, 16)} UTC, resolved`
                    : ", open"}
                </strong>
              </p>
              <p>
                <strong>Effect.</strong> {incident.effect}
              </p>
              <p>
                <strong>Cause.</strong> {incident.cause}
              </p>
              <p>
                <strong>Fix.</strong> {incident.fix}
              </p>
            </div>
          ))
        )}
      </InformationSection>

      <InformationSection index="03" title="What this page does not promise">
        <p>
          Prism does not offer an availability commitment. Capacity is sourced as demand arrives, so
          the number above can fall to zero without anything being broken, and a lease that cannot
          be matched returns the deposit rather than waiting.
        </p>
        <p>
          The figures here are read live from the network each time this page loads. They are not
          cached, averaged, or smoothed, and no uptime percentage is published, because a single
          number would hide exactly the failures this page exists to disclose.
        </p>
      </InformationSection>
    </InformationPage>
  );
}
