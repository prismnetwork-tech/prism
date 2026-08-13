import type { Metadata } from "next";
import Link from "next/link";
import { PublicFooter } from "@/components/public-footer";
import { docsUrl, siteUrl } from "@/lib/site";
import {
  type StatusComponent,
  type StatusIndex,
  STATUS_LABEL,
  formatUptime,
  headline,
  incidents,
  isStatusIndex,
  overall,
  strip,
  uptime,
} from "@/lib/status";
import "./status.css";

export const metadata: Metadata = {
  title: "Status",
  description:
    "Live status of the Prism Network marketplace, leasing, settlement and onchain contracts, with a daily record and every incident that affected customers.",
  alternates: { canonical: "/status" },
};

// A status page that reports what was true earlier is the one thing it must
// never do.
export const dynamic = "force-dynamic";

const HISTORY_DAYS = 90;

async function readStatus(): Promise<StatusIndex | null> {
  const source = process.env.PRISM_STATUS_INDEX_URL;
  if (!source) return null;
  try {
    const response = await fetch(source, { cache: "no-store", signal: AbortSignal.timeout(5_000) });
    if (!response.ok) return null;
    const payload: unknown = await response.json();
    return isStatusIndex(payload) ? payload : null;
  } catch {
    return null;
  }
}

function Bars({ component, index }: { component: StatusComponent; index: StatusIndex }) {
  const cells = strip(index.history, component.key, HISTORY_DAYS, new Date());
  return (
    <div className="status-bars" role="img" aria-label={`${HISTORY_DAYS} day history for ${component.name}`}>
      {cells.map((day) => {
        const reading = day.statuses[component.key] ?? "unknown";
        return <span key={day.date} className={`status-bar ${reading}`} title={`${day.date}: ${STATUS_LABEL[reading]}`} />;
      })}
    </div>
  );
}

export default async function StatusPage() {
  const index = await readStatus();
  const components = index?.components ?? [];
  const state = overall(components);
  const groups = [...new Set(components.map((component) => component.group))];

  return (
    <div className="information-page">
      <header className="information-header">
        <Link className="landing-brand" href="/" aria-label="prism. home">
          <img src="/brand/prism-logo.svg" alt="" width="32" height="32" />
          <span>prism.</span>
        </Link>
        <nav aria-label="Public page navigation">
          <Link href="/pricing">Pricing</Link>
          <Link href={docsUrl.href}>Docs</Link>
          <Link className="information-console-link" href="/compute">Open console ↗</Link>
        </nav>
      </header>

      <main id="main-content" tabIndex={-1} className="status-main">
        <section className={`status-headline ${index ? state : "unknown"}`}>
          <span className="status-dot" aria-hidden="true" />
          <div>
            <h1>{index ? headline(state, components.length) : "Status is unavailable"}</h1>
            <p>
              {index
                ? `Last updated ${new Date(index.generated_at).toUTCString().replace("GMT", "UTC")}`
                : "This page could not read the network just now, which is a fault in the page rather than a statement about the network."}
            </p>
          </div>
        </section>

        {groups.map((group) => (
          <section className="status-group" key={group}>
            <h2>{group}</h2>
            {components
              .filter((component) => component.group === group)
              .map((component) => (
                <article className="status-component" key={component.key}>
                  <div className="status-component-head">
                    <div>
                      <h3>{component.name}</h3>
                      <p>{component.detail}</p>
                    </div>
                    <span className={`status-pill ${component.status}`}>{STATUS_LABEL[component.status]}</span>
                  </div>
                  {index && <Bars component={component} index={index} />}
                  <div className="status-scale">
                    <span>{HISTORY_DAYS} days ago</span>
                    <span>{formatUptime(uptime(index?.history ?? [], component.key))}</span>
                    <span>Today</span>
                  </div>
                </article>
              ))}
          </section>
        ))}

        <section className="status-group">
          <h2>Past incidents</h2>
          {incidents.length === 0 ? (
            <p className="status-empty">No incidents recorded.</p>
          ) : (
            incidents.map((incident) => (
              <article className="status-incident" key={incident.started}>
                <h3>{incident.title}</h3>
                <p className="status-incident-when">
                  {new Date(incident.started).toUTCString().replace("GMT", "UTC")}
                  {incident.resolved
                    ? `, resolved after ${Math.round(
                        (Date.parse(incident.resolved) - Date.parse(incident.started)) / 3_600_000,
                      )} hours`
                    : ", ongoing"}
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
              </article>
            ))
          )}
        </section>

        <section className="status-note">
          <p>
            Readings are taken every five minutes. A day shows the worst reading it recorded, because
            averaging an outage across a day produces a number that looks like a good day. Days
            before recording began are marked unknown rather than counted as healthy.
          </p>
          <p>
            Prism publishes no single uptime figure and offers no availability commitment. Capacity
            is sourced as demand arrives, so an empty marketplace at a quiet hour is normal and is
            not counted as an outage. Settled leases are listed on the{" "}
            <Link href={new URL("/proof", siteUrl).href}>receipts page</Link>.
          </p>
        </section>
      </main>
      <PublicFooter />
    </div>
  );
}
