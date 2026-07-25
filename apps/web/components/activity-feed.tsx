"use client";

import { useEffect, useState } from "react";
import type { PublicActivityFeed, PublicActivityItem } from "@/lib/activity";

const REFRESH_MS = 30_000;

export function ActivityFeed() {
  const [feed, setFeed] = useState<PublicActivityFeed | null>(null);
  const [status, setStatus] = useState<"loading" | "unavailable" | "ready">("loading");

  useEffect(() => {
    const controller = new AbortController();
    const load = () =>
      fetch("/api/activity", { cache: "no-store", signal: controller.signal })
        .then(async (response) => {
          if (!response.ok) throw new Error("activity feed unavailable");
          return response.json() as Promise<PublicActivityFeed>;
        })
        .then((data) => {
          setFeed(data);
          setStatus("ready");
        })
        .catch((error: unknown) => {
          if (error instanceof DOMException && error.name === "AbortError") return;
          setStatus((prev) => (prev === "ready" ? "ready" : "unavailable"));
        });
    void load();
    const timer = setInterval(() => void load(), REFRESH_MS);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, []);

  const items = feed?.activity ?? [];

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div><p className="eyebrow">Live network</p><h1>Activity</h1></div>
        <span className="chip">{statusLabel(status, items.length)}</span>
      </div>
      <article className="panel proof-disclosure">
        <strong>What this shows</strong>
        <p>Recent GPU leases moving through the network, provisioning, running, and settling onchain. Renter identity is never shown. Settled leases also publish a verifiable receipt on the <a href="/proof">receipts</a> feed.</p>
      </article>
      {status === "loading" && <article className="panel empty-state"><span className="empty-icon">◇</span><h2>Loading activity</h2></article>}
      {status === "unavailable" && <article className="panel empty-state"><span className="empty-icon">◇</span><h2>Activity is temporarily unavailable</h2></article>}
      {status === "ready" && items.length === 0 && <article className="panel empty-state"><span className="empty-icon">◇</span><h2>No recent activity</h2><p>Leases appear here as agents rent and settle compute.</p></article>}
      {status === "ready" && items.length > 0 && <article className="panel proof-list">{items.map((item) => <Activity key={item.lease_id} item={item} />)}</article>}
    </section>
  );
}

function statusLabel(status: "loading" | "unavailable" | "ready", count: number) {
  if (status === "loading") return "Loading";
  if (status === "unavailable") return "Unavailable";
  return count ? "Live" : "Idle";
}

function Activity({ item }: { item: PublicActivityItem }) {
  return (
    <div className="receipt">
      <div>
        <p className="eyebrow">{stateLabel(item.state)}</p>
        <h2>{item.gpu_model}</h2>
        <span className="mono">Lease #{item.lease_id} · {item.node_prefix}…</span>
      </div>
      <div className="receipt-values">
        <span>{formatRuntime(item.duration_seconds)}</span>
        <span>{item.settled ? `${formatUsdg(item.cost_base_units)} USDG charged` : `up to ${formatUsdg(item.cost_base_units)} USDG`}</span>
        <span>{relativeTime(item.updated_at)}</span>
      </div>
    </div>
  );
}

function stateLabel(state: string) {
  if (state === "finalized") return "Settled";
  if (state === "active" || state === "ready") return "Running";
  return state.replaceAll("_", " ");
}

function relativeTime(iso: string) {
  const seconds = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (seconds < 45) return "just now";
  if (seconds < 3_600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.round(seconds / 3_600)}h ago`;
  return `${Math.round(seconds / 86_400)}d ago`;
}

function formatRuntime(seconds: number) {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return remaining ? `${minutes}m ${remaining}s` : `${minutes}m`;
}

function formatUsdg(value: number) {
  return (value / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 6 });
}
