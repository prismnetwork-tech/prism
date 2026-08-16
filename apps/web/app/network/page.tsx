import type { Metadata } from "next";
import { NetworkMetrics } from "@/components/network-metrics";

export const metadata: Metadata = {
  title: "Network",
  description:
    "What Prism Network has settled and what it can rent right now: GPU hours served, USDG charged and paid to suppliers, refunds, and live capacity by GPU.",
  alternates: { canonical: "/network" },
};

export default function NetworkPage() {
  return <NetworkMetrics />;
}
