import type { Metadata } from "next";
import { ActivityFeed } from "@/components/activity-feed";

export const metadata: Metadata = {
  title: "Activity",
  description: "Recent GPU lease activity across the Prism network, updated live.",
  alternates: { canonical: "/activity" },
};

export default function ActivityPage() {
  return <ActivityFeed />;
}
