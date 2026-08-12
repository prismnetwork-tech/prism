import type { Metadata } from "next";
import { ActivityFeed } from "@/components/activity-feed";

export const metadata: Metadata = {
  title: "Activity",
  description: "Live GPU lease activity across the Prism network: capacity coming online, leases funded and settling, with renter identity left out of the feed.",
  alternates: { canonical: "/activity" },
};

export default function ActivityPage() {
  return <ActivityFeed />;
}
