import type { Metadata } from "next";
import { NodeFleet } from "@/components/node-fleet";

export const metadata: Metadata = {
  title: "GPU provider program",
  description: "Supply NVIDIA GPU capacity to Prism and earn 90% of confirmed usage. Hardware requirements, bonding, and how registered infrastructure is managed.",
  alternates: { canonical: "/nodes" },
};

export default function NodesPage() {
  return <NodeFleet />;
}
