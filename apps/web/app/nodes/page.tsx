import type { Metadata } from "next";
import { NodeFleet } from "@/components/node-fleet";

export const metadata: Metadata = {
  title: "GPU provider program",
  description: "Review provider requirements and manage registered NVIDIA infrastructure on Prism Network.",
  alternates: { canonical: "/nodes" },
};

export default function NodesPage() {
  return <NodeFleet />;
}
