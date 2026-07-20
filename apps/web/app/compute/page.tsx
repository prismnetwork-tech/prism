import type { Metadata } from "next";
import { ComputeWorkspace } from "@/components/compute-workspace";

export const metadata: Metadata = {
  title: "GPU compute",
  description: "Launch NVIDIA L40S workspaces with per-second USDG billing and onchain settlement.",
  alternates: { canonical: "/compute" },
};

export default function ComputePage() {
  return <ComputeWorkspace />;
}
