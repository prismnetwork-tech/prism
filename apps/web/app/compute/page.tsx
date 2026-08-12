import type { Metadata } from "next";
import { ComputeWorkspace } from "@/components/compute-workspace";

export const metadata: Metadata = {
  title: "GPU compute",
  description: "Launch an NVIDIA GPU workspace in minutes. Digest-pinned images, temporary SSH, per-second USDG billing, and onchain settlement when the lease ends.",
  alternates: { canonical: "/compute" },
};

export default function ComputePage() {
  return <ComputeWorkspace />;
}
