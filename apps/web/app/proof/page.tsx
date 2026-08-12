import type { Metadata } from "next";
import { ProofFeed } from "@/components/proof-feed";

export const metadata: Metadata = {
  title: "Receipts",
  description: "Every settled GPU lease on Prism leaves an onchain receipt: the GPU, the runtime, and the USDG charged. Public feed, updated as leases finalize.",
  alternates: { canonical: "/proof" },
};

export default function ProofPage() {
  return <ProofFeed />;
}
