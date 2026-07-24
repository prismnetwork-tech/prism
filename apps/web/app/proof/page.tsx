import type { Metadata } from "next";
import { ProofFeed } from "@/components/proof-feed";

export const metadata: Metadata = {
  title: "Receipts",
  description: "Onchain settlement receipts for GPU leases on Prism Network.",
  alternates: { canonical: "/proof" },
};

export default function ProofPage() {
  return <ProofFeed />;
}
