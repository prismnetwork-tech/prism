import type { Metadata } from "next";
import { ProofFeed } from "@/components/proof-feed";

export const metadata: Metadata = {
  title: "Settlement proof",
  description: "Verify published GPU usage receipts against finalized Robinhood Chain settlement events.",
  alternates: { canonical: "/proof" },
};

export default function ProofPage() {
  return <ProofFeed />;
}
