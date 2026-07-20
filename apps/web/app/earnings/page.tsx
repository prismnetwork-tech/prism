import type { Metadata } from "next";
import { Earnings } from "@/components/earnings";

export const metadata: Metadata = {
  title: "Provider earnings",
  description: "Review finalized provider earnings and settlement records.",
  robots: { index: false, follow: false },
};

export default function EarningsPage() {
  return <Earnings />;
}
