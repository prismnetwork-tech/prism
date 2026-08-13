import type { Metadata } from "next";
import { Stake } from "@/components/stake";

export const metadata: Metadata = {
  title: "Stake",
  description: "Lock PRISM to reach GPU capacity priced below the published rate.",
  robots: { index: false, follow: false },
};

export default function StakePage() {
  return <Stake />;
}
