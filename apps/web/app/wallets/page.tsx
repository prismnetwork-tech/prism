import type { Metadata } from "next";
import { Wallets } from "@/components/wallets";

export const metadata: Metadata = {
  title: "Wallets",
  description: "Manage funding, operator, and payout wallets associated with your Prism account.",
  robots: { index: false, follow: false },
};

export default function WalletsPage() {
  return <Wallets />;
}
