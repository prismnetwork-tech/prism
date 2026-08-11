import type { Metadata } from "next";
import { Vault } from "@/components/vault";

export const metadata: Metadata = {
  title: "Vault",
  description: "Store cards, identity documents and credentials encrypted under a key derived on your device.",
  robots: { index: false, follow: false },
};

export default function VaultPage() {
  return <Vault />;
}
