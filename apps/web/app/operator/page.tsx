import type { Metadata } from "next";
import { OperatorConsole } from "@/components/operator-console";

export const metadata: Metadata = {
  title: "Operator controls",
  description: "Restricted administrative controls for Prism Network operations.",
  robots: { index: false, follow: false },
};

export default function OperatorPage() {
  return <OperatorConsole />;
}
