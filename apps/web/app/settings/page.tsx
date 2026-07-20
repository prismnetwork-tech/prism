import type { Metadata } from "next";
import { Settings } from "@/components/settings";

export const metadata: Metadata = {
  title: "Account settings",
  description: "Manage Prism account recovery, session security, and risk controls.",
  robots: { index: false, follow: false },
};

export default function SettingsPage() {
  return <Settings />;
}
