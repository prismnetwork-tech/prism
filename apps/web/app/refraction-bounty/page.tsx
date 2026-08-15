import type { Metadata } from "next";
import { Refraction } from "@/components/refraction";
import "./refraction-bounty.css";

export const metadata: Metadata = {
  title: "Refraction",
  description:
    "Four questions about how Prism Network works. The first three people to answer them take 3,000,000, 2,000,000 and 1,000,000 PRISM from a contract that pays out by itself.",
  alternates: { canonical: "/refraction-bounty" },
};

export default function RefractionPage() {
  return <Refraction />;
}
