import type { Metadata, Viewport } from "next";
import { AppShell } from "@/components/app-shell";
import { Providers } from "@/components/providers";
import { siteUrl } from "@/lib/site";
import "./globals.css";
import "./landing.css";
import "./docs.css";
import "./legal.css";
import "./information.css";
import "./public-footer.css";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  metadataBase: siteUrl,
  title: {
    default: "Prism Network",
    template: "%s · Prism Network",
  },
  description: "GPU compute autonomous agents can rent with a wallet. Lease NVIDIA L40S capacity, pay per second in USDG, settle every lease onchain.",
  applicationName: "Prism Network",
  openGraph: {
    type: "website",
    siteName: "Prism Network",
    title: "Prism Network",
    description: "GPU compute autonomous agents can rent with a wallet. Lease NVIDIA L40S capacity, pay per second in USDG, settle every lease onchain.",
  },
  twitter: {
    card: "summary_large_image",
    title: "Prism Network",
    description: "GPU compute autonomous agents can rent with a wallet. Lease NVIDIA L40S capacity, pay per second in USDG, settle every lease onchain.",
  },
  manifest: "/manifest.webmanifest",
  icons: {
    icon: [
      { url: "/favicon.ico" },
      { url: "/icons/favicon-16x16.png", sizes: "16x16", type: "image/png" },
      { url: "/icons/favicon-32x32.png", sizes: "32x32", type: "image/png" },
    ],
    apple: [{ url: "/apple-icon.png", sizes: "180x180", type: "image/png" }],
  },
};

export const viewport: Viewport = {
  colorScheme: "dark light",
  themeColor: "#000000",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html data-theme="dark" lang="en" suppressHydrationWarning>
      <body>
        <a className="skip-link" href="#main-content">Skip to content</a>
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
