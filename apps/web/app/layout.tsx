import type { Metadata, Viewport } from "next";
import { AppShell } from "@/components/app-shell";
import { Providers } from "@/components/providers";
import { siteUrl } from "@/lib/site";
import "./globals.css";
import "./landing.css";
import "./docs.css";
import "./legal.css";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  metadataBase: siteUrl,
  title: {
    default: "Prism Network",
    template: "%s · Prism Network",
  },
  description: "On-demand L40S compute with metered USDG settlement.",
  applicationName: "Prism Network",
  openGraph: {
    type: "website",
    siteName: "Prism Network",
    title: "Prism Network",
    description: "On-demand L40S compute with metered USDG settlement.",
  },
  twitter: {
    card: "summary",
    title: "Prism Network",
    description: "On-demand L40S compute with metered USDG settlement.",
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
