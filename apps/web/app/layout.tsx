import type { Metadata, Viewport } from "next";
import { AppShell } from "@/components/app-shell";
import { Providers } from "@/components/providers";
import { StructuredData } from "@/components/structured-data";
import { siteUrl } from "@/lib/site";
import "./globals.css";
import "./landing.css";
import "./docs.css";
import "./legal.css";
import "./information.css";
import "./public-footer.css";

export const dynamic = "force-dynamic";

const description =
  "GPU compute your agents can rent with a wallet. Lease NVIDIA capacity, pay per second in USDG, and settle every lease onchain with a public receipt.";

export const metadata: Metadata = {
  metadataBase: siteUrl,
  title: {
    // The home page carries the brand and what it is. A bare wordmark tells a
    // search engine nothing, and this is the one title that has to earn a click
    // from someone who has never heard of us.
    default: "prism. · GPU compute your agents can rent with a wallet",
    template: "%s · prism.",
  },
  description,
  applicationName: "prism.",
  // Titles set per page flow into the social cards too, so a shared link shows
  // the page rather than the site name over and over.
  openGraph: {
    type: "website",
    siteName: "prism.",
    locale: "en_US",
    description,
  },
  twitter: {
    card: "summary_large_image",
    site: "@useprismnetwork",
    creator: "@useprismnetwork",
    description,
  },
  alternates: { canonical: "/" },
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true, "max-image-preview": "large", "max-snippet": -1 },
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
  colorScheme: "dark",
  themeColor: "#000000",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html data-theme="dark" lang="en" suppressHydrationWarning>
      <body>
        <StructuredData />
        <a className="skip-link" href="#main-content">Skip to content</a>
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
