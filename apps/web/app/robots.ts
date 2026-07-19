import type { MetadataRoute } from "next";
import { siteUrl } from "@/lib/site";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: ["/", "/proof", "/compute", "/nodes"],
      disallow: ["/api/", "/operator", "/settings", "/wallets", "/leases", "/earnings"],
    },
    sitemap: new URL("/sitemap.xml", siteUrl).href,
  };
}
