import type { MetadataRoute } from "next";
import { siteUrl } from "@/lib/site";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: siteUrl.href,
      changeFrequency: "weekly",
      priority: 1,
    },
    {
      url: new URL("/proof", siteUrl).href,
      changeFrequency: "daily",
      priority: 0.8,
    },
    {
      url: new URL("/compute", siteUrl).href,
      changeFrequency: "daily",
      priority: 0.7,
    },
    {
      url: new URL("/nodes", siteUrl).href,
      changeFrequency: "weekly",
      priority: 0.7,
    },
  ];
}
