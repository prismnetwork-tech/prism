import type { MetadataRoute } from "next";
import { docsUrl, siteUrl } from "@/lib/site";

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
    {
      url: docsUrl.href,
      changeFrequency: "weekly",
      priority: 0.8,
    },
    {
      url: new URL("/privacy", siteUrl).href,
      changeFrequency: "yearly",
      priority: 0.3,
    },
    {
      url: new URL("/terms", siteUrl).href,
      changeFrequency: "yearly",
      priority: 0.3,
    },
    {
      url: new URL("/about", siteUrl).href,
      changeFrequency: "monthly",
      priority: 0.5,
    },
    {
      url: new URL("/pricing", siteUrl).href,
      changeFrequency: "weekly",
      priority: 0.7,
    },
    {
      url: new URL("/security", siteUrl).href,
      changeFrequency: "monthly",
      priority: 0.5,
    },
    {
      url: new URL("/contact", siteUrl).href,
      changeFrequency: "monthly",
      priority: 0.4,
    },
  ];
}
