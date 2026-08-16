import type { MetadataRoute } from "next";
import { explainers } from "@/lib/explainers";
import { docsUrl, siteUrl } from "@/lib/site";

export default function sitemap(): MetadataRoute.Sitemap {
  // Crawlers use this to decide what is worth re-fetching, so it has to move
  // when the site does rather than sit at a hardcoded date.
  const lastModified = new Date();

  const routes: MetadataRoute.Sitemap = [
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
      url: new URL("/network", siteUrl).href,
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
      url: new URL("/refraction-bounty", siteUrl).href,
      changeFrequency: "hourly",
      priority: 0.8,
    },
    {
      url: new URL("/status", siteUrl).href,
      changeFrequency: "hourly",
      priority: 0.6,
    },
    {
      url: new URL("/contact", siteUrl).href,
      changeFrequency: "monthly",
      priority: 0.4,
    },
    {
      url: new URL("/learn", siteUrl).href,
      changeFrequency: "monthly",
      priority: 0.7,
    },
    ...explainers.map((entry) => ({
      url: new URL(`/learn/${entry.slug}`, siteUrl).href,
      changeFrequency: "monthly" as const,
      priority: 0.6,
    })),
    {
      url: new URL("/faq", siteUrl).href,
      changeFrequency: "monthly",
      priority: 0.7,
    },
    {
      url: new URL("/roadmap", siteUrl).href,
      changeFrequency: "monthly",
      priority: 0.5,
    },
    {
      url: new URL("/activity", siteUrl).href,
      changeFrequency: "daily",
      priority: 0.6,
    },
  ];

  return routes.map((entry) => ({ ...entry, lastModified }));
}
