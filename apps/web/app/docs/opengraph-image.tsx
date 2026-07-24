import { ogContentType, ogSize, renderOgImage } from "@/lib/og-image";

export const size = ogSize;
export const contentType = ogContentType;
export const alt = "Prism Network developer documentation";

export default function Image() {
  return renderOgImage({
    eyebrow: "Developer reference",
    title: "Build against metered GPU infrastructure.",
    tag: "SDK · MCP · x402",
  });
}
