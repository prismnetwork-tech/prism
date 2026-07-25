import { ogContentType, ogSize, renderOgImage } from "@/lib/og-image";

export const size = ogSize;
export const contentType = ogContentType;
export const alt = "Prism Network live activity";

export default function Image() {
  return renderOgImage({
    eyebrow: "Live network",
    title: "Watch the network work.",
    tag: "Robinhood Chain · USDG",
  });
}
