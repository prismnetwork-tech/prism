import { ogContentType, ogSize, renderOgImage } from "@/lib/og-image";

export const size = ogSize;
export const contentType = ogContentType;
export const alt = "Prism pricing";

export default function Image() {
  return renderOgImage({
    eyebrow: "Pricing",
    title: "L40S compute at \$0.80 per GPU hour.",
    tag: "Per-second billing · USDG",
  });
}
