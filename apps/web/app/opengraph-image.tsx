import { ogContentType, ogSize, renderOgImage } from "@/lib/og-image";

export const size = ogSize;
export const contentType = ogContentType;
export const alt = "Prism Network";

export default function Image() {
  return renderOgImage({
    eyebrow: "Agent-native GPU compute",
    title: "GPU compute your agents can rent themselves.",
  });
}
