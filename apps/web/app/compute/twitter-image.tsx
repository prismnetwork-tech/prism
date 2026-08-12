import { ogContentType, ogSize, renderOgImage } from "@/lib/og-image";

export const size = ogSize;
export const contentType = ogContentType;
export const alt = "Prism GPU compute";

export default function Image() {
  return renderOgImage({
    eyebrow: "GPU compute",
    title: "Launch a workspace in minutes.",
    tag: "NVIDIA L40S · Temporary SSH",
  });
}
