import { ImageResponse } from "next/og";

export const ogSize = { width: 1200, height: 630 };
export const ogContentType = "image/png";

const CANVAS = "#000000";
const TEXT = "#f4f7ef";
const MUTED = "#8b9286";
const ACCENT = "#ccff00";
const BORDER = "#252a20";

type OgFields = { eyebrow: string; title: string; tag?: string };

export function renderOgImage({ eyebrow, title, tag = "Live · Robinhood Chain · USDG" }: OgFields) {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: CANVAS,
          color: TEXT,
          padding: "80px",
          fontFamily: "sans-serif",
        }}
      >
        <div
          style={{
            position: "absolute",
            top: "-260px",
            left: "50%",
            width: "900px",
            height: "600px",
            transform: "translateX(-50%)",
            background: `radial-gradient(circle, rgba(204,255,0,0.16), rgba(0,0,0,0))`,
          }}
        />
        <div style={{ display: "flex", alignItems: "center", gap: "18px" }}>
          <div style={{ width: "20px", height: "20px", borderRadius: "50%", background: ACCENT }} />
          <div style={{ fontSize: "42px", fontWeight: 600, letterSpacing: "-0.03em" }}>prism.</div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "24px", maxWidth: "1000px" }}>
          <div
            style={{
              fontSize: "24px",
              letterSpacing: "0.28em",
              textTransform: "uppercase",
              color: ACCENT,
            }}
          >
            {eyebrow}
          </div>
          <div style={{ fontSize: "68px", fontWeight: 600, lineHeight: 1.05, letterSpacing: "-0.02em" }}>
            {title}
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ fontSize: "26px", color: MUTED }}>prismnetwork.tech</div>
          <div
            style={{
              display: "flex",
              fontSize: "22px",
              color: TEXT,
              border: `1px solid ${BORDER}`,
              borderRadius: "999px",
              padding: "12px 26px",
            }}
          >
            {tag}
          </div>
        </div>
      </div>
    ),
    { ...ogSize },
  );
}
