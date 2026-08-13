import { describe, expect, it } from "vitest";
import { contentSecurityPolicy } from "./proxy";

describe("script policy and rendering mode", () => {
  // Removing force-dynamic once served prerendered HTML with no nonce on any
  // script. `strict-dynamic` makes the browser ignore `'self'`, so every
  // script was refused and the whole site stopped hydrating while still
  // returning 200. Nothing in the suite noticed, so pin the invariant.
  it("uses a nonce and strict-dynamic, which only works with per-request rendering", async () => {
    const policy = contentSecurityPolicy("abc123", false);

    expect(policy).toContain("'nonce-abc123'");
    expect(policy).toContain("'strict-dynamic'");

    // The root layout must therefore opt out of prerendering. If this ever
    // changes, the CSP has to change with it.
    const layout = await import("node:fs/promises").then((fs) =>
      fs.readFile(new URL("./app/layout.tsx", import.meta.url), "utf8"),
    );
    expect(layout).toMatch(/export const dynamic = "force-dynamic"/);
  });
});
