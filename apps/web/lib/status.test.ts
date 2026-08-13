import { describe, expect, it } from "vitest";
import { incidents, since, summarize } from "./status";

describe("since", () => {
  const now = Date.parse("2026-08-14T12:00:00Z");

  it("reports the coarsest unit that still says something", () => {
    expect(since("2026-08-14T11:59:40Z", now)).toBe("just now");
    expect(since("2026-08-14T11:59:00Z", now)).toBe("1 minute ago");
    expect(since("2026-08-14T11:00:00Z", now)).toBe("1 hour ago");
    expect(since("2026-08-13T12:00:00Z", now)).toBe("1 day ago");
    expect(since("2026-08-11T12:00:00Z", now)).toBe("3 days ago");
  });

  it("never reports a future reading as negative time", () => {
    expect(since("2026-08-14T12:05:00Z", now)).toBe("just now");
  });
});

describe("summarize", () => {
  it("separates having no capacity from failing to read it", () => {
    expect(summarize(null, null)).toMatch(/could not be read/);
    expect(summarize({ offers: 0, gpuModels: [] }, null)).toMatch(/No capacity/);
  });

  it("counts machines and classes", () => {
    expect(summarize({ offers: 1, gpuModels: ["L40S"] }, null)).toBe(
      "1 machine is available to rent across 1 GPU class.",
    );
    expect(summarize({ offers: 4, gpuModels: ["L40S", "RTX 6000Ada"] }, null)).toMatch(
      /4 machines are available to rent across 2 GPU classes\./,
    );
  });
});

describe("the incident record", () => {
  it("keeps every entry answerable to a customer", () => {
    for (const incident of incidents) {
      expect(Number.isNaN(Date.parse(incident.started))).toBe(false);
      if (incident.resolved !== null) {
        expect(Date.parse(incident.resolved)).toBeGreaterThan(Date.parse(incident.started));
      }
      // An entry without all three is a note to ourselves, not a disclosure.
      expect(incident.effect.length).toBeGreaterThan(0);
      expect(incident.cause.length).toBeGreaterThan(0);
      expect(incident.fix.length).toBeGreaterThan(0);
    }
  });
});
