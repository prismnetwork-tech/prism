import { describe, expect, it } from "vitest";
import {
  type StatusDay,
  formatUptime,
  headline,
  incidents,
  isStatusIndex,
  overall,
  strip,
  uptime,
} from "./status";

const component = (key: string, status: string) => ({
  key,
  name: key,
  group: "Renting",
  status,
  detail: "",
});

describe("overall", () => {
  it("takes the worst component rather than the average", () => {
    expect(overall([component("a", "operational"), component("b", "outage")] as never)).toBe("outage");
    expect(overall([component("a", "operational"), component("b", "degraded")] as never)).toBe("degraded");
  });

  it("treats a component it cannot read as worse than a healthy one", () => {
    expect(overall([component("a", "operational"), component("b", "unknown")] as never)).toBe("unknown");
  });

  it("is operational only when everything is", () => {
    expect(overall([component("a", "operational"), component("b", "operational")] as never)).toBe(
      "operational",
    );
  });
});

describe("headline", () => {
  it("says what the reader needs in the first three words", () => {
    expect(headline("operational", 4)).toBe("All services are online");
    expect(headline("outage", 4)).toBe("Some services are down");
    expect(headline("degraded", 4)).toBe("Some services are degraded");
    expect(headline("operational", 0)).toBe("Status is unavailable");
  });
});

describe("uptime", () => {
  const history: StatusDay[] = [
    { date: "2026-08-11", statuses: { leasing: "operational" } },
    { date: "2026-08-12", statuses: { leasing: "outage" } },
    { date: "2026-08-13", statuses: { leasing: "operational" } },
  ];

  it("counts only days that were measured", () => {
    expect(uptime(history, "leasing")).toBeCloseTo(66.66, 1);
    expect(uptime([{ date: "2026-08-13", statuses: { leasing: "unknown" } }], "leasing")).toBeNull();
    expect(uptime(history, "settlement")).toBeNull();
  });

  it("never rounds a bad day up to a clean hundred", () => {
    const almost = Array.from({ length: 1000 }, (_, index) => ({
      date: `2026-01-${index}`,
      statuses: { leasing: index === 0 ? "outage" : "operational" } as StatusDay["statuses"],
    }));
    expect(formatUptime(uptime(almost, "leasing"))).toBe("99.90% uptime");
    expect(formatUptime(null)).toBe("no data yet");
  });
});

describe("strip", () => {
  it("pads days before recording began as unknown, not as healthy", () => {
    const cells = strip(
      [{ date: "2026-08-14", statuses: { leasing: "operational" } }],
      "leasing",
      3,
      new Date("2026-08-14T12:00:00Z"),
    );
    expect(cells.map((day) => day.statuses.leasing)).toEqual(["unknown", "unknown", "operational"]);
  });

  it("always returns the requested width so a gap reads as a gap", () => {
    expect(strip([], "leasing", 90, new Date("2026-08-14T12:00:00Z"))).toHaveLength(90);
  });
});

describe("isStatusIndex", () => {
  it("rejects a payload that is not a status index", () => {
    expect(isStatusIndex(null)).toBe(false);
    expect(isStatusIndex({ generated_at: "nope", components: [], history: [] })).toBe(false);
    expect(isStatusIndex({ generated_at: "2026-08-14T00:00:00Z", components: [{}], history: [] })).toBe(
      false,
    );
  });

  it("accepts a well-formed one", () => {
    expect(
      isStatusIndex({
        generated_at: "2026-08-14T00:00:00Z",
        components: [component("leasing", "operational")],
        history: [{ date: "2026-08-14", statuses: { leasing: "operational" } }],
      }),
    ).toBe(true);
  });
});

describe("the incident record", () => {
  it("keeps every entry answerable to a customer", () => {
    for (const incident of incidents) {
      expect(Number.isNaN(Date.parse(incident.started))).toBe(false);
      if (incident.resolved !== null) {
        expect(Date.parse(incident.resolved)).toBeGreaterThan(Date.parse(incident.started));
      }
      expect(incident.effect.length).toBeGreaterThan(0);
      expect(incident.cause.length).toBeGreaterThan(0);
      expect(incident.fix.length).toBeGreaterThan(0);
    }
  });
});
