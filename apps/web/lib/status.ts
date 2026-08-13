export type ComponentStatus = "operational" | "degraded" | "outage" | "unknown";

export type StatusComponent = {
  key: string;
  name: string;
  group: string;
  status: ComponentStatus;
  detail: string;
};

export type StatusDay = {
  date: string;
  statuses: Record<string, ComponentStatus>;
};

export type StatusIndex = {
  generated_at: string;
  components: StatusComponent[];
  history: StatusDay[];
};

const STATUSES: ComponentStatus[] = ["operational", "degraded", "outage", "unknown"];

// Worst wins, so one broken component cannot be averaged away by three healthy
// ones. "unknown" ranks above operational because a component we cannot read is
// not one we can vouch for.
const RANK: Record<ComponentStatus, number> = {
  operational: 0,
  unknown: 1,
  degraded: 2,
  outage: 3,
};

export const STATUS_LABEL: Record<ComponentStatus, string> = {
  operational: "Operational",
  degraded: "Degraded",
  outage: "Outage",
  unknown: "Unknown",
};

function isComponentStatus(value: unknown): value is ComponentStatus {
  return typeof value === "string" && (STATUSES as string[]).includes(value);
}

export function isStatusIndex(value: unknown): value is StatusIndex {
  if (typeof value !== "object" || value === null) return false;
  const index = value as Partial<StatusIndex>;
  if (typeof index.generated_at !== "string" || Number.isNaN(Date.parse(index.generated_at))) return false;
  if (!Array.isArray(index.components) || index.components.length > 32) return false;
  if (!Array.isArray(index.history) || index.history.length > 400) return false;
  return (
    index.components.every(
      (component) =>
        typeof component?.key === "string" &&
        component.key.length > 0 &&
        component.key.length <= 32 &&
        typeof component.name === "string" &&
        component.name.length <= 64 &&
        typeof component.group === "string" &&
        component.group.length <= 32 &&
        typeof component.detail === "string" &&
        component.detail.length <= 200 &&
        isComponentStatus(component.status),
    ) &&
    index.history.every(
      (day) =>
        typeof day?.date === "string" &&
        /^\d{4}-\d{2}-\d{2}$/.test(day.date) &&
        typeof day.statuses === "object" &&
        day.statuses !== null,
    )
  );
}

export function overall(components: StatusComponent[]): ComponentStatus {
  return components.reduce<ComponentStatus>(
    (worst, component) => (RANK[component.status] > RANK[worst] ? component.status : worst),
    "operational",
  );
}

export function headline(status: ComponentStatus, componentCount: number) {
  if (componentCount === 0) return "Status is unavailable";
  switch (status) {
    case "operational":
      return "All services are online";
    case "degraded":
      return "Some services are degraded";
    case "outage":
      return "Some services are down";
    default:
      return "Some services could not be checked";
  }
}

/// Uptime across the recorded window only. Days before recording began are not
/// counted as good ones.
export function uptime(history: StatusDay[], key: string) {
  const readings = history.map((day) => day.statuses[key]).filter(isComponentStatus);
  const measured = readings.filter((status) => status !== "unknown");
  if (measured.length === 0) return null;
  const good = measured.filter((status) => status === "operational").length;
  return (good / measured.length) * 100;
}

export function formatUptime(value: number | null) {
  if (value === null) return "no data yet";
  // Never round a bad day up to a clean 100%.
  const floored = Math.floor(value * 100) / 100;
  return `${floored.toFixed(2)}% uptime`;
}

/// One cell per day, oldest first, padded so the strip is always the same width
/// and the days before recording began read as unknown rather than as healthy.
export function strip(history: StatusDay[], key: string, days: number, today: Date): StatusDay[] {
  const byDate = new Map(history.map((day) => [day.date, day]));
  const cells: StatusDay[] = [];
  for (let offset = days - 1; offset >= 0; offset -= 1) {
    const date = new Date(today.getTime() - offset * 86_400_000).toISOString().slice(0, 10);
    cells.push(byDate.get(date) ?? { date, statuses: { [key]: "unknown" } });
  }
  return cells;
}

export type Incident = {
  started: string;
  resolved: string | null;
  title: string;
  effect: string;
  cause: string;
  fix: string;
};

/// Incidents are kept in source rather than a dashboard so that a change to the
/// record is reviewed like any other change, and so the history cannot be
/// quietly edited after the fact.
export const incidents: Incident[] = [
  {
    started: "2026-08-13T14:10:00Z",
    resolved: "2026-08-13T21:15:00Z",
    title: "Leases were funded but never started",
    effect:
      "Renters who funded a lease did not get a machine. Deposits were returned automatically, but the rental did not happen and the time was lost.",
    cause:
      "Lease numbering restarted when the settlement contract was replaced, so new leases collided with the numbers of older ones. The network rejected its own confirmations as belonging to a different lease.",
    fix: "A lease is now identified by the contract that issued it as well as by its number. A separate alarm now asks the chain, rather than our own records, whether anyone has paid and received nothing.",
  },
];
