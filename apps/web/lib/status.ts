export type Incident = {
  /** ISO date the incident started. */
  started: string;
  /** ISO date service was restored, or null while it is still open. */
  resolved: string | null;
  title: string;
  /** What a customer would have seen. */
  effect: string;
  /** What was actually wrong, in plain language. */
  cause: string;
  /** What changed so it does not happen again. */
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
      "Lease numbering restarted when the settlement contract was replaced, so new leases collided with the numbers of older ones. The network rejected its own confirmations as mismatched.",
    fix: "Leases are now identified by the contract that issued them as well as by number, so numbering from a new contract cannot collide with the old record.",
  },
];

export type Capacity = {
  offers: number;
  gpuModels: string[];
};

export type LatestSettlement = {
  observedAt: string;
  gpuModel: string;
  transactionHash: string;
};

export function summarize(capacity: Capacity | null, latest: LatestSettlement | null) {
  if (!capacity) return "Live capacity could not be read just now.";
  if (capacity.offers === 0) {
    return "No capacity is available to rent at the moment.";
  }
  const classes = capacity.gpuModels.length;
  const machines = `${capacity.offers} ${capacity.offers === 1 ? "machine is" : "machines are"}`;
  const kinds = `${classes} GPU ${classes === 1 ? "class" : "classes"}`;
  const settled = latest ? " The most recent lease settled onchain." : "";
  return `${machines} available to rent across ${kinds}.${settled}`;
}

/// Time since an instant, in the coarsest unit that still says something.
export function since(iso: string, now: number) {
  const elapsed = Math.max(0, now - Date.parse(iso));
  const minutes = Math.floor(elapsed / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}
