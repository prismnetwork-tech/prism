export type PublicActivityItem = {
  lease_id: number;
  state: string;
  node_prefix: string;
  gpu_model: string;
  duration_seconds: number;
  cost_base_units: number;
  settled: boolean;
  updated_at: string;
};

export type PublicActivityFeed = {
  generated_at: string;
  activity: PublicActivityItem[];
};

export function isPublicActivityFeed(value: unknown): value is PublicActivityFeed {
  if (!value || typeof value !== "object") return false;
  const feed = value as Partial<PublicActivityFeed>;
  return typeof feed.generated_at === "string"
    && !Number.isNaN(Date.parse(feed.generated_at))
    && Array.isArray(feed.activity)
    && feed.activity.length <= 200
    && feed.activity.every(isPublicActivityItem);
}

function isPublicActivityItem(value: unknown): value is PublicActivityItem {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<PublicActivityItem>;
  return isSafeInt(item.lease_id, 0)
    && isBoundedText(item.state, 1, 32)
    && typeof item.node_prefix === "string" && /^0x[0-9a-f]{2,64}$/i.test(item.node_prefix)
    && isBoundedText(item.gpu_model, 1, 64)
    && isSafeInt(item.duration_seconds, 0)
    && item.duration_seconds <= 21_600
    && isSafeInt(item.cost_base_units, 0)
    && item.cost_base_units <= 50_000_000
    && typeof item.settled === "boolean"
    && typeof item.updated_at === "string" && !Number.isNaN(Date.parse(item.updated_at));
}

function isSafeInt(value: unknown, minimum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum;
}

function isBoundedText(value: unknown, minimum: number, maximum: number): value is string {
  return typeof value === "string" && value.length >= minimum && value.length <= maximum;
}
