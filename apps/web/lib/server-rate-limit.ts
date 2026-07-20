import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createClient, type RedisClientType } from "redis";

type Bucket = { count: number; resetAt: number };
type RateLimit = { allowed: boolean; available: boolean; retryAfter: number };

const buckets = new Map<string, Bucket>();
const oneTimeValues = new Map<string, number>();
let clientPromise: Promise<RedisClientType> | undefined;

export async function takeRateLimit(
  scope: string,
  subject: string,
  limit: number,
  windowMs: number,
  now = Date.now(),
): Promise<RateLimit> {
  const key = `prism:rate:${scope}:${createHash("sha256").update(subject).digest("hex")}`;
  const url = process.env.PRISM_REDIS_URL;
  if (!url) {
    if (process.env.NODE_ENV === "production" && process.env.PRISM_ALLOW_DEVELOPMENT_RATE_LIMIT !== "1") {
      return { allowed: false, available: false, retryAfter: 1 };
    }
    return takeMemoryRateLimit(key, limit, windowMs, now);
  }
  try {
    const client = await redisClient(url);
    const result = await client.eval(
      "local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); end; return {count, redis.call('PTTL', KEYS[1])};",
      { keys: [key], arguments: [String(windowMs)] },
    );
    if (!Array.isArray(result) || result.length !== 2) throw new Error("invalid rate-limit response");
    const count = Number(result[0]);
    const ttl = Number(result[1]);
    if (!Number.isSafeInteger(count) || !Number.isSafeInteger(ttl)) throw new Error("invalid rate-limit response");
    return {
      allowed: count <= limit,
      available: true,
      retryAfter: Math.max(1, Math.ceil(ttl / 1_000)),
    };
  } catch (error) {
    logRedisError(error);
    return { allowed: false, available: false, retryAfter: 1 };
  }
}

export async function registerOneTime(scope: string, value: string, ttlMs: number) {
  const key = oneTimeKey(scope, value);
  const url = process.env.PRISM_REDIS_URL;
  if (!url) {
    if (process.env.NODE_ENV === "production" && process.env.PRISM_ALLOW_DEVELOPMENT_RATE_LIMIT !== "1") {
      return { available: false, stored: false };
    }
    const now = Date.now();
    for (const [current, expiresAt] of oneTimeValues) {
      if (expiresAt <= now) oneTimeValues.delete(current);
    }
    if (oneTimeValues.has(key)) return { available: true, stored: false };
    oneTimeValues.set(key, now + ttlMs);
    return { available: true, stored: true };
  }
  try {
    const client = await redisClient(url);
    const result = await client.set(key, "1", { NX: true, PX: ttlMs });
    return { available: true, stored: result === "OK" };
  } catch (error) {
    logRedisError(error);
    return { available: false, stored: false };
  }
}

export async function consumeOneTime(scope: string, value: string) {
  const key = oneTimeKey(scope, value);
  const url = process.env.PRISM_REDIS_URL;
  if (!url) {
    if (process.env.NODE_ENV === "production" && process.env.PRISM_ALLOW_DEVELOPMENT_RATE_LIMIT !== "1") {
      return { available: false, consumed: false };
    }
    const expiresAt = oneTimeValues.get(key);
    oneTimeValues.delete(key);
    return { available: true, consumed: typeof expiresAt === "number" && expiresAt > Date.now() };
  }
  try {
    const client = await redisClient(url);
    const result = await client.eval(
      "if redis.call('GET', KEYS[1]) then redis.call('DEL', KEYS[1]); return 1; end; return 0;",
      { keys: [key], arguments: [] },
    );
    return { available: true, consumed: Number(result) === 1 };
  } catch (error) {
    logRedisError(error);
    return { available: false, consumed: false };
  }
}

async function redisClient(url: string) {
  if (!isAllowedRedisUrl(url)) throw new Error("insecure Redis connection");
  clientPromise ??= (async () => {
    const caPath = process.env.PRISM_REDIS_CA_FILE;
    const client = createClient({
      url,
      socket: caPath ? { tls: true, ca: readFileSync(caPath, "utf8") } : undefined,
    }) as RedisClientType;
    client.on("error", () => undefined);
    await client.connect();
    return client;
  })();
  try {
    return await clientPromise;
  } catch (error) {
    clientPromise = undefined;
    throw error;
  }
}

export function isAllowedRedisUrl(value: string) {
  try {
    const url = new URL(value);
    if (url.protocol === "rediss:") return true;
    return url.protocol === "redis:"
      && /^red-[a-z0-9]+$/.test(url.hostname)
      && url.port === "6379"
      && !url.username
      && !url.password;
  } catch {
    return false;
  }
}

function logRedisError(error: unknown) {
  const code = error && typeof error === "object" && "code" in error && typeof error.code === "string"
    ? error.code.slice(0, 64)
    : "unknown";
  console.error(JSON.stringify({ event: "redis_unavailable", code }));
}

function takeMemoryRateLimit(key: string, limit: number, windowMs: number, now: number): RateLimit {
  if (buckets.size >= 5_000) {
    for (const [bucketKey, bucket] of buckets) {
      if (bucket.resetAt <= now) buckets.delete(bucketKey);
    }
    while (buckets.size >= 5_000) {
      const oldest = buckets.keys().next().value;
      if (typeof oldest !== "string") break;
      buckets.delete(oldest);
    }
  }
  const current = buckets.get(key);
  const bucket = !current || current.resetAt <= now ? { count: 0, resetAt: now + windowMs } : current;
  bucket.count += 1;
  buckets.set(key, bucket);
  return {
    allowed: bucket.count <= limit,
    available: true,
    retryAfter: Math.max(1, Math.ceil((bucket.resetAt - now) / 1_000)),
  };
}

function oneTimeKey(scope: string, value: string) {
  return `prism:once:${scope}:${createHash("sha256").update(value).digest("hex")}`;
}

export function requestSubject(headers: Headers) {
  const name = process.env.PRISM_CLIENT_IP_HEADER?.toLowerCase();
  if (!name || !["cf-connecting-ip", "x-forwarded-for", "x-real-ip"].includes(name)) {
    return "unattributed";
  }
  const value = headers.get(name)?.split(",")[0]?.trim();
  return value ? value.slice(0, 64) : "unattributed";
}
