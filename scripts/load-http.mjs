import { performance } from "node:perf_hooks";

const [url, totalValue = "1000", concurrencyValue = "25", p95LimitValue = "1000"] = process.argv.slice(2);
const total = Number(totalValue);
const concurrency = Number(concurrencyValue);
const p95Limit = Number(p95LimitValue);

if (!url || !Number.isSafeInteger(total) || total < 1 || !Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > total || !Number.isFinite(p95Limit) || p95Limit <= 0) {
  console.error("usage: node scripts/load-http.mjs <url> [requests] [concurrency] [p95-limit-ms]");
  process.exit(64);
}

const latencies = [];
let cursor = 0;
let failures = 0;

async function worker() {
  while (cursor < total) {
    cursor += 1;
    const started = performance.now();
    try {
      const response = await fetch(url, {
        cache: "no-store",
        signal: AbortSignal.timeout(5_000),
      });
      if (!response.ok) failures += 1;
      await response.arrayBuffer();
    } catch {
      failures += 1;
    } finally {
      latencies.push(performance.now() - started);
    }
  }
}

const started = performance.now();
await Promise.all(Array.from({ length: concurrency }, () => worker()));
const elapsed = performance.now() - started;
latencies.sort((left, right) => left - right);
const p95 = latencies[Math.max(0, Math.ceil(latencies.length * 0.95) - 1)] ?? Infinity;
const throughput = total / (elapsed / 1_000);

console.log(JSON.stringify({
  requests: total,
  concurrency,
  failures,
  p95_ms: Number(p95.toFixed(2)),
  requests_per_second: Number(throughput.toFixed(2)),
}));

if (failures > 0 || p95 > p95Limit) process.exit(1);
