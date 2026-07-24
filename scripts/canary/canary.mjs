// Capped mainnet canary: an agent funds a short GPU lease, verifies nvidia-smi over
// SSH, and prints the on-chain funding tx. Duration and spend are hard-capped, and
// a funded lease is always reported by id so it is never silently forgotten.
//
//   PRISM_AGENT_KEY=0x<funded agent wallet> \
//   PRISM_ESCROW=0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD \
//   node canary.mjs
//
// Tunables (all optional): CANARY_DURATION=600  CANARY_MAX_USDG=0.5
//   CANARY_MIN_VRAM=16000  CANARY_NODE=0x<nodeId>
// Spends real USDG on mainnet. Pre-production and unaudited.
import { DEFAULT_IMAGE, PrismAgent } from "@prismnetwork/agent-sdk";

const DURATION = int(process.env.CANARY_DURATION, 600);
const MAX_USDG = num(process.env.CANARY_MAX_USDG, 0.5);
const MIN_VRAM = int(process.env.CANARY_MIN_VRAM, 16000);
const NODE = process.env.CANARY_NODE || null;
const TX = "https://robinhoodchain.blockscout.com/tx/";

if (DURATION > 3600) abort("duration is capped at 1 hour");
if (MAX_USDG > 5) abort("spend is capped at 5 USDG");

const agent = new PrismAgent({ privateKey: env("PRISM_AGENT_KEY"), escrow: env("PRISM_ESCROW") });
const capMicros = Math.round(MAX_USDG * 1e6);

const { subject } = await agent.authenticate();
log(`authenticated ${subject} (${agent.address})`);

const { usdg, eth } = await agent.balances();
log(`balance ${Number(usdg) / 1e6} USDG · ${Number(eth) / 1e18} ETH gas`);
if (BigInt(usdg) < BigInt(capMicros)) abort(`USDG below the ${MAX_USDG} cap; top up ${agent.address}`);
if (BigInt(eth) === 0n) abort(`no gas on ${agent.address}`);

const offers = await agent.offers();
if (!offers.length) abort("no GPU offers online");
log(`${offers.length} offer(s): ${offers.map((o) => o.gpu.model).join(", ")}`);

if (process.env.CANARY_CONFIRM !== "1") {
  log("\npreflight OK. Set CANARY_CONFIRM=1 to fund the lease (spends USDG + gas).");
  process.exit(0);
}

let lease;
let failure;
try {
  log(`leasing ${MIN_VRAM} MiB for ${DURATION}s (cap ${MAX_USDG} USDG)...`);
  lease = await agent.lease({
    image: DEFAULT_IMAGE,
    durationSeconds: DURATION,
    minVramMib: MIN_VRAM,
    preferredNodeId: NODE,
    maxDeposit: capMicros,
  });
  log(`lease ${lease.leaseId} funded on-chain: ${TX}${lease.fundingHash}`);
  log(`access ${lease.access.ssh_host}:${lease.access.ssh_port}`);

  const smi = await agent.run(
    lease,
    "nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader",
  );
  if (smi.code !== 0) throw new Error(`nvidia-smi exited ${smi.code}: ${smi.stderr || smi.stdout}`);
  log(`GPU verified: ${smi.stdout}`);
} catch (err) {
  failure = err;
} finally {
  if (lease) agent.endLease(lease);
}

if (failure) {
  if (lease) {
    log(`lease ${lease.leaseId} was funded (${TX}${lease.fundingHash}); it settles on-chain when its window ends`);
  }
  abort(failure.message);
}

log("");
log("canary OK.");
log(`funding tx: ${TX}${lease.fundingHash}`);
log(`lease id:   ${lease.leaseId}`);
log("settlement (SettlementProposed, receiptHash) is proposed on-chain after the lease window;");
log("finalize() unlocks 24h later (DISPUTE_WINDOW), then the receipt publishes to /proof.");

function env(name) {
  const v = process.env[name];
  if (!v) abort(`missing ${name}`);
  return v;
}
function int(v, d) {
  return v == null ? d : parseInt(v, 10);
}
function num(v, d) {
  return v == null ? d : Number(v);
}
function log(...a) {
  console.log(...a);
}
function abort(msg) {
  console.error(`canary aborted: ${msg}`);
  process.exit(1);
}
