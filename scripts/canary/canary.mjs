// Capped mainnet canary: an agent funds a short GPU lease, verifies nvidia-smi over
// SSH, and prints the on-chain funding tx. Duration and spend are hard-capped, and
// a funded lease is always reported by id so it is never silently forgotten.
//
//   PRISM_AGENT_KEY=0x<funded agent wallet> \
//   PRISM_ESCROW=0x62C042265991bEa17B07229322A01850974626dA \
//   node canary.mjs
//
// Tunables (all optional): CANARY_DURATION=600  CANARY_MAX_USDG=0.5
//   CANARY_MIN_VRAM=16000  CANARY_NODE=0x<nodeId>
// Spends real USDG on mainnet. Pre-production and unaudited.
import { readCanaryConfig } from "./config.mjs";

let config;
try {
  config = readCanaryConfig();
} catch (err) {
  abort(err.message);
}

const {
  duration: DURATION,
  maxUsdg: MAX_USDG,
  minVram: MIN_VRAM,
  node: NODE,
  image: IMAGE,
  capMicros,
} = config;
const TX = "https://robinhoodchain.blockscout.com/tx/";

if (process.argv.includes("--dry-run")) {
  log(`canary configuration OK: ${MIN_VRAM} MiB for ${DURATION}s, capped at ${MAX_USDG} USDG`);
  log("dry run complete: no wallet, network, or transaction used");
  process.exit(0);
}

const { DEFAULT_IMAGE, PrismAgent } = await import("@prismnetwork/agent-sdk");
const agent = new PrismAgent({ privateKey: env("PRISM_AGENT_KEY"), escrow: env("PRISM_ESCROW") });

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
    image: IMAGE || DEFAULT_IMAGE,
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
log("finalize() unlocks after DISPUTE_WINDOW (5 minutes on the deployed escrow), then the receipt publishes to /proof.");

function env(name) {
  const v = process.env[name];
  if (!v) abort(`missing ${name}`);
  return v;
}
function log(...a) {
  console.log(...a);
}
function abort(msg) {
  console.error(`canary aborted: ${msg}`);
  process.exit(1);
}
