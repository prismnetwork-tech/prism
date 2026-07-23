// Prism agent quickstart: authenticate with a wallet, lease a GPU, run a command,
// and read the metered result — no browser, no dashboard.
//
//   PRISM_AGENT_KEY=0x<agent wallet private key> \
//   PRISM_ESCROW=0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD \
//   node quickstart.mjs
//
// The wallet needs USDG and native Robinhood-Chain gas. Set PRISM_RUN_LEASE=1 to
// actually lease and run (spends funds); otherwise this stops after listing GPUs.
// Prism is pre-production and unaudited — do not use funds or data you cannot lose.
import { DEFAULT_IMAGE, PrismAgent } from "@prism-network/agent-sdk";

const agent = new PrismAgent({
  privateKey: requireEnv("PRISM_AGENT_KEY"),
  escrow: requireEnv("PRISM_ESCROW"),
});

const session = await agent.authenticate();
console.log("authenticated as", session.subject);

const offers = await agent.offers();
if (offers.length === 0) {
  console.log("no GPUs online right now — try again shortly.");
  process.exit(0);
}
console.log(`${offers.length} offer(s) online:`, offers.map((offer) => offer.gpu.model).join(", "));

if (process.env.PRISM_RUN_LEASE !== "1") {
  console.log("\nauth OK. Set PRISM_RUN_LEASE=1 to lease + run (spends USDG + gas).");
  process.exit(0);
}

console.log("leasing a GPU (provisioning takes a few minutes)...");
const lease = await agent.lease({ image: DEFAULT_IMAGE, durationSeconds: 900, minVramMib: 16000 });
console.log("leased", lease.leaseId, "at", `${lease.access.ssh_host}:${lease.access.ssh_port}`);

const result = await agent.run(lease, "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader");
console.log(`\nremote output (exit ${result.code}):\n${result.stdout || result.stderr}`);

agent.endLease(lease);
console.log("lease released. Settlement and a public receipt follow on chain.");

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`missing ${name} — see the header of this file for the required environment.`);
    process.exit(1);
  }
  return value;
}
