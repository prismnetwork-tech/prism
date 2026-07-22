// End-to-end agent flow against a live Prism deployment.
//   PRISM_AGENT_KEY=0x<privkey> PRISM_ESCROW=0x<escrow> node example.mjs
// Set PRISM_RUN_LEASE=1 to actually lease + run (needs USDG + gas); otherwise it
// stops after quoting so you can validate auth without spending.
import { DEFAULT_IMAGE, PrismAgent } from "./prism.mjs";

const agent = new PrismAgent({
  privateKey: process.env.PRISM_AGENT_KEY,
  escrow: process.env.PRISM_ESCROW,
  apiBase: process.env.PRISM_API_BASE ?? "https://prismnetwork.tech",
});

console.log("agent wallet:", agent.address);
const session = await agent.authenticate();
console.log("authenticated:", session.subject, "expires in", session.expiresIn, "s");

const offers = await agent.offers();
console.log(`offers online: ${offers.length}`, offers.map((o) => `${o.gpu.model} @ ${o.rate_per_second}/s`));
if (offers.length === 0) {
  console.log("no GPUs online right now. Try again shortly.");
  process.exit(0);
}

const quote = await agent.quote({ image: DEFAULT_IMAGE, durationSeconds: 900, minVramMib: 16000 });
console.log("quote:", { quote_id: quote.quote_id, node: quote.node_id.slice(0, 12), deposit: quote.maximum_escrow });

if (process.env.PRISM_RUN_LEASE !== "1") {
  console.log("\nauth + quote OK. Set PRISM_RUN_LEASE=1 to lease + run (needs USDG + gas).");
  process.exit(0);
}

console.log("leasing + provisioning (a few minutes)...");
const lease = await agent.lease({ image: DEFAULT_IMAGE, durationSeconds: 900, minVramMib: 16000 });
console.log("leased:", lease.leaseId, `${lease.access.ssh_host}:${lease.access.ssh_port}`);

const out = await agent.run(lease, "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader");
console.log(`exit ${out.code}:`, out.stdout || out.stderr);
agent.endLease(lease);
