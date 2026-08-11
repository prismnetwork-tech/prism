// lease a GPU for a given duration, print "LEASE <id>" on success or "FAIL <reason>"
import { DEFAULT_IMAGE, PrismAgent } from "./prism.mjs";
const dur = Number(process.argv[2] || 180);
const agent = new PrismAgent({ privateKey: process.env.PRISM_AGENT_KEY, escrow: process.env.PRISM_ESCROW, apiBase: "https://prismnetwork.tech" });
try {
  const lease = await agent.lease({ image: DEFAULT_IMAGE, durationSeconds: dur, minVramMib: 16000 });
  console.log("LEASE", lease.leaseId, lease.access.ssh_host + ":" + lease.access.ssh_port);
  agent.endLease(lease);
} catch (e) {
  console.log("FAIL", (e.code || e.message || String(e)).toString().slice(0, 60));
  process.exit(1);
}
