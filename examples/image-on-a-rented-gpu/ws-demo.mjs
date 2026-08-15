import { PrismAgent } from "../../sdk/prism.mjs";
const D = "\x1b[2m", G = "\x1b[1;32m", O = "\x1b[0m";
const say = async (m) => { console.log(`${D}# ${m}${O}`); await new Promise(r => setTimeout(r, 1400)); };
const step = async (m) => { console.log(`${G}$${O} ${m}`); await new Promise(r => setTimeout(r, 700)); };

const agent = new PrismAgent({ privateKey: process.env.PRISM_AGENT_KEY, escrow: process.env.PRISM_ESCROW });
await agent.authenticate();
await agent.workspace.unlock();
await say("A workspace key, derived from a wallet signature. Never sent to us.");

const ws = await agent.workspace.create(`demo-${Date.now()}`);
await step(`prism workspace create  ->  ${ws.workspace_id.slice(0, 8)}…`);

await say("Rent a GPU and leave something on it.");
const a = await agent.lease({ image: process.env.PRISM_IMAGE, durationSeconds: 900, minVramMib: 16000 });
await step(`lease ${a.leaseId} on ${a.access.ssh_host}`);
const marker = `trained on lease ${a.leaseId}`;
await agent.run(a, `mkdir -p /root/work && printf %s ${JSON.stringify(marker)} > /root/work/checkpoint.txt`);
console.log(`  wrote /root/work/checkpoint.txt: "${marker}"`);
const saved = await agent.workspace.save(a, ws.workspace_id, "/root/work");
await step(`prism workspace save  ->  version ${saved.version}, ${saved.snapshot.size_bytes} bytes sealed`);
agent.endLease(a);
await say("That machine is now gone.");

const b = await agent.lease({ image: process.env.PRISM_IMAGE, durationSeconds: 900, minVramMib: 16000 });
await step(`lease ${b.leaseId} on ${b.access.ssh_host}  (a different machine)`);
await agent.workspace.restore(b, ws.workspace_id, "/root/restored");
await step("prism workspace restore");
const out = await agent.run(b, "cat /root/restored/checkpoint.txt");
console.log(`  ${out.stdout.trim()}`);
if (!out.stdout.includes(marker)) throw new Error("mismatch");
agent.endLease(b);
await say("Same bytes, new machine.");
console.log(`\nWORKSPACE_KEY=${ws.workspace_id}`);
