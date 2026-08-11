import { DEFAULT_IMAGE, PrismAgent } from "./prism.mjs";
const agent = new PrismAgent({ privateKey: process.env.PRISM_AGENT_KEY, escrow: process.env.PRISM_ESCROW, apiBase: "https://prismnetwork.tech" });
try {
  const q = await agent.quote({ image: DEFAULT_IMAGE, durationSeconds: 120, minVramMib: 16000 });
  console.log("QUOTE OK:", JSON.stringify(q));
} catch (e) {
  console.log("ERR status:", e.status, "code:", e.code, "msg:", e.message);
  console.log("details:", JSON.stringify(e.details ?? e.body ?? e.cause ?? null));
}
