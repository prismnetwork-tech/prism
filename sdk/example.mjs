// End-to-end agent flow against a live Prism deployment.
//   PRISM_AGENT_KEY=0x<privkey> PRISM_ESCROW=0x<escrow> node sdk/example.mjs
// Set PRISM_RUN_LEASE=1 to actually fund + provision (costs USDG + gas); otherwise
// it stops after quoting so you can validate auth without spending.
import { generateKeyPairSync } from "node:crypto";
import { PrismAgent } from "./prism.mjs";

const OLLAMA = "docker.io/ollama/ollama@sha256:a61a8fd395dbb931cc8cb1b5da7a2510746575c87113fdc45b647ee59ef7f808";

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

const quote = await agent.quote({ image: OLLAMA, durationSeconds: 900, minVramMib: 45000 });
console.log("quote:", { quote_id: quote.quote_id, node: quote.node_id.slice(0, 12), deposit: quote.maximum_escrow });

if (process.env.PRISM_RUN_LEASE !== "1") {
  console.log("\nauth + quote OK. Set PRISM_RUN_LEASE=1 to fund + provision.");
  process.exit(0);
}

const { publicKey } = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "der" } });
const sshKey = `ssh-ed25519 ${Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from("ssh-ed25519"), Buffer.from([0, 0, 0, 32]), publicKey.subarray(-32)]).toString("base64")} agent`;

console.log("funding on-chain...");
const funded = await agent.fund(quote);
console.log("funded:", funded.hash);

const lease = await agent.confirm({ quoteId: quote.quote_id, transactionHash: funded.hash, sshAuthorizedKey: sshKey });
console.log("lease confirmed:", lease.lease_id);

const access = await agent.waitForAccess(lease.lease_id);
console.log("access:", access);
