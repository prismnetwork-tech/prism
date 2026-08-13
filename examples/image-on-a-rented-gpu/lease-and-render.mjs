// Lease a Prism GPU with a wallet signature, generate an image on it, and bring
// the PNG home before the machine is destroyed.
//
//   PRISM_AGENT_KEY=0x<agent wallet private key> \
//   PRISM_ESCROW=0x62C042265991bEa17B07229322A01850974626dA \
//   PRISM_IMAGE=<digest-pinned CUDA + PyTorch image, repo@sha256:...> \
//   node lease-and-render.mjs "a prism splitting light"
//
// PRISM_IMAGE must be an immutable digest reference; Prism rejects plain tags.
// Resolve one, e.g.:
//   docker buildx imagetools inspect pytorch/pytorch:2.4.0-cuda12.1-cudnn9-runtime
// The wallet needs USDG and native Robinhood-Chain gas. Prism is pre-production
// and unaudited.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PrismAgent } from "@prismnetwork/agent-sdk";

const here = dirname(fileURLToPath(import.meta.url));
const renderScript = readFileSync(join(here, "render.py")).toString("base64");
const prompt = process.argv[2] ?? "a glass prism splitting light on a black desk, studio photograph";
const output = join(here, "rendered.png");

const agent = new PrismAgent({
  privateKey: requireEnv("PRISM_AGENT_KEY"),
  escrow: requireEnv("PRISM_ESCROW"),
});
const image = requireEnv("PRISM_IMAGE");

await agent.authenticate();

console.log("leasing a GPU (provisioning takes a few minutes)...");
const lease = await agent.lease({ image, durationSeconds: 1200, minVramMib: 16000 });
console.log(`leased ${lease.leaseId} on ${lease.access.ssh_host}, funded in ${lease.fundingHash}`);

const remote = [
  `printf %s ${renderScript} | base64 -d > /tmp/render.py`,
  // Pinned, like the image digest above it. An open upper bound means the
  // example installs whatever released this morning, and diffusers 0.36 needs
  // a newer torch than this image ships, so it fails on import after the
  // renter has already paid for the machine.
  "python -m pip install --quiet 'diffusers==0.31.0' transformers accelerate safetensors",
  `PRISM_PROMPT=${shellQuote(prompt)} python /tmp/render.py`,
].join(" && ");

console.log(`rendering "${prompt}"...`);
const result = await agent.run(lease, remote, { timeoutMs: 1_500_000 });

const encoded = result.stdout.split("\n").find((line) => line.startsWith("PRISM_IMAGE_BASE64:"));
for (const line of result.stdout.split("\n")) {
  if (line && !line.startsWith("PRISM_IMAGE_BASE64:")) console.log(`  ${line}`);
}

agent.endLease(lease);

if (result.code !== 0 || !encoded) {
  console.error(`\nrender failed (exit ${result.code})\n${result.stderr}`);
  process.exit(1);
}

writeFileSync(output, Buffer.from(encoded.slice("PRISM_IMAGE_BASE64:".length), "base64"));
console.log(`\nwrote ${output}`);
console.log("lease released. Settlement and a public receipt follow on chain.");

function shellQuote(value) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`missing ${name}: see the header of this file for the required environment.`);
    process.exit(1);
  }
  return value;
}
