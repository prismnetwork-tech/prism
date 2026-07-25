import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const mcpDir = resolve(root, "mcp");
const packageJson = readJson(resolve(mcpDir, "package.json"));
const serverJson = readJson(resolve(mcpDir, "server.json"));
const registryPackage = serverJson.packages?.find(({ registryType }) => registryType === "npm");

assert.equal(serverJson.name, packageJson.mcpName, "server name must match package mcpName");
assert.equal(serverJson.version, packageJson.version, "server and package versions must match");
assert.ok(registryPackage, "server.json must contain an npm package");
assert.equal(registryPackage.identifier, packageJson.name, "registry package name must match package name");
assert.equal(registryPackage.version, packageJson.version, "registry package version must match package version");
assert.equal(registryPackage.transport?.type, "stdio", "MCP package must use stdio transport");
assert.match(
  serverJson.$schema,
  /^https:\/\/static\.modelcontextprotocol\.io\/schemas\/[^/]+\/server\.schema\.json$/,
  "server.json must use the official schema",
);
assert.ok(serverJson.description.length <= 100, "registry description must not exceed 100 characters");

execFileSync(process.execPath, ["--check", resolve(mcpDir, "server.mjs")], { stdio: "inherit" });

const packed = JSON.parse(
  execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: mcpDir,
    encoding: "utf8",
  }),
);
assert.equal(packed.length, 1, "npm pack must produce one archive");
assert.equal(packed[0].name, packageJson.name);
assert.equal(packed[0].version, packageJson.version);
assert.deepEqual(
  packed[0].files.map(({ path }) => path).sort(),
  ["README.md", "package.json", "server.mjs"],
  "npm archive contents changed",
);

const bin = Object.values(packageJson.bin ?? {});
assert.deepEqual(bin, ["server.mjs"], "package must expose server.mjs as its only executable");
assert.equal(
  packed[0].files.find(({ path }) => path === bin[0])?.mode,
  0o755,
  "MCP executable must be executable in the npm archive",
);

console.log(`${packageJson.name}@${packageJson.version} package and registry metadata are valid`);

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}
