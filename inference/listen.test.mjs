import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const server = fileURLToPath(new URL("./server.mjs", import.meta.url));

/// A bare environment, so nothing the operator happens to have exported can
/// carry one of these runs past the check it is meant to hit.
function boot(env) {
  const child = spawn(process.execPath, [server], {
    env: { PATH: process.env.PATH, ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let said = "";
  child.stderr.on("data", (chunk) => {
    said += chunk;
  });
  return new Promise((resolve) => child.on("exit", (code) => resolve({ code, said })));
}

test("a gateway asked to answer strangers refuses to start without a credential", async () => {
  const { code, said } = await boot({ INFERENCE_HOST: "0.0.0.0" });
  assert.equal(code, 1, "the gateway bound a public address instead of refusing");
  assert.match(said, /INFERENCE_HOST is 0\.0\.0\.0/);
  assert.match(said, /INFERENCE_TOKEN/, "the refusal has to name the variable that fixes it");
});

/// The address is settled before the wallet is, because a gateway that came up
/// on the wrong one has already been reachable by the time a later line of
/// config fails.
test("the address is checked before anything else the operator got wrong", async () => {
  const { said } = await boot({ INFERENCE_HOST: "0.0.0.0" });
  assert.doesNotMatch(said, /PRISM_AGENT_KEY/, "the wallet error masked the address error");

  const guarded = await boot({ INFERENCE_HOST: "0.0.0.0", INFERENCE_TOKEN: "t".repeat(32) });
  assert.equal(guarded.code, 1);
  assert.match(guarded.said, /PRISM_AGENT_KEY/, "the credential should have satisfied the address check");
});
