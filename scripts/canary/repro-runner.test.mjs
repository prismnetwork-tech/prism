import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("review reaches the MCP boundary after all runtime declarations initialize", () => {
  const directory = mkdtempSync(join(tmpdir(), "prism-repro-runner-"));
  try {
    const preload = "data:text/javascript," + encodeURIComponent(
      "globalThis.fetch=async()=>new Response('unavailable',{status:503,headers:{'content-type':'text/plain'}})",
    );
    const result = spawnSync(process.execPath, ["--import", preload, "repro.mjs", "--review"], {
      cwd: dirname(fileURLToPath(import.meta.url)),
      encoding: "utf8",
      env: {
        ...process.env,
        PRISM_AGENT_KEY: `0x${"11".repeat(32)}`,
        PRISM_RPC_URL: "https://rpc.invalid",
        PRISM_API_BASE: "https://prism.invalid",
        REPRO_STATE_FILE: join(directory, "state.json"),
      },
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /paid repro stopped \[mcp_unavailable\]/);
    assert.doesNotMatch(result.stderr, /Cannot access|before initialization|\[unexpected\]/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("refuses a second execution while another holds the state file", () => {
  const directory = mkdtempSync(join(tmpdir(), "prism-repro-lock-"));
  const statePath = join(directory, "state.json");
  try {
    writeFileSync(`${statePath}.lock`, JSON.stringify({ pid: 1 }), { mode: 0o600 });
    const result = spawnSync(process.execPath, ["repro.mjs", "--execute"], {
      cwd: dirname(fileURLToPath(import.meta.url)),
      encoding: "utf8",
      env: {
        ...process.env,
        PRISM_AGENT_KEY: `0x${"11".repeat(32)}`,
        PRISM_RPC_URL: "https://rpc.invalid",
        PRISM_API_BASE: "https://prism.invalid",
        REPRO_STATE_FILE: statePath,
      },
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /paid repro stopped \[run_locked\]/);
    // The blocked run must leave the holder's lock in place.
    assert.ok(existsSync(`${statePath}.lock`));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("releases the run lock when an execution stops early", () => {
  const directory = mkdtempSync(join(tmpdir(), "prism-repro-unlock-"));
  const statePath = join(directory, "state.json");
  try {
    const result = spawnSync(process.execPath, ["repro.mjs", "--execute"], {
      cwd: dirname(fileURLToPath(import.meta.url)),
      encoding: "utf8",
      env: {
        ...process.env,
        PRISM_AGENT_KEY: `0x${"11".repeat(32)}`,
        PRISM_RPC_URL: "https://rpc.invalid",
        PRISM_API_BASE: "https://prism.invalid",
        REPRO_STATE_FILE: statePath,
      },
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /paid repro stopped \[state_missing\]/);
    assert.ok(!existsSync(`${statePath}.lock`));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
