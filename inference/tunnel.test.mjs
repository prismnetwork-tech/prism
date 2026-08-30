import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { openTunnel } from "./tunnel.mjs";

const SSHD = "/usr/sbin/sshd";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

function reachable(port) {
  return new Promise((resolve) => {
    const probe = new Socket();
    const settle = (answer) => {
      probe.destroy();
      resolve(answer);
    };
    probe.setTimeout(200);
    probe.once("connect", () => settle(true));
    probe.once("error", () => settle(false));
    probe.once("timeout", () => settle(false));
    probe.connect(port, "127.0.0.1");
  });
}

async function serveSshd(dir, hostKeyPath, port) {
  const config = join(dir, "sshd_config");
  writeFileSync(
    config,
    [`Port ${port}`, "ListenAddress 127.0.0.1", `HostKey ${hostKeyPath}`, "PasswordAuthentication no", "StrictModes no", ""].join(
      "\n",
    ),
  );
  const child = spawn(SSHD, ["-D", "-e", "-f", config], { stdio: "ignore" });
  for (let attempt = 0; attempt < 50; attempt++) {
    if (await reachable(port)) return child;
    await sleep(100);
  }
  child.kill("SIGKILL");
  throw new Error("sshd did not come up");
}

// `ssh` itself is stubbed so the argv the gateway builds can be read back
// without a login. The host key check runs for real against the sshd above,
// which is the part being tested.
function stubSsh(dir) {
  const record = join(dir, "argv");
  const bin = join(dir, "ssh");
  // `exec` so the process the tunnel holds is the one that stays open, and
  // closing the tunnel ends it rather than orphaning a sleep.
  writeFileSync(bin, `#!/bin/sh\nprintf '%s\\n' "$@" > ${record}\nexec sleep 30\n`);
  chmodSync(bin, 0o755);
  process.env.PATH = `${dir}:${process.env.PATH}`;
  return record;
}

async function recordedArgv(record) {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (existsSync(record)) return readFileSync(record, "utf8").split("\n");
    await sleep(100);
  }
  throw new Error("the tunnel never ran ssh");
}

test(
  "the tunnel refuses a box that is not the one the lease names",
  { skip: !existsSync(SSHD) && "no sshd to serve a host key" },
  async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "prism-tunnel-"));
    const path = process.env.PATH;
    t.after(() => {
      process.env.PATH = path;
      rmSync(dir, { recursive: true, force: true });
    });

    const hostKey = join(dir, "hostkey");
    execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", hostKey]);
    const fingerprint = execFileSync("ssh-keygen", ["-lf", `${hostKey}.pub`], { encoding: "utf8" }).split(/\s+/)[1];
    const port = await freePort();
    const sshd = await serveSshd(dir, hostKey, port);
    t.after(() => sshd.kill("SIGKILL"));

    const record = stubSsh(dir);
    const keyPath = join(dir, "id_ed25519");
    writeFileSync(keyPath, "");
    const lease = {
      keyPath,
      access: {
        ssh_host: "127.0.0.1",
        ssh_port: port,
        ssh_user: "root",
        channel_key_fingerprint: fingerprint,
        channel_key_source: "node_report",
      },
    };

    const tunnel = await openTunnel(lease, await freePort());
    t.after(() => tunnel.close());
    const argv = await recordedArgv(record);
    assert.ok(argv.includes("StrictHostKeyChecking=yes"));
    assert.ok(argv.includes(`UserKnownHostsFile=${join(dir, "known_hosts")}`));
    assert.ok(!argv.includes("StrictHostKeyChecking=no"));
    assert.ok(!argv.includes("UserKnownHostsFile=/dev/null"));

    rmSync(record);
    const other = join(dir, "other");
    execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", other]);
    lease.access.channel_key_fingerprint = execFileSync("ssh-keygen", ["-lf", `${other}.pub`], {
      encoding: "utf8",
    }).split(/\s+/)[1];
    await assert.rejects(openTunnel(lease, await freePort()), (err) => err.code === "host_key_mismatch");
    assert.equal(existsSync(record), false, "no prompt crosses a tunnel to a machine that failed the check");
  },
);

test("a lease that publishes no host key is pinned on first sight", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "prism-tunnel-"));
  const path = process.env.PATH;
  t.after(() => {
    process.env.PATH = path;
    rmSync(dir, { recursive: true, force: true });
  });

  const record = stubSsh(dir);
  const keyPath = join(dir, "id_ed25519");
  writeFileSync(keyPath, "");
  const tunnel = await openTunnel(
    { keyPath, access: { ssh_host: "127.0.0.1", ssh_port: 2222, ssh_user: "root" } },
    await freePort(),
  );
  t.after(() => tunnel.close());
  const argv = await recordedArgv(record);
  assert.ok(argv.includes("StrictHostKeyChecking=accept-new"));
  assert.ok(argv.includes(`UserKnownHostsFile=${join(dir, "known_hosts")}`));
  assert.ok(!argv.includes("StrictHostKeyChecking=no"));
});
