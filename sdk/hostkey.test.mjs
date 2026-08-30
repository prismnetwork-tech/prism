import assert from "node:assert/strict";
import { execFile, execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { hostKeyArgs, HostKeyError, hostKeyPolicy, knownHostsFingerprint, knownHostsPath } from "./hostkey.mjs";
import { PrismAgent } from "./prism.mjs";

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

function generateKey(dir, name) {
  const path = join(dir, name);
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", path]);
  return {
    path,
    fingerprint: execFileSync("ssh-keygen", ["-lf", `${path}.pub`], { encoding: "utf8" }).split(/\s+/)[1],
  };
}

// A real sshd, because what is being tested is whether the key the network
// named is the key the machine actually offers. Nothing logs in: `ssh-keyscan`
// reads the host key out of the exchange and hangs up.
async function serveSshd(dir, hostKeyPath, port) {
  const config = join(dir, "sshd_config");
  writeFileSync(
    config,
    [
      `Port ${port}`,
      "ListenAddress 127.0.0.1",
      `HostKey ${hostKeyPath}`,
      "PasswordAuthentication no",
      "StrictModes no",
      "",
    ].join("\n"),
  );
  const child = spawn(SSHD, ["-D", "-e", "-f", config], { stdio: "ignore" });
  for (let attempt = 0; attempt < 50; attempt++) {
    if (await reachable(port)) return child;
    await sleep(100);
  }
  child.kill("SIGKILL");
  throw new Error("sshd did not come up");
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

const SSHD = "/usr/sbin/sshd";

test("a published fingerprint is checked against the machine that answers", { skip: !existsSync(SSHD) && "no sshd to serve a host key" }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "prism-hostkey-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const served = generateKey(dir, "served");
  const other = generateKey(dir, "other");
  const port = await freePort();
  const sshd = await serveSshd(dir, served.path, port);
  t.after(() => sshd.kill("SIGKILL"));

  const renterKey = join(dir, "id_ed25519");
  writeFileSync(renterKey, "");
  const target = { host: "127.0.0.1", port, keyPath: renterKey };
  const known = knownHostsPath(renterKey);

  const args = await hostKeyArgs(target, {
    channel_key_fingerprint: served.fingerprint,
    channel_key_source: "node_report",
  });
  assert.deepEqual(args, ["-o", `UserKnownHostsFile=${known}`, "-o", "StrictHostKeyChecking=yes"]);
  const recorded = readFileSync(known, "utf8").trim().split("\n");
  assert.equal(recorded.length, 1, "only the key that was checked is recorded");
  assert.equal(recorded[0].split(/\s+/)[0], `[127.0.0.1]:${port}`);
  assert.equal(knownHostsFingerprint(recorded[0]), served.fingerprint);

  // The renter's own key material is never what decides this, so a grant naming
  // a key the machine does not hold has to fail before anything is sent.
  rmSync(known);
  await assert.rejects(
    hostKeyArgs(target, { channel_key_fingerprint: other.fingerprint, channel_key_source: "snp_report" }),
    (err) => {
      assert.ok(err instanceof HostKeyError);
      assert.equal(err.code, "host_key_mismatch");
      assert.equal(err.detail.expected, other.fingerprint);
      assert.deepEqual(err.detail.offered, [served.fingerprint]);
      return true;
    },
  );
  assert.equal(existsSync(known), false, "a machine that failed the check is not recorded");
});

test("an unreachable box reads as a wait rather than a wrong machine", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "prism-hostkey-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const renterKey = join(dir, "id_ed25519");
  writeFileSync(renterKey, "");

  await assert.rejects(
    hostKeyArgs(
      { host: "127.0.0.1", port: await freePort(), keyPath: renterKey },
      { channel_key_fingerprint: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" },
    ),
    (err) => err instanceof HostKeyError && err.code === "host_key_unavailable",
  );
});

test("a lease that publishes no key is pinned on first sight, or refused outright", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "prism-hostkey-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const renterKey = join(dir, "id_ed25519");
  writeFileSync(renterKey, "");
  const target = { host: "127.0.0.1", port: 2222, keyPath: renterKey };
  const known = knownHostsPath(renterKey);

  assert.deepEqual(await hostKeyArgs(target, { mode: "direct_ssh" }), [
    "-o",
    `UserKnownHostsFile=${known}`,
    "-o",
    "StrictHostKeyChecking=accept-new",
  ]);
  await assert.rejects(
    hostKeyArgs(target, { mode: "direct_ssh" }, { requireHostKey: true }),
    (err) => err instanceof HostKeyError && err.code === "host_key_unpublished",
  );
});

// `ssh` is stubbed so the argv `run()` builds can be read back without a login.
function stubSsh(dir) {
  const record = join(dir, "argv");
  const bin = join(dir, "ssh");
  writeFileSync(bin, `#!/bin/sh\nprintf '%s\\n' "$@" > ${record}\n`);
  chmodSync(bin, 0o755);
  process.env.PATH = `${dir}:${process.env.PATH}`;
  return record;
}

function agentFor(options = {}) {
  return new PrismAgent({
    privateKey: `0x${"11".repeat(32)}`,
    escrow: `0x${"22".repeat(20)}`,
    ...options,
  });
}

test("run() never hands ssh a session it has not checked", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "prism-hostkey-"));
  const path = process.env.PATH;
  t.after(() => {
    process.env.PATH = path;
    rmSync(dir, { recursive: true, force: true });
  });

  const record = stubSsh(dir);
  const keyPath = join(dir, "id_ed25519");
  writeFileSync(keyPath, "");
  const lease = {
    leaseId: 7,
    keyPath,
    access: { mode: "direct_ssh", ssh_host: "127.0.0.1", ssh_port: 2222, ssh_user: "root" },
  };

  await agentFor().run(lease, "nvidia-smi");
  const argv = readFileSync(record, "utf8").split("\n");
  assert.ok(argv.includes("StrictHostKeyChecking=accept-new"));
  assert.ok(argv.includes(`UserKnownHostsFile=${knownHostsPath(keyPath)}`));
  assert.ok(!argv.includes("StrictHostKeyChecking=no"));
  assert.ok(!argv.includes("UserKnownHostsFile=/dev/null"));

  rmSync(record);
  await assert.rejects(agentFor({ requireHostKey: true }).run(lease, "nvidia-smi"), (err) => {
    assert.equal(err.code, "host_key_unpublished");
    assert.equal(err.status, 400);
    return true;
  });
  assert.equal(existsSync(record), false, "a refused lease never reaches ssh");
});

test("the grant says which claim it is making about the host key", () => {
  assert.deepEqual(hostKeyPolicy({ channel_key_fingerprint: "SHA256:a", channel_key_source: "snp_report" }), {
    mode: "attested",
    fingerprint: "SHA256:a",
    source: "snp_report",
  });
  assert.deepEqual(hostKeyPolicy({ channel_key_fingerprint: "SHA256:a", channel_key_source: "node_report" }), {
    mode: "reported",
    fingerprint: "SHA256:a",
    source: "node_report",
  });
  assert.deepEqual(hostKeyPolicy({ mode: "direct_ssh" }), { mode: "unverified", fingerprint: null, source: null });
  assert.deepEqual(hostKeyPolicy(null), { mode: "unverified", fingerprint: null, source: null });
});

// `ssh` for real, against a real sshd, because what is being tested is whether
// the record the first session wrote is the record the second session reads.
function sshAttempt(port, keyPath, args) {
  return new Promise((resolve) => {
    execFile(
      "ssh",
      [
        "-i", keyPath,
        "-p", String(port),
        ...args,
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "workspace@127.0.0.1",
        "true",
      ],
      { timeout: 20_000 },
      (_err, _stdout, stderr) => resolve(stderr ?? ""),
    );
  });
}

/// The case first-use pinning exists for, on the capacity that actually has no
/// published key. A physical node is reached through a tunnel that opens on a
/// fresh local port every time, so a record filed under the port is a record
/// nothing ever reads again: the second session would take whatever answered.
test(
  "a relayed lease pins the machine that answered first, across sessions",
  { skip: !existsSync(SSHD) && "no sshd to serve a host key" },
  async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "prism-hostkey-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const first = generateKey(dir, "first");
    const second = generateKey(dir, "second");
    const firstPort = await freePort();
    const secondPort = await freePort();
    const one = await serveSshd(mkdtempSync(join(dir, "one-")), first.path, firstPort);
    t.after(() => one.kill("SIGKILL"));
    const two = await serveSshd(mkdtempSync(join(dir, "two-")), second.path, secondPort);
    t.after(() => two.kill("SIGKILL"));

    const keyPath = join(dir, "id_ed25519");
    execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", keyPath]);
    const known = knownHostsPath(keyPath);
    const access = { mode: "gateway", lease_id: 4711 };
    const session = async (port) =>
      sshAttempt(port, keyPath, await hostKeyArgs({ host: "127.0.0.1", port, keyPath, access }, access));

    const opened = await session(firstPort);
    assert.doesNotMatch(opened, /IDENTIFICATION HAS CHANGED/);
    const recorded = readFileSync(known, "utf8").trim().split("\n");
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0].split(/\s+/)[0], "prism-lease-4711", "the record is filed under the port that has gone");
    assert.equal(knownHostsFingerprint(recorded[0]), first.fingerprint);

    const substituted = await session(secondPort);
    assert.match(substituted, /IDENTIFICATION HAS CHANGED|HOST KEY VERIFICATION FAILED/);
    assert.equal(readFileSync(known, "utf8").trim().split("\n").length, 1, "the second key was recorded anyway");
  },
);

test("only a lease with no address of its own is pinned under a name", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "prism-hostkey-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const keyPath = join(dir, "id_ed25519");
  writeFileSync(keyPath, "");
  const target = { host: "127.0.0.1", port: 2222, keyPath };

  assert.ok((await hostKeyArgs(target, { mode: "gateway", lease_id: 12 })).includes("HostKeyAlias=prism-lease-12"));
  assert.ok(!(await hostKeyArgs(target, { mode: "direct_ssh" })).some((arg) => arg.startsWith("HostKeyAlias")));
});
