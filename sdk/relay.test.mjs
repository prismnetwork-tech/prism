import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:tls";
import test from "node:test";

import { RelayError, openRelayForwarder } from "./relay.mjs";

// A self-signed root standing in for the gateway's private CA, so the test
// exercises the pinning path rather than skipping past it.
function issueCertificate() {
  const dir = mkdtempSync(join(tmpdir(), "prism-relay-test-"));
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost",
    "-keyout", join(dir, "key.pem"),
    "-out", join(dir, "cert.pem"),
  ], { stdio: "ignore" });
  return {
    dir,
    key: readFileSync(join(dir, "key.pem"), "utf8"),
    cert: readFileSync(join(dir, "cert.pem"), "utf8"),
  };
}

function readFrame(socket, onFrame) {
  let buffer = Buffer.alloc(0);
  let done = false;
  socket.on("data", (chunk) => {
    if (done) return;
    buffer = Buffer.concat([buffer, chunk]);
    if (buffer.length < 4) return;
    const length = buffer.readUInt32BE(0);
    if (buffer.length < 4 + length) return;
    done = true;
    onFrame(JSON.parse(buffer.subarray(4, 4 + length).toString("utf8")), buffer.subarray(4 + length));
  });
}

function writeFrame(socket, value) {
  const payload = Buffer.from(JSON.stringify(value));
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  socket.write(Buffer.concat([header, payload]));
}

/// Stands in for the gateway: reads the request frame, answers, and then echoes
/// whatever the workspace would have sent back.
async function startRelay({ key, cert }, { ready = true, error = null, onRequest = () => {} } = {}) {
  const server = createServer({ key, cert }, (socket) => {
    readFrame(socket, (request) => {
      onRequest(request);
      writeFrame(socket, { ready, error });
      if (!ready) {
        socket.end();
        return;
      }
      socket.on("data", (chunk) => socket.write(Buffer.concat([Buffer.from("echo:"), chunk])));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, port: server.address().port };
}

test("refuses a grant with no root to verify the relay against", async () => {
  await assert.rejects(
    () => openRelayForwarder({ gateway_host: "localhost", relay_port: 1, token: "t" }),
    (err) => err instanceof RelayError && err.code === "relay_ca_missing",
  );
});

test("refuses an access grant that names no relay", async () => {
  await assert.rejects(
    () => openRelayForwarder({ gateway_ca: "pem", token: "t" }),
    (err) => err instanceof RelayError && err.code === "relay_access_incomplete",
  );
});

test("carries traffic to the workspace and presents the grant", async () => {
  const material = issueCertificate();
  let seen = null;
  const relay = await startRelay(material, { onRequest: (request) => { seen = request; } });
  const forwarder = await openRelayForwarder({
    gateway_host: "localhost",
    relay_port: relay.port,
    token: "grant-token",
    gateway_ca: material.cert,
  });

  const reply = await new Promise((resolve, reject) => {
    const socket = connect(forwarder.port, forwarder.host, () => socket.write("hello"));
    socket.on("data", (chunk) => {
      resolve(chunk.toString("utf8"));
      socket.destroy();
    });
    socket.on("error", reject);
  });

  assert.equal(reply, "echo:hello");
  assert.deepEqual(seen, { token: "grant-token", service: "ssh" });

  await forwarder.close();
  await new Promise((resolve) => relay.server.close(resolve));
  rmSync(material.dir, { recursive: true, force: true });
});

test("a refused grant closes the local connection rather than hanging", async () => {
  const material = issueCertificate();
  const relay = await startRelay(material, { ready: false, error: "lease_not_active" });
  const forwarder = await openRelayForwarder({
    gateway_host: "localhost",
    relay_port: relay.port,
    token: "stale",
    gateway_ca: material.cert,
  });

  const closed = await new Promise((resolve, reject) => {
    const socket = connect(forwarder.port, forwarder.host, () => socket.write("hello"));
    socket.on("close", () => resolve(true));
    socket.on("error", () => resolve(true));
    setTimeout(() => reject(new Error("the local connection stayed open")), 10_000);
  });

  assert.equal(closed, true);
  await forwarder.close();
  await new Promise((resolve) => relay.server.close(resolve));
  rmSync(material.dir, { recursive: true, force: true });
});
