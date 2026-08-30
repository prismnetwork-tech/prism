// The gateway's half of a warm lease: a local port that reaches the box's
// ollama and nothing else.
//
// Every prompt this gateway is paid for crosses this forward, so the machine on
// the far end is checked against the host key the lease publishes before it
// carries anything. Where the lease publishes none, which is every box brokered
// from a public cloud, the key is taken on first sight and held for the rest of
// the lease: that catches a machine swapped in partway through and cannot catch
// one that was wrong from the start.
import { spawn } from "node:child_process";
import { hostKeyArgs } from "@prismnetwork/agent-sdk";

export async function openTunnel(lease, localPort) {
  const access = lease.access;
  const target = { host: access.ssh_host, port: access.ssh_port, keyPath: lease.keyPath };
  const child = spawn("ssh", [
    "-i", lease.keyPath,
    "-p", String(access.ssh_port),
    ...(await hostKeyArgs(target, access)),
    "-o", "BatchMode=yes",
    "-o", "ServerAliveInterval=15",
    "-o", "ExitOnForwardFailure=yes",
    "-N",
    "-L", `127.0.0.1:${localPort}:127.0.0.1:11434`,
    `${access.ssh_user ?? "root"}@${access.ssh_host}`,
  ]);
  child.on("error", (err) => console.error(`tunnel error: ${err.message}`));
  return { close: () => child.kill("SIGTERM") };
}
