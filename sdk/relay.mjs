// Reaching a workspace that has no public address.
//
// Capacity brokered from a cloud gives the renter an SSH endpoint on the host.
// A physical node has none: it dials out to the gateway and accepts nothing
// inbound, so the renter's session is carried back through that tunnel. This
// opens the renter's half of it and presents the result as a local port, which
// is what lets `ssh`, `scp`, or anything else speak to a machine that cannot be
// addressed.
//
// The relay wants one JSON frame naming the grant and the service, answers with
// one saying whether it paired, and from then on the connection is the workspace
// socket. Frames are a big-endian u32 length followed by the payload.
import { createServer } from "node:net";
import { connect as tlsConnect } from "node:tls";

const MAX_FRAME_BYTES = 16 * 1_024;
const HANDSHAKE_TIMEOUT_MS = 20_000;

export class RelayError extends Error {
  constructor(code, detail) {
    super(code);
    this.name = "RelayError";
    this.code = code;
    this.detail = detail ?? null;
  }
}

function frame(value) {
  const payload = Buffer.from(JSON.stringify(value));
  if (payload.length > MAX_FRAME_BYTES) throw new RelayError("relay_frame_too_large");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

// Resolves with the first frame and whatever bytes arrived behind it. Those
// trailing bytes are already workspace traffic, so losing them corrupts the
// session before it starts.
function readFrame(socket) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new RelayError("relay_handshake_timeout"));
    }, HANDSHAKE_TIMEOUT_MS);

    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 4) return;
      const length = buffer.readUInt32BE(0);
      if (length > MAX_FRAME_BYTES) {
        cleanup();
        reject(new RelayError("relay_frame_too_large"));
        return;
      }
      if (buffer.length < 4 + length) return;
      cleanup();
      try {
        resolve({
          message: JSON.parse(buffer.subarray(4, 4 + length).toString("utf8")),
          rest: buffer.subarray(4 + length),
        });
      } catch (err) {
        reject(new RelayError("relay_frame_malformed", err?.message ?? String(err)));
      }
    };
    const onError = (err) => {
      cleanup();
      reject(new RelayError("relay_disconnected", err?.message ?? String(err)));
    };
    const onEnd = () => {
      cleanup();
      reject(new RelayError("relay_closed_early"));
    };
    function cleanup() {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("end", onEnd);
    }

    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("end", onEnd);
  });
}

function dial(access) {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect(
      {
        host: access.gateway_host,
        port: access.relay_port,
        servername: access.gateway_host,
        // The relay runs under a private CA, so the public trust store says
        // nothing about it. Pinning the root the control plane handed back is
        // the whole reason it is in the grant.
        ca: access.gateway_ca ? [access.gateway_ca] : undefined,
      },
      () => resolve(socket),
    );
    socket.once("error", (err) => reject(new RelayError("relay_connect_failed", err?.message ?? String(err))));
  });
}

// Checked before anything is opened, so a grant that can never work says so at
// once instead of leaving the caller with a port that resets every connection.
function assertUsable(access) {
  if (!access?.gateway_host || !access?.relay_port || !access?.token) {
    throw new RelayError("relay_access_incomplete");
  }
  if (!access.gateway_ca) {
    throw new RelayError("relay_ca_missing", "the access grant carries no gateway root to verify against");
  }
}

// One relay connection, paired and ready to carry traffic.
export async function openRelayConnection(access, service = "ssh") {
  assertUsable(access);
  const socket = await dial(access);
  socket.write(frame({ token: access.token, service }));
  const { message, rest } = await readFrame(socket);
  if (!message?.ready) {
    socket.destroy();
    throw new RelayError("relay_refused", message?.error ?? null);
  }
  return { socket, rest };
}

/// A local port that forwards to the workspace, one relay connection per
/// inbound connection. `ssh` gets an address it can use and never learns the
/// session is tunnelled.
export async function openRelayForwarder(access, { service = "ssh" } = {}) {
  assertUsable(access);
  const server = createServer();
  const sockets = new Set();

  server.on("connection", (local) => {
    sockets.add(local);
    local.on("close", () => sockets.delete(local));
    local.on("error", () => local.destroy());
    openRelayConnection(access, service)
      .then(({ socket, rest }) => {
        if (local.destroyed) {
          socket.destroy();
          return;
        }
        sockets.add(socket);
        socket.on("close", () => sockets.delete(socket));
        socket.on("error", () => {
          socket.destroy();
          local.destroy();
        });
        if (rest.length > 0) local.write(rest);
        local.pipe(socket);
        socket.pipe(local);
      })
      .catch(() => local.destroy());
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  const { port } = server.address();
  return {
    host: "127.0.0.1",
    port,
    async close() {
      for (const socket of sockets) socket.destroy();
      sockets.clear();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
