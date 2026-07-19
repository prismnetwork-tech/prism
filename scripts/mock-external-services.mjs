import { createServer } from "node:http";

const port = Number(process.env.PORT);
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) process.exit(2);

const grants = new Map();

createServer(async (request, response) => {
  const body = await readBody(request);
  if (request.method === "GET" && request.url === "/healthz") {
    response.writeHead(204).end();
    return;
  }
  if (request.method === "POST" && request.url === "/v1/probes") {
    const payload = parse(body);
    const observedAt = new Date().toISOString();
    json(response, 200, {
      node_id: payload.node_id,
      connection_id: payload.connection_id,
      cuda_ready_at: observedAt,
      interactive_access_ready_at: observedAt,
    });
    return;
  }
  if (request.method === "POST" && request.url === "/v1/grants") {
    const payload = parse(body);
    const current = grants.get(payload.token_id);
    if (current) {
      json(response, 200, current);
      return;
    }
    const expiresAt = new Date(Date.now() + payload.ttl_seconds * 1_000).toISOString();
    const grant = {
      token: `test.${payload.token_id}.gateway-token-material`,
      grant: {
        token_id: payload.token_id,
        lease_id: payload.lease_id,
        node_id: payload.node_id,
        connection_id: payload.connection_id,
        expires_at: expiresAt,
      },
    };
    grants.set(payload.token_id, grant);
    json(response, 200, grant);
    return;
  }
  if (request.method === "DELETE" && request.url?.startsWith("/v1/grants/")) {
    grants.delete(request.url.slice("/v1/grants/".length));
    response.writeHead(204).end();
    return;
  }
  if (request.method === "POST" && request.url === "/2/tweets") {
    json(response, 201, { data: { id: "test-proof-post" } });
    return;
  }
  json(response, 404, { error: "not_found" });
}).listen(port, "127.0.0.1");

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    request.on("data", (chunk) => {
      length += chunk.length;
      if (length > 64 * 1_024) {
        reject(new Error("request too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function parse(body) {
  return JSON.parse(body.toString("utf8") || "{}");
}

function json(response, status, value) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}
