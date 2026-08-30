import http from "node:http";

const port = Number.parseInt(process.env.PORT ?? "", 10);
const upstream = process.env.RPC_URL;

if (!Number.isInteger(port) || port <= 0 || !upstream) {
  throw new Error("PORT and RPC_URL are required");
}

let droppedSubmission = false;
let staleTransactionCount;

const server = http.createServer(async (request, response) => {
  if (request.method !== "POST") {
    response.writeHead(404).end();
    return;
  }

  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const body = Buffer.concat(chunks);
  const payload = JSON.parse(body.toString("utf8"));
  if (payload.method === "eth_getTransactionCount" && staleTransactionCount) {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(staleTransactionCount);
    return;
  }
  const upstreamResponse = await fetch(upstream, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
  const upstreamBody = Buffer.from(await upstreamResponse.arrayBuffer());

  if (payload.method === "eth_getTransactionCount") {
    staleTransactionCount = upstreamBody;
  }

  if (payload.method === "eth_sendRawTransaction" && !droppedSubmission) {
    droppedSubmission = true;
    request.socket.destroy();
    return;
  }

  response.writeHead(upstreamResponse.status, {
    "content-type": upstreamResponse.headers.get("content-type") ?? "application/json",
  });
  response.end(upstreamBody);
});

server.listen(port, "127.0.0.1");
