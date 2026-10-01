import http from "node:http";
import assert from "node:assert/strict";
import test from "node:test";
import { LockGateClient, LockGateError } from "./index.js";

const listen = server => new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const close = server => new Promise(resolve => server.close(resolve));

test("waits for approval and returns the configured bundle", async () => {
  let key = "";
  const server = http.createServer((request, response) => {
    response.setHeader("Content-Type", "application/json");
    if (request.method === "POST") {
      key = request.headers["idempotency-key"];
      response.writeHead(202).end(JSON.stringify({ status: "waiting_approval", request_id: "request_1", retry_after: 0 }));
      return;
    }
    response.end(JSON.stringify({ status: "approved", secrets: { "apps/test/production": { DB_USER: "postgres" } } }));
  });
  await listen(server);
  try {
    const config = await new LockGateClient({ url: `http://127.0.0.1:${server.address().port}`, token: "lg_app_test" }).getConfig();
    assert.equal(config.DB_USER, "postgres");
    assert.ok(key);
  } finally { await close(server); }
});

test("does not forward a token through redirects", async () => {
  let leaked = false;
  const target = http.createServer((request, response) => { leaked = Boolean(request.headers.authorization); response.end("{}"); });
  await listen(target);
  const source = http.createServer((request, response) => {
    response.writeHead(307, { Location: `http://127.0.0.1:${target.address().port}/leak` }).end();
  });
  await listen(source);
  try {
    const client = new LockGateClient({ url: `http://127.0.0.1:${source.address().port}`, token: "lg_app_secret" });
    await assert.rejects(() => client.getConfig(), LockGateError);
    assert.equal(leaked, false);
  } finally { await close(source); await close(target); }
});
