import test from "node:test";
import assert from "node:assert/strict";
import { authorized, isLoopback, listener } from "./listen.mjs";

const TOKEN = "s".repeat(32);
const request = (authorization) => ({ headers: authorization ? { authorization } : {} });

test("an operator who sets nothing gets a listener only this machine can reach", () => {
  assert.deepEqual(listener({}, "X402"), { host: "127.0.0.1", token: null });
  assert.deepEqual(listener({ X402_PORT: "8402" }, "X402"), { host: "127.0.0.1", token: null });
});

test("the loopback names are all treated as loopback, whitespace and case included", () => {
  for (const host of ["127.0.0.1", "::1", "localhost", "LOCALHOST", " ::1 ", "0:0:0:0:0:0:0:1"]) {
    assert.equal(isLoopback(host), true, `${host} should be loopback`);
    assert.equal(listener({ X402_HOST: host }, "X402").token, null, `${host} should not demand a token`);
  }
  for (const host of ["0.0.0.0", "::", "10.0.0.4", "example.test"]) {
    assert.equal(isLoopback(host), false, `${host} should not be loopback`);
  }
});

test("binding wider without a credential refuses to start, and says which variable to set", () => {
  assert.throws(
    () => listener({ INFERENCE_HOST: "0.0.0.0" }, "INFERENCE"),
    (err) => err.message.includes("INFERENCE_HOST is 0.0.0.0") && err.message.includes("INFERENCE_TOKEN"),
  );
});

test("a credential too short to be a secret is refused rather than accepted", () => {
  assert.throws(
    () => listener({ X402_HOST: "0.0.0.0", X402_TOKEN: "short" }, "X402"),
    (err) => err.message.includes("at least 16 characters"),
  );
  assert.deepEqual(listener({ X402_HOST: "0.0.0.0", X402_TOKEN: TOKEN }, "X402"), {
    host: "0.0.0.0",
    token: TOKEN,
  });
});

/// An operator who names a token on loopback meant it, and honouring it there
/// is what lets the gate be exercised without opening a port to the network.
test("a token set on a loopback listener is still enforced", () => {
  const { token } = listener({ X402_HOST: "127.0.0.1", X402_TOKEN: TOKEN }, "X402");
  assert.equal(token, TOKEN);
  assert.equal(authorized(request(), token), "missing");
});

test("without a token every caller is already on this machine", () => {
  assert.equal(authorized(request(), null), "ok");
  assert.equal(authorized(request("Bearer anything"), null), "ok");
});

test("the token is checked whether or not the caller spelled the scheme", () => {
  assert.equal(authorized(request(`Bearer ${TOKEN}`), TOKEN), "ok");
  assert.equal(authorized(request(TOKEN), TOKEN), "ok");
  assert.equal(authorized(request(`Bearer ${"s".repeat(31)}`), TOKEN), "mismatch");
  assert.equal(authorized(request(`Bearer ${"x".repeat(32)}`), TOKEN), "mismatch");
  assert.equal(authorized(request("Bearer "), TOKEN), "missing");
  assert.equal(authorized(request(), TOKEN), "missing");
});
