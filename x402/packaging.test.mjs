import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// An export the tarball does not carry fails only on a fresh install, so it
// survives every local test run and lands in production instead.
test("every subpath the package exports is one the tarball ships", () => {
  const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
  const shipped = new Set(pkg.files);
  const missing = Object.values(pkg.exports)
    .map((target) => target.replace(/^\.\//, ""))
    .filter((file) => !shipped.has(file));

  assert.deepEqual(missing, [], `exported but not in files: ${missing.join(", ")}`);
});
