// Supply-chain rules for the npm package (AGENTS.md rule 6).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

test("the package has no dependencies of any kind", () => {
  for (const field of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "bundleDependencies"]) {
    assert.equal(pkg[field], undefined, `${field} must not exist`);
  }
});

test("the package is plain ES modules with an explicit file list", () => {
  assert.equal(pkg.type, "module");
  assert.ok(Array.isArray(pkg.files) && pkg.files.length > 0);
  assert.equal(pkg.sideEffects, false);
});
