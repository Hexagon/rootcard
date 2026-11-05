// keytool.html is generated from the package's modules (tools/build-keytool.mjs) and must be up to date.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { build } from "../tools/build-keytool.mjs";

test("keytool.html is built from the current sources", () => {
  const current = readFileSync(new URL("../keytool.html", import.meta.url), "utf8");
  assert.ok(current === build(), "keytool.html is stale: run `npm run build` in packages/rootcard");
});

test("keytool.html loads nothing from the network and allows no inline handlers", () => {
  const html = readFileSync(new URL("../keytool.html", import.meta.url), "utf8");
  assert.doesNotMatch(html, /<script[^>]+src=/);
  assert.doesNotMatch(html, /<link[^>]+href=/);
  assert.doesNotMatch(html, /\son[a-z]+=/);
  assert.match(html, /Content-Security-Policy/);
});

// Regression (0.2.0): binding.js was re-exported by index.js but not inlined, so keytool.html had no checkBaseUrl and
// refused every host address. Every public name of the package must exist in the page's `rc`.
test("keytool.html has every function the package exports", async () => {
  const html = readFileSync(new URL("../keytool.html", import.meta.url), "utf8");
  const script = html.slice(html.indexOf("<script>") + 8, html.lastIndexOf("</script>"));
  // Run the library part of the page (up to the app) and collect what the app sees as `rc`.
  const lib = script.slice(0, script.indexOf("const $ = "));
  const rc = new Function(`${lib.replace(/^\s*"use strict";\s*\(\(\) => \{/, "")}\nreturn rc;`)();
  const index = await import("../src/index.js");
  const vault = await import("../src/vault-index.js");
  const missing = [...Object.keys(index), ...Object.keys(vault)].filter((n) => !(n in rc));
  assert.deepEqual(missing, []);
});
