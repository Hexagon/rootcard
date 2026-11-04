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
