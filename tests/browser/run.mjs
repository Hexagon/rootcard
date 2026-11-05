// Run the shared vectors and keytool.html in real browsers with Playwright: `node run.mjs [chromium] [firefox]
// [webkit]` (all three by default). Serves the repository over http://127.0.0.1 (a secure context, so WebCrypto is
// available) for the vectors, and drives keytool.html from file:// against the development host (keytool.mjs, which
// runs `cargo run --example host`; set ROOTCARD_SKIP_KEYTOOL to skip it). Fails if anything fails in any browser. Playwright is installed only here, never in the npm package (AGENTS.md rule 6).

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, firefox, webkit } from "playwright";
import { keytoolTest } from "./keytool.mjs";

const ROOT = normalize(join(fileURLToPath(new URL(".", import.meta.url)), "..", ".."));
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".json": "application/json" };
const ENGINES = { chromium, firefox, webkit };
const TIMEOUT = 15 * 60 * 1000;

const server = createServer(async (req, res) => {
  const path = normalize(join(ROOT, decodeURIComponent(new URL(req.url, "http://x").pathname)));
  if (!path.startsWith(ROOT + sep) || !TYPES[extname(path)]) {
    res.writeHead(404).end();
    return;
  }
  try {
    const body = await readFile(path);
    res.writeHead(200, { "content-type": TYPES[extname(path)] }).end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const names = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(ENGINES);
let failed = false;
for (const name of names) {
  const engine = ENGINES[name];
  if (!engine) throw new Error(`unknown browser ${name}`);
  const browser = await engine.launch();
  try {
    const page = await browser.newPage();
    page.on("pageerror", (e) => console.error(`[${name}] page error: ${e.message}`));
    await page.goto(`${base}/tests/browser/vectors.html`);
    await page.waitForFunction(() => window.results !== undefined, null, { timeout: TIMEOUT, polling: 1000 });
    const r = await page.evaluate(() => window.results);
    console.log(`${name} (${r.userAgent ?? "?"}): ${r.pass} passed, ${r.fail} failed`);
    for (const f of r.failures) console.log(`  FAIL ${f}`);
    if (r.fail > 0 || r.pass === 0) failed = true;
    // TEMPORARY diagnostic (PR #11): which WebCrypto step rejects an Ed25519 seed with a zero first byte. Never fails.
    const seedHex = "004ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6";
    const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]);
    const nk = (await import("node:crypto")).createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    const nj = nk.export({ format: "jwk" });
    const expectSig = (await import("node:crypto")).sign(null, Buffer.from("72", "hex"), nk).toString("hex");
    const probe = await page.evaluate(async ({ derHex, jwk, expectSig }) => {
      const hx = (h) => Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
      const toHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
      const msg = hx("72");
      const out = {};
      const step = async (name, f) => {
        try {
          out[name] = await f();
        } catch (e) {
          out[name] = `ERR ${e.name}: ${e.message}`;
        }
      };
      const variants = {
        "d only": { kty: "OKP", crv: "Ed25519", d: jwk.d, ext: true },
        "d, x of zeros": { kty: "OKP", crv: "Ed25519", d: jwk.d, x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ext: true },
        "d, x of another key": { kty: "OKP", crv: "Ed25519", d: jwk.d, x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", ext: true },
      };
      for (const [n, j] of Object.entries(variants)) {
        let k;
        await step(`${n}: import`, async () => ((k = await crypto.subtle.importKey("jwk", j, { name: "Ed25519" }, true, ["sign"])), "ok"));
        if (!k) continue;
        await step(`${n}: export x`, async () => {
          const e = await crypto.subtle.exportKey("jwk", k);
          return e.x === jwk.x ? "correct" : "WRONG " + e.x;
        });
        await step(`${n}: sign`, async () => {
          const s = toHex(await crypto.subtle.sign("Ed25519", k, msg));
          return s === expectSig ? "matches" : "DIFFERS";
        });
      }
      return out;
    }, { derHex: der.toString("hex"), jwk: { kty: "OKP", crv: "Ed25519", d: nj.d, x: nj.x, ext: true }, expectSig });
    console.log(`  PROBE ${name}: ${JSON.stringify(probe)}`);
  } finally {
    await browser.close();
  }
  if (process.env.ROOTCARD_SKIP_KEYTOOL) continue;
  try {
    console.log(`${name} keytool.html: ${await keytoolTest(engine, ROOT, 18700 + names.indexOf(name))}`);
  } catch (e) {
    console.log(`${name} keytool.html: FAIL ${e.message}`);
    failed = true;
  }
}
server.close();
process.exit(failed ? 1 : 0);
