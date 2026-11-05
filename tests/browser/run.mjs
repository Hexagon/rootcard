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
