// keytool.html end to end in a browser, against the development host (crates/rootcard-host/examples/host.rs): create
// an identity at the host, load it from the downloaded card, add a password, rotate the recovery key with the host gone
// (the new card must still be downloaded and both cards kept) and with the host up, load the new card and retire it.
// Then create a second identity only on the card, open it without a host (only offline actions are allowed) and
// start it at the host, typed without a scheme. The page is opened from file://, as users open it, so every request is cross-origin.
// The 0.2.0 page could not reach any host and no test noticed (docs/PLAN.md).

import { spawn } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const PASSWORD = "correct horse battery staple";
const SEED = "07".repeat(32);

/** Start the development host on `port`; resolves when it listens. */
export function startHost(root, port) {
  const child = spawn("cargo", ["run", "-q", "-p", "rootcard-host", "--example", "host"], {
    cwd: root,
    env: { ...process.env, ROOTCARD_HOST_PORT: String(port), ROOTCARD_HOST_SEED: SEED },
    stdio: ["ignore", "ignore", "pipe"],
  });
  return new Promise((resolve, reject) => {
    let err = "";
    child.stderr.on("data", (d) => {
      err += d;
      if (err.includes("rootcard development host at")) resolve(child);
    });
    child.on("exit", (code) => reject(new Error(`the host exited (${code}):\n${err}`)));
  });
}

function stopHost(child) {
  return new Promise((resolve) => {
    child.removeAllListeners("exit");
    child.on("exit", resolve);
    child.kill();
  });
}

/** Click a button and wait until the page reports the outcome. Returns `{ ok, text }`. */
async function act(page, selector) {
  await page.click(selector);
  await page.waitForFunction(() => ["Done.", "Failed."].includes(document.getElementById("status").textContent), null, {
    timeout: 5 * 60 * 1000,
  });
  return {
    ok: (await page.textContent("#status")) === "Done.",
    text: await page.textContent("#out"),
  };
}

/** Click and collect the downloads the action triggers, saved into `dir`. */
async function actWithDownloads(page, selector, dir) {
  const files = [];
  const onDownload = async (d) => {
    const path = join(dir, d.suggestedFilename());
    files.push(d.saveAs(path).then(() => path));
  };
  page.on("download", onDownload);
  const r = await act(page, selector);
  page.off("download", onDownload);
  return { ...r, files: await Promise.all(files) };
}

function expect(cond, what, detail = "") {
  if (!cond) throw new Error(`${what}${detail ? `\n${detail}` : ""}`);
}

export async function keytoolTest(engine, root, port) {
  const url = `http://127.0.0.1:${port}`;
  const dir = await mkdtemp(join(tmpdir(), "rootcard-keytool-"));
  const host = await startHost(root, port);
  const browser = await engine.launch();
  try {
    const context = await browser.newContext({ acceptDownloads: true });
    const page = await context.newPage();
    page.on("pageerror", (e) => console.error(`page error: ${e.message}`));
    await page.goto(pathToFileURL(join(root, "packages/rootcard/keytool.html")).href);

    // Create an identity at the host ([CLT-1]): the card and the account file are downloaded.
    await page.click("text=Create a new identity");
    await page.fill("#nUser", "Astra");
    await page.fill("#nHost", url);
    await page.fill("#nPassword", PASSWORD);
    let r = await actWithDownloads(page, "#create", dir);
    expect(r.ok, "create failed", r.text);
    const card = r.files.find((f) => f.endsWith(".card.json"));
    expect(card && r.files.length === 2, "create did not download the card and the account file", r.files.join("\n"));

    // Load it from the card file; the host supplies the log and the vault. (A card holds only the inception, so the
    // page needs the account file or a host to ask, like `--from` in the CLI.)
    expect((await page.inputValue("#hosts")) === url, "create did not fill in the host for opening the identity");
    await page.click("#tab-open");
    await page.setInputFiles("#cardFile", card);
    r = await act(page, "#load");
    expect(r.ok && r.text.includes("Astra#") && !r.text.includes("Vault not available"), "load failed", r.text);

    // Add a password ([KT-4]).
    await page.click("[data-pick=add]");
    await page.fill("#newPassword", "a second passphrase");
    await page.fill("#label", "Phone");
    r = await act(page, "[data-op=add]");
    expect(r.ok && r.text.includes("Phone"), "add password failed", r.text);

    // Rotate while the host cannot be reached for the rotation itself ([KT-5]): the new card is downloaded before
    // anything is sent, and the page says to keep both cards. Nothing reached the host, so the old card stays current.
    await page.click("[data-pick=rotate]");
    await page.route("**/events", (route) => route.abort("connectionrefused"));
    r = await actWithDownloads(page, "[data-op=rotate]", dir);
    await page.unroute("**/events");
    expect(!r.ok && r.files.length === 1 && r.text.includes("Keep both cards"), "rotation with the host gone", r.text);

    // Rotate with the host up: the new card is downloaded; the old card no longer loads as current, the new one does.
    r = await actWithDownloads(page, "[data-op=rotate]", dir);
    expect(r.ok && r.files.length === 1, "rotation with the host up failed", r.text);
    const second = r.files[0];
    await page.setInputFiles("#cardFile", card);
    r = await act(page, "#load");
    expect(!r.ok && r.text.includes("wrong_recovery_key"), "the old card still loads after the rotation", r.text);
    await page.setInputFiles("#cardFile", second);
    r = await act(page, "#load");
    expect(r.ok && !r.text.includes("Vault not available"), "loading the new card failed (the vault must verify)", r.text);

    // Retire ([KT-6]).
    await page.click("[data-pick=retire]");
    await page.fill("#retireConfirm", "Astra");
    r = await act(page, "[data-op=retire]");
    expect(r.ok && r.text.includes("retired"), "retire failed", r.text);

    // An identity that exists only on its card ([KT-1]): created without a host, opened without one. Actions that
    // need a host are unavailable and say why; showing the card works offline.
    await page.click("#tab-create");
    await page.fill("#nUser", "Bora");
    await page.check("#nLocal");
    r = await actWithDownloads(page, "#create", dir);
    expect(r.ok && r.files.length === 2, "creating an identity on the card only failed", r.text);
    const local = r.files.find((f) => f.endsWith(".card.json"));
    await page.click("#tab-open");
    await page.fill("#hosts", "");
    await page.setInputFiles("#cardFile", local);
    r = await act(page, "#load");
    expect(r.ok && r.text.includes("Instance: none"), "opening a card-only identity failed", r.text);
    expect((await page.textContent("#badges")).includes("Not at any host"), "the page does not say the identity is at no host");
    await page.click("[data-pick=reset]");
    expect(await page.isDisabled("[data-op=reset]"), "reset is offered for an identity at no host");
    expect(await page.isVisible("#opBlocked"), "the page does not say why reset is unavailable");
    await page.click("[data-pick=card]");
    r = await act(page, "[data-op=card]");
    expect(r.ok && r.text.includes("Bora"), "showing the card offline failed", r.text);

    // Start it at the host ([KT-3] fresh). The address is typed without a scheme; the page adds http:// for this
    // computer, and shows what it will contact.
    await page.click("[data-pick=fresh]");
    await page.fill("#targetHost", url.replace("http://", ""));
    expect((await page.textContent("#targetHostCheck")).includes(url), "the host address is not shown as normalized");
    await page.fill("#newPassword", PASSWORD);
    r = await actWithDownloads(page, "[data-op=fresh]", dir);
    expect(r.ok && r.text.includes(`at ${url}`) && r.files.length === 1, "starting at the host failed", r.text);
    expect((await page.textContent("#badges")).includes("At a host"), "the page does not show the new host");
    expect(!(await page.isDisabled("[data-op=fresh]")), "fresh disabled after starting at the host");
    await page.click("[data-pick=add]");
    expect(!(await page.isDisabled("[data-op=add]")), "add is not offered once the identity is at a host");
    return "create, load, add, rotate (send failed, then sent), load the new card, retire; card only: create, open, start at host";
  } finally {
    await browser.close();
    await stopHost(host);
  }
}
