// The key tool page (SPEC §18.2), inlined into keytool.html after the library modules. It talks only to hosts the
// user enters ([KT-1]) and gathers the newest log before signing anything ([KT-2]).

const rc = { ...__modules["index.js"] };
for (const name of ["errors.js", "json.js", "encoding.js", "labels.js", "binding.js", "crypto.js", "keys.js", "recovery.js", "id.js", "log.js",
  "vaultcheck.js", "profile.js", "messages.js", "proof.js", "file.js", "argon2.js", "vault.js", "account.js", "testing.js"]) {
  Object.assign(rc, __modules[name]);
}
const $ = (id) => document.getElementById(id);
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const now = () => Math.floor(Date.now() / 1000);
let current = null; // { keys, key, log, state, vault, public, realm, username, account }

function show(text, ok = true) {
  $("status").className = ok ? "ok" : "err";
  $("status").textContent = ok ? "Done." : "Failed.";
  $("out").textContent = text;
}

function explain(e) {
  if (e instanceof rc.RootcardError) {
    const why = {
      wrong_recovery_key: "This recovery key is not the identity's current one.",
      bad_checksum: "The recovery key has a typo.",
      unlock_failed: "Wrong password or recovery key.",
      weak_password: "The password is too weak: at least 12 characters, not the username.",
      fork: "Two versions of the identity's log fork. Extend the branch the primary host holds.",
      not_home: "This host is not the identity's primary host.",
      unsupported_browser: "This browser lacks WebCrypto Ed25519 or X25519.",
    }[e.code];
    return `${why ?? "Error"} (${e.code})`;
  }
  return String(e?.message ?? e);
}

async function run(f) {
  for (const b of document.querySelectorAll("button")) b.disabled = true;
  $("status").className = "";
  $("status").textContent = "Working…";
  try {
    await rc.checkSupport();
    show(await f());
  } catch (e) {
    show(explain(e), false);
  } finally {
    for (const b of document.querySelectorAll("button")) b.disabled = false;
  }
}

function download(name, value) {
  const blob = new Blob([rc.canonicalString(value) + "\n"], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
}

async function readFile(input) {
  const f = input.files?.[0];
  if (!f) return undefined;
  return rc.parseLimited(new Uint8Array(await f.arrayBuffer()), rc.FILE_LIMIT ?? 5 * 1024 * 1024);
}

function checkUrl(url) {
  if (!/^https:\/\//.test(url) && !/^http:\/\/(127\.0\.0\.1|localhost)(:|\/|$)/.test(url)) throw new Error(`${url}: hosts are reached over https`);
  return url.replace(/\/+$/, "");
}

// A host address as the user typed it: trailing slashes removed, then checked as a base URL ([HST-22]).
function checkHost(url) {
  const base = url.replace(/\/+$/, "");
  try {
    rc.checkBaseUrl(base);
  } catch {
    throw new Error(`${url}: not a host base URL (https://host[:port][/path], without /v0 at the end)`);
  }
  return base;
}

// The API root of a host: every endpoint is under `<base URL>/v0` until 1.0.0 (HOST_PROTOCOL.md §1.3). Base URLs
// (`home.url`, and `url` in signed messages) never include the version.
function apiRoot(base) {
  return `${checkHost(base)}/${rc.API_VERSION}`;
}

async function http(method, url, body) {
  const res = await fetch(checkUrl(url), {
    method,
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : rc.canonicalString(body),
    credentials: "omit",
    referrerPolicy: "no-referrer",
    cache: "no-store",
  });
  const text = await res.text();
  const value = text ? rc.parseJson(text) : true;
  if (!res.ok) {
    const code = value?.error;
    if (code && rc.ERROR_CODES.includes(code)) throw new rc.RootcardError(code);
    throw new Error(`${url}: HTTP ${res.status}`);
  }
  return value;
}

function hostList() {
  return $("hosts").value.split(",").map((s) => s.trim()).filter(Boolean).map(checkHost);
}

/** [KT-2]: the newest log from the card, the account file and the hosts; a fork stops. */
async function gather() {
  let cardValue = await readFile($("cardFile"));
  if (!cardValue) {
    const key = await rc.parseRecoveryKey($("rkey").value);
    const realm = $("realm").value.trim();
    const username = $("username").value.trim();
    const keys = await rc.deriveRecoveryKeys(key, realm, username);
    const inc = await rc.inception(keys, realm, username);
    cardValue = await rc.recoveryCard(realm, username, await rc.accountId(inc), key);
  }
  const card = await rc.readCard(cardValue);
  const opts = { realms: [card.realm], now: now() };
  let log = card.log;
  let vault;
  let pub;
  const consider = async (candidate, source) => {
    await rc.verifyLog(candidate, opts);
    const order = await rc.compareLogs(log, candidate);
    if (order === "fork") throw new Error(`${source} holds a log that forks from the one already found. Extend the branch the primary host holds.`);
    if (order === "newer") log = candidate;
  };
  const file = await readFile($("accountFile"));
  if (file) {
    const a = await rc.importAccount(file, opts);
    if (a.state.account !== card.account) throw new Error("The account file is another identity.");
    await consider(a.log, "the account file");
    vault = a.vault?.value;
    pub = a.public?.value;
  }
  const hosts = hostList();
  const st0 = await rc.verifyLog(log, opts);
  if (st0.instance) hosts.push(st0.instance.home.url);
  const notes = [];
  for (const h of [...new Set(hosts)]) {
    try {
      const v = await http("GET", `${apiRoot(h)}/id/${card.account}/log`);
      await consider(v.events, h);
    } catch (e) {
      notes.push(`${h}: ${explain(e)}`);
    }
  }
  const state = await rc.verifyLog(log, opts);
  await rc.checkRecoveryKey(state, card.keys.signSeed);
  current = { keys: card.keys, key: card.key, card: cardValue, log, state, vault, public: pub };
  return notes;
}

function describe(state) {
  const lines = [
    `Handle:   ${state.handle}`,
    `Account:  ${state.account}`,
    `Realm:    ${state.realm}`,
    `Version:  seq ${state.version.seq} ${state.version.hash}`,
  ];
  if (state.retired) lines.push("Status:   retired");
  else if (state.instance) lines.push(`Instance: seq ${state.instance.seq} (${state.instance.reason}) at ${state.instance.home.url}`);
  else lines.push("Instance: none");
  return lines.join("\n");
}

async function currentVault() {
  if (current.vault) {
    try {
      return { vault: current.vault, u: await rc.unlockVault(current.vault, current.state, { recovery: current.keys }) };
    } catch {}
  }
  if (!current.state.instance) throw new Error("No instance found: load the account file or enter the primary host.");
  const base = current.state.instance.home.url;
  const account = current.state.account;
  const ch = rc.parseChallenge(await http("POST", `${apiRoot(base)}/id/${account}/challenge`, { purpose: "fetch" }));
  const sig = await rc.ed25519Sign(current.keys.signSeed, rc.fetchMessage(account, ch.host, "recovery", ch.nonce, base));
  const v = await http("POST", `${apiRoot(base)}/id/${account}/fetch`, { lock: "recovery", nonce: ch.nonce, url: base, sig: rc.base64urlEncode(sig) });
  return { vault: v.vault, u: await rc.unlockVault(v.vault, current.state, { recovery: current.keys }) };
}

async function hostHome(base) {
  const d = await http("GET", `${apiRoot(base)}/host`);
  rc.parseKey(d.key, "ed25519");
  return { key: d.key, url: base };
}

function newSlot() {
  const password = $("newPassword").value;
  rc.checkPassword(password, current.state.username);
  return { label: $("label").value.trim() || "Password", password, kdf: rc.KDF_DEFAULT };
}

async function submitInstance(base, mode, old) {
  const home = await hostHome(base);
  let publicData;
  if (current.public) {
    try {
      publicData = (await rc.verifyPublic(current.public, current.state)).data;
    } catch {}
  }
  const ni = await rc.newInstance(current.state, current.keys, old, publicData, mode, home, now(), random);
  const account = current.state.account;
  await http("POST", `${apiRoot(base)}/id/${account}/instance`, { events: current.log, instance: ni.event, vault: ni.vault, public: ni.public });
  const v = await http("GET", `${apiRoot(base)}/id/${account}/log`);
  const state = await rc.verifyLog(v.events, { realms: [current.state.realm], now: now() });
  const oldHome = current.state.instance?.home.url;
  let note = "";
  if (oldHome && oldHome !== base) {
    try {
      await http("POST", `${apiRoot(oldHome)}/id/${account}/events`, { events: v.events.slice(current.log.length) });
    } catch (e) {
      note = `\nCould not tell the previous primary host: ${explain(e)}`;
    }
  }
  current.log = v.events;
  current.state = state;
  current.vault = ni.vault;
  current.public = ni.public;
  download(rc.accountFileName(state), rc.exportAccount(state, v.events, ni.public, ni.vault));
  return describe(state) + "\n\nThe new account file was downloaded." + note;
}

function refreshSlots(info) {
  $("slot").replaceChildren(...info.slots.map((s) => new Option(`${s.label} (${s.id})`, s.id)));
}

async function challengeOf(text) {
  const t = text.trim();
  if (/^[0-9a-fA-F]{64}$/.test(t)) return rc.hexDecode(t);
  return rc.statementChallenge(rc.parseJson(t));
}

const ops = {
  async restore() {
    const { u } = await currentVault();
    return submitInstance(checkHost($("targetHost").value.trim()), { restore: true }, u);
  },
  async fresh() {
    return submitInstance(checkHost($("targetHost").value.trim()), { fresh: newSlot() }, undefined);
  },
  async reset() {
    const { u } = await currentVault();
    return submitInstance(current.state.instance.home.url, { reset: newSlot() }, u);
  },
  async revoke() {
    const { u } = await currentVault();
    const id = $("slot").value;
    if (!id) throw new Error("Choose a password to revoke.");
    return submitInstance(current.state.instance.home.url, { revoke: [id] }, u);
  },
  async add() {
    const { vault, u } = await currentVault();
    const v = await rc.addSlot(u, vault, current.keys, newSlot(), random);
    await http("PUT", `${apiRoot(current.state.instance.home.url)}/id/${current.state.account}/vault`, { vault: v });
    current.vault = v;
    const info = await rc.verifyVault(v, current.state);
    refreshSlots(info);
    return "Passwords:\n" + info.slots.map((s) => `  ${s.label} (${s.id})`).join("\n");
  },
  async rotate() {
    const { vault, u } = await currentVault();
    const newKey = random(32);
    const r = await rc.rotateRecovery(current.state, current.log, current.keys, newKey, vault, u, now(), random);
    newKey.fill(0);
    // The new card is saved and shown before the rotation is sent: once the host has the event, the old key no longer
    // signs and the new card is the only copy of the new key ([KT-5]).
    download(`${current.state.username}-new.card.json`, r.card);
    const text = await rc.cardText(r.card);
    show(text + "\nSending the rotation… Keep this card.", true);
    try {
      await http("POST", `${apiRoot(current.state.instance.home.url)}/id/${current.state.account}/events`, { events: [r.event], vault: r.vault });
    } catch (e) {
      throw new Error(
        `${explain(e)}\n\nThe rotation may or may not have reached the primary host. Keep both cards: the new card ` +
          `below (also downloaded) and the old one. Load the identity with the old card: if it answers that the ` +
          `recovery key is not the current one, the rotation arrived and the new card is current.\n\n${text}`,
      );
    }
    current = null;
    $("actions").hidden = true;
    return text + "\nThe new card was downloaded. Destroy the old card, then load the new one.";
  },
  async retire() {
    if ($("retireConfirm").value !== current.state.username) throw new Error("Type the username to confirm.");
    const ev = await rc.retireEvent(current.state, current.keys.signSeed, now());
    const base = current.state.instance?.home.url ?? hostList()[0];
    if (!base) throw new Error("Enter a host.");
    await http("POST", `${apiRoot(base)}/id/${current.state.account}/events`, { events: [ev] });
    return `${current.state.handle} is retired.`;
  },
  async card() {
    return rc.cardText(current.card);
  },
  async prove() {
    const p = await rc.prove(current.state, "recovery", current.keys.signSeed, await challengeOf($("proofStatement").value), $("proofRecipient").value);
    return rc.canonicalString(p);
  },
};

$("version").textContent = ROOTCARD_VERSION;
$("load").addEventListener("click", () =>
  run(async () => {
    const notes = await gather();
    $("actions").hidden = false;
    let extra = "";
    try {
      const { u } = await currentVault();
      refreshSlots(u.info);
    } catch (e) {
      extra = `\n(Vault not available: ${explain(e)})`;
    }
    return describe(current.state) + extra + (notes.length ? "\n\n" + notes.join("\n") : "");
  }),
);
for (const b of document.querySelectorAll("[data-op]")) {
  b.addEventListener("click", () => run(() => (current ? ops[b.dataset.op]() : Promise.reject(new Error("Load the identity first.")))));
}
$("create").addEventListener("click", () =>
  run(async () => {
    const realm = $("nRealm").value.trim();
    const username = $("nUser").value.trim();
    const rk = random(32);
    const base = $("nHost").value.trim();
    let card;
    let file;
    let state;
    if (base) {
      const home = await hostHome(checkHost(base));
      const reg = await rc.register(rk, realm, username, $("nPassword").value, "Password", home, now(), rc.KDF_DEFAULT, random);
      rk.fill(0);
      // The card is saved before anything is sent: once the host has the identity, the card is the only copy of its
      // recovery key ([CLT-1]).
      download(`${username}-${rc.tag(reg.account)}.card.json`, reg.card);
      await http("POST", `${apiRoot(home.url)}/id/register`, { log: reg.log, vault: reg.vault, public: reg.public });
      const v = await http("GET", `${apiRoot(home.url)}/id/${reg.account}/log`);
      state = await rc.verifyLog(v.events, { realms: [realm], now: now() });
      card = reg.card;
      file = rc.exportAccount(state, v.events, reg.public, reg.vault);
    } else {
      const keys = await rc.deriveRecoveryKeys(rk, realm, username);
      const inc = await rc.inception(keys, realm, username);
      state = await rc.verifyLog([inc], { realms: [realm] });
      card = await rc.recoveryCard(realm, username, state.account, rk);
      file = rc.exportAccount(state, [inc]);
    }
    rk.fill(0);
    if (!base) download(`${username}-${rc.tag(state.account)}.card.json`, card);
    download(rc.accountFileName(state), file);
    return (await rc.cardText(card)) + "\n" + describe(state) + "\n\nThe card and the account file were downloaded. Keep the card offline.";
  }),
);
$("verify").addEventListener("click", () =>
  run(async () => {
    const v = rc.parseJson($("vLog").value);
    const log = Array.isArray(v) ? v : v.log;
    const realm = log?.[0]?.body?.realm;
    const st = await rc.verifyProof(rc.parseJson($("vProof").value), log, await challengeOf($("vStatement").value), $("vRecipient").value, { realms: [realm], now: now() });
    return `Valid proof by ${st.handle}\n\n` + describe(st);
  }),
);
