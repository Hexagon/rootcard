// SPEC [IMP-6]: on a platform that cannot import some Ed25519 seeds (WebKit refuses a pkcs8 seed whose first byte is
// zero), an identity whose keys are such seeds still logs in, signs its profile and vault, proves, adds a password,
// starts a new instance and rotates its recovery key, because each of those seeds is checked against a public key on
// record first. Node imports every seed, so this test makes WebCrypto refuse the pkcs8 import of a chosen set of seeds
// (the existing identity's own), the way WebKit refuses zero-led ones. New seeds import as usual, as in WebKit for
// seeds made under [CRY-9].
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as rc from "../src/index.js";
import * as vault from "../src/vault-index.js";
import { testRandom } from "../src/testing.js";
import { base64urlEncode, hexEncode } from "../src/encoding.js";

const sha256Sync = (m) => new Uint8Array(createHash("sha256").update(m).digest());
const PASSWORD = "correct horse battery staple";
const T0 = 1_800_000_000;
const ED_PKCS8_PREFIX = "302e020100300506032b657004220420";

const subtle = Object.getPrototypeOf(globalThis.crypto.subtle);
const realImport = subtle.importKey;
const blocked = new Set();
function refuseSeeds(seeds) {
  for (const x of seeds) blocked.add(hexEncode(x));
  subtle.importKey = function (format, data, alg, ...rest) {
    if (format === "pkcs8" && (alg?.name ?? alg) === "Ed25519") {
      const der = hexEncode(new Uint8Array(data.buffer ?? data, data.byteOffset ?? 0, data.byteLength));
      if (der.startsWith(ED_PKCS8_PREFIX) && blocked.has(der.slice(ED_PKCS8_PREFIX.length))) {
        return Promise.reject(new DOMException("Data provided to an operation does not meet requirements", "DataError"));
      }
    }
    return realImport.call(this, format, data, alg, ...rest);
  };
}
function restore() {
  subtle.importKey = realImport;
  blocked.clear();
}

async function setUp() {
  const random = testRandom(new TextEncoder().encode("imp6"), sha256Sync);
  const rk = await rc.newRecoveryKey("global", "Astra", random);
  const hostSeed = random(32);
  const home = { key: rc.formatKey("ed25519", await rc.ed25519Public(hostSeed)), url: "https://a.example" };
  const reg = await vault.register(rk, "global", "Astra", PASSWORD, "Laptop", home, T0, rc.KDF_MIN, random);
  await rc.addReceipt(reg.log[1], hostSeed); // the host accepts the registration ([LOG-8])
  const state = await rc.verifyLog(reg.log, { realms: ["global"] });
  const slot = (await rc.verifyVault(reg.vault, state)).slots[0].id;
  const keys = await rc.deriveRecoveryKeys(rk, "global", "Astra");
  const u = await vault.unlockVault(reg.vault, state, { lock: slot, password: PASSWORD });
  // The platform can no longer import this identity's account seed, lock seed or recovery signing seed.
  refuseSeeds([u.contents.accountSeed, u.lockSeed, keys.signSeed]);
  return { random, rk, home, hostSeed, reg, state, slot };
}

test("[IMP-6] the platform refuses the identity's seeds, so nothing can compute their public keys", async () => {
  try {
    const { rk } = await setUp();
    const keys = await rc.deriveRecoveryKeys(rk, "global", "Astra");
    await assert.rejects(rc.ed25519Public(keys.signSeed), (e) => e.name === "DataError");
    await assert.rejects(rc.ed25519Sign(keys.signSeed, new Uint8Array(1)), (e) => e.name === "DataError");
  } finally {
    restore();
  }
});

test("[IMP-6] login, profile, proof and vault work with seeds checked against keys on record", async () => {
  try {
    const { random, reg, state, slot, home } = await setUp();
    const u = await vault.unlockVault(reg.vault, state, { lock: slot, password: PASSWORD });
    const info = await rc.verifyVault(reg.vault, state);
    const auth = info.locks.find((l) => l.id === slot).value.auth;

    const challenge = { nonce: base64urlEncode(random(32)), host: home.key, realm: "global", version: state.version, expires: T0 + 60 };
    const login = await rc.signLogin(state, challenge, "https://app.example", slot, u.contents.accountSeed, u.lockSeed);
    await rc.verifyLogin(login, "global", home.key, state.instance.account_key, auth);

    const profile = await rc.signPublic(state.account, state.instance.hash, 2, { "app.test.x": 1 }, u.contents.accountSeed);
    await rc.verifyPublic(profile, state);

    const ch = random(32);
    const proof = await rc.prove(state, "account", u.contents.accountSeed, ch, "https://app.example");
    await rc.verifyProof(proof, reg.log, ch, "https://app.example", { realms: ["global"] });

    const changed = await vault.updateContents(u, reg.vault, { ...u.contents, data: { "app.test.y": 2 } }, random);
    await rc.verifyVault(changed, state);
  } finally {
    restore();
  }
});

test("[IMP-6] the recovery key proves, adds a password, starts an instance and rotates", async () => {
  try {
    const { random, rk, reg, state, home, hostSeed } = await setUp();
    const keys = await rc.deriveRecoveryKeys(rk, "global", "Astra");
    const ch = random(32);
    const proof = await rc.prove(state, "recovery", keys.signSeed, ch, "https://app.example");
    await rc.verifyProof(proof, reg.log, ch, "https://app.example", { realms: ["global"] });

    const ur = await vault.unlockVault(reg.vault, state, { recovery: keys });
    const added = await vault.addSlot(ur, reg.vault, keys, { label: "Phone", password: "another passphrase", username: "Astra", kdf: rc.KDF_MIN }, random);
    assert.equal((await rc.verifyVault(added, state)).slots.length, 2);

    const ni = await vault.newInstance(state, keys, ur, {}, { restore: true }, home, T0 + 10, random);
    await rc.addReceipt(ni.event, hostSeed);
    await rc.verifyLog([...reg.log, ni.event], { realms: ["global"] });

    const newKey = await rc.newRecoveryKey("global", "Astra", random);
    const rot = await vault.rotateRecovery(state, reg.log, keys, newKey, reg.vault, ur, T0 + 20, random);
    await rc.verifyLog([...reg.log, rot.event], { realms: ["global"] });
  } finally {
    restore();
  }
});

test("[IMP-6] a key on record that is not the seed's is refused, not used", async () => {
  try {
    const { rk, state } = await setUp();
    const other = await rc.deriveRecoveryKeys(new Uint8Array(32).fill(7), "global", "Astra");
    await assert.rejects(rc.prove(state, "recovery", other.signSeed, new Uint8Array(32), "https://app.example"), { code: "wrong_recovery_key" });
    const keys = await rc.deriveRecoveryKeys(rk, "global", "Astra");
    const wrong = { ...state, recovery: rc.formatKey("ed25519", await rc.ed25519Public(other.signSeed)) };
    assert.equal(await rc.ed25519PublicIs(keys.signSeed, rc.parseKey(wrong.recovery, "ed25519")), false);
    await assert.rejects(rc.ed25519Sign(keys.signSeed, new Uint8Array(1)), (e) => e.name === "DataError");
  } finally {
    restore();
  }
});
