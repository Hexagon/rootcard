# rootcard: setup plan

This is the plan for agents that set up the monorepo and build the first release. Work through the phases in order. A
phase is done when every acceptance criterion is checked, with tests where possible. Record deviations under the phase.

**Current phase: 0 (repository skeleton).**

Source design: [docs/origin/xigna-IDENTITY.sv.md](origin/xigna-IDENTITY.sv.md) (Swedish, from the Xigna game). It uses
the working labels `xid/...` and Xigna-specific wording (world seed, primary server). In rootcard these become
`rootcard/...`, `realm` and *host*.

---

## Decisions needed from the owner (before phase 6)

| # | Question | Proposal |
|---|---|---|
| D1 | License | `MIT OR Apache-2.0` (the Rust ecosystem default, also fine for npm) |
| D2 | Reserve the names now with placeholder releases? | Yes: `rootcard`, `rootcard-cli`, `rootcard-host` on crates.io and `rootcard` on npm, version `0.0.0`, published by the owner |
| D3 | npm scope as well (`@rootcard/*`)? | Create the `rootcard` org on npm to block look-alikes, publish the main package unscoped |
| D4 | Minimum supported Rust version | Latest stable minus two releases, checked in CI |
| D5 | Minimum browsers | Those with WebCrypto `Ed25519` and `X25519`. No weaker fallback |
| D6 | Security contact and disclosure policy | `SECURITY.md` with a private advisory address on GitHub |

---

## Phase 0: repository skeleton

- [ ] `Cargo.toml` workspace with `crates/rootcard`, `crates/rootcard-cli`, `crates/rootcard-host`, `crates/xtask`
  (`resolver = "3"`, edition 2024, shared `[workspace.package]`: version, license, repository, rust-version)
- [ ] `[workspace.lints]`: `unsafe_code = "forbid"`, `clippy::unwrap_used = "deny"`, `missing_docs = "warn"` for the libraries
- [ ] `rustfmt.toml` (`max_width = 120`), `deny.toml` for `cargo deny`
- [ ] `packages/rootcard/package.json`: `"type": "module"`, `exports` map (`.`, `./keytool`), `"files"` whitelist,
  `"sideEffects": false`, `engines.node >= 20`, no dependencies, `"test": "node --test"`
- [ ] `spec/SPEC.md` (stub), `spec/vectors/` (empty), `CHANGELOG.md` per package, `SECURITY.md` (placeholder)
- [ ] CI (`.github/workflows/ci.yml`): fmt, clippy, test on Linux, macOS and Windows, MSRV, `cargo deny`, npm test on Node 20
  and 22, and a job that runs the JS tests against the Rust-generated vectors
- [ ] Every crate and the npm package builds and tests green with empty modules

**Acceptance:** a fresh clone passes all commands in AGENTS.md, and CI is green.

## Phase 1: specification and threat model

- [ ] `spec/SPEC.md`: port the origin design into a normative, application-neutral specification (MUST/SHOULD):
  canonical JSON, base32 and the recovery-key format, inception and id, handle and extended tags, log events (`incept`,
  `instance`, `rotate_recovery`, `retire`), the total order of versions, the vault and locks, the public profile and
  namespaces, login, receipts and proofs, the account file and the recovery card, size limits, error codes
- [ ] Every label renamed to `rootcard/<purpose>/v1`. `world` becomes `realm`. "Server" becomes *host*
- [ ] `docs/THREAT_MODEL.md`: the threat table, the secure-and-feasible decisions and the accepted risks from the origin
  design, rewritten for a generic host
- [ ] `docs/HOST_PROTOCOL.md`: the HTTP endpoints as a recommended (not required) binding

**Acceptance:** the spec can be implemented without reading the origin document, and every rule has a number that tests can
refer to.

## Phase 2: primitives in both languages

- [ ] Rust: `canon`, `base32` (Crockford + checksum), thin wrappers over the crypto crates with strict verification
- [ ] JS: `canon.js`, `base32.js`, `crypto.js` (WebCrypto wrappers), `blake2b.js`, `argon2.js`
- [ ] `xtask vectors`: generates `spec/vectors/primitives.json`. Both suites check it. RFC 8032, RFC 7748, RFC 5869 and RFC
  9106 vectors pass in both languages
- [ ] JS Argon2id benchmark (`m = 64 MiB, t = 3`) recorded in the PR: Node, desktop browser, a mid-range phone

**Acceptance:** identical bytes for every vector in both languages. Argon2id in JS within about 3 s on a mid-range phone, or
a documented parameter change in the spec.

## Phase 3: identity log and versions

- [ ] Deterministic inception from recovery key + username + realm, account id, handle, extended tags
- [ ] Events, `verify_log` (including self-signature of every new public key), current instance, `newer` (total order)
- [ ] Reject cases: wrong `prev`, wrong signer, wrong realm, future time, after `retire`, forged inception, tag collision
- [ ] Vectors: `spec/vectors/log.json`

**Acceptance:** both languages accept and reject exactly the same logs, and order the same versions the same way.

## Phase 4: vault, public profile, login and proofs

- [ ] Vault: create, unlock with a password or the recovery key, add a lock, revoke (new instance, rewrap to remaining
  locks by their public keys), `restore` and `fresh` instances, private data
- [ ] Public profile: key and value rules, namespaces, versions, signing
- [ ] Login message, receipts, proofs (`prove`, `verify_proof`), account file and recovery card (text and QR payload)
- [ ] Power-level tests: nothing reachable with the account key can change the log or the locks
- [ ] Vectors: `spec/vectors/vault.json`, `profile.json`, `proof.json`, `file.json`

**Acceptance:** an account created in JS is unlocked, revoked and re-instanced in Rust and the other way round.

## Phase 5: key tool and host helpers

- [ ] `rootcard-cli`: `new`, `card`, `add-password`, `revoke-password`, `restore`, `fresh`, `rotate-recovery`, `retire`,
  `inspect`, `verify`, `prove`. Reads and writes account files and cards, talks to a host only when asked
- [ ] `packages/rootcard/keytool.html`: the same operations as one standalone page with no network access unless the user picks
  a host. Works from `file://`
- [ ] `rootcard-host`: `ChallengeStore` (single use, 60 s), `IdentityStore` trait with an in-memory implementation, version
  handling (`stale_version`, sessions bound to an instance), handlers independent of any HTTP framework
- [ ] An example host (`examples/host`, axum) and an end-to-end test: register, log in, export, new instance on a second host,
  the first host answers `not_home`

**Acceptance:** the full flow runs end to end in CI with two example hosts.

## Phase 6: hardening and release

- [ ] Fuzz targets for every parser and verifier, run in CI for a fixed time
- [ ] `cargo deny`, `cargo audit`, `npm audit` (empty tree), reproducible npm tarball check
- [ ] Release workflow: tag `vX.Y.Z` → crates published in dependency order with crates.io trusted publishing, npm published
  with trusted publishing and `--provenance`, GitHub release with checksums
- [ ] Documentation: crate docs, `README` per package, a "getting started" for apps and for hosts
- [ ] External review of the spec and the crypto use before `1.0.0`

**Acceptance:** `0.1.0` published on crates.io and npm from CI, with provenance, and the docs build on docs.rs.

## Later

- Passkeys (WebAuthn PRF) as a lock type
- Witnesses and pre-rotation (`v: 2`) against a stolen recovery key
- Post-quantum key types (ML-DSA, ML-KEM) by new type tags
- Federation of public logs between hosts
- Integration back into Xigna (`xg-identity` replaced by the `rootcard` crate and npm package)
