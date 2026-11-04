# rootcard: setup plan

This is the plan for agents that set up the monorepo and build the first release. Work through the phases in order. A
phase is done when every acceptance criterion is checked, with tests where possible. Record deviations under the phase.

**Current phase: 2 (primitives in both languages).** Phases 0 and 1 are done.

Design: [docs/DESIGN.md](DESIGN.md). It started in the Xigna game and is application-neutral here (labels `rootcard/...`,
`realm`, *host*). Xigna's own integration plan lives in the Xigna repository.

---

## Decisions needed from the owner (before phase 6)

| # | Question | Proposal |
|---|---|---|
| D1 | License | ✅ **MIT** (decided) |
| D2 | Reserve the names now with placeholder releases? | Yes: `rootcard`, `rootcard-cli`, `rootcard-host` on crates.io and `rootcard` on npm, version `0.0.0`, published by the owner |
| D3 | npm scope as well (`@rootcard/*`)? | Create the `rootcard` org on npm to block look-alikes, publish the main package unscoped |
| D4 | Minimum supported Rust version | Latest stable minus two releases, checked in CI |
| D5 | Minimum browsers | Those with WebCrypto `Ed25519` and `X25519`. No weaker fallback |
| D6 | Security contact and disclosure policy | `SECURITY.md` with a private advisory address on GitHub |
| D7 | Unicode dependency for passwords (NFC) | ✅ **`unicode-normalization`** in Rust, behind the core's `vault` feature so hosts do not build it; JS uses `String.prototype.normalize` (decided) |
| D8 | Scope of v1 | ✅ **Good for servers first** (decided): hosts are simple, multi-server safe and need no password handling; forks are detected, not resolved, and fork resolution waits for a later format version |

---

## Phase 0: repository skeleton ✅

- [x] `Cargo.toml` workspace with `crates/rootcard`, `crates/rootcard-cli`, `crates/rootcard-host`, `crates/xtask`
  (`resolver = "3"`, edition 2024, shared `[workspace.package]`: version, license, repository, rust-version)
- [x] `[workspace.lints]`: `unsafe_code = "forbid"`, `clippy::unwrap_used = "deny"`, `missing_docs = "warn"` for the libraries
- [x] `rustfmt.toml` (`max_width = 120`), `deny.toml` for `cargo deny`
- [x] `packages/rootcard/package.json`: `"type": "module"`, `exports` map (`.`, `./keytool`), `"files"` whitelist,
  `"sideEffects": false`, `engines.node >= 20`, no dependencies, `"test": "node --test"`
- [x] `spec/SPEC.md` (stub), `spec/vectors/` (empty), `CHANGELOG.md` per package, `SECURITY.md` (placeholder)
- [x] CI (`.github/workflows/ci.yml`): fmt, clippy, test on Linux, macOS and Windows, MSRV, `cargo deny`, npm test on Node 20
  and 22, and a job that runs the JS tests against the Rust-generated vectors
- [x] Every crate and the npm package builds and tests green with empty modules

**Acceptance:** a fresh clone passes all commands in AGENTS.md, and CI is green.
- [x] All commands pass locally (stable 1.97 and MSRV 1.95, Node 22, `cargo deny check`)
- [ ] CI green on GitHub (first run on the phase-0 pull request)

**Deviations**
- The `./keytool` export is left out of `package.json` until the page exists (phase 5).
- The license is MIT (D1). The published crates and the npm package carry `license = "MIT"`, and `LICENSE` is included in
  the npm tarball. `xtask` stays `publish = false`. Nothing is published before the release workflow (phase 6), except
  the placeholder releases the owner may make for D2.
- MSRV (D4) is set to 1.95, the stable release two versions back at the time of writing.
- The parity mechanism is in place from the start: `xtask vectors` writes `spec/vectors/meta.json` (format version and labels),
  and the JS tests read it. Every later phase adds its vectors the same way.

## Phase 1: specification and threat model ✅

- [x] `spec/SPEC.md`: turn DESIGN.md into a normative, application-neutral specification (MUST/SHOULD):
  canonical JSON, base32 and the recovery-key format, inception and id, handle and extended tags, log events (`incept`,
  `instance`, `rotate_recovery`, `retire`), versions, the vault and locks, the public profile and
  namespaces, login, receipts and proofs, the account file and the recovery card, size limits, error codes
- [x] `docs/THREAT_MODEL.md`: the threat table, the secure-and-feasible decisions and the accepted risks from DESIGN.md §2 and §10,
  expanded (attacker capabilities, assets, trust boundaries)
- [x] `docs/HOST_PROTOCOL.md`: the HTTP endpoints as a recommended (not required) binding

**Acceptance:** the spec can be implemented without reading DESIGN.md, and every rule has a number that tests can
refer to.
- [x] Every normative rule has a stable identifier (`[LOG-12]`) and names its error code; algorithms are numbered steps
  checked in order, so reject vectors can require the same code from both implementations (SPEC [CNV-3])
- [x] The label registry (SPEC §5) is checked against `spec/vectors/meta.json` by both test suites and by `xtask vectors`

**Deviations**
- The spec changes the design where it was ambiguous or unsafe; SPEC Appendix B lists every change. The ones that matter
  most for later phases:
  - every hashed or signed input is `label ‖ 0x00 ‖ canonical JSON` (login and proof messages are JSON objects);
  - the vault is released only after a **lock proof** (`rootcard/fetch/v1`, signed by a per-lock `auth` key derived from the
    same Argon2id output), because the design's public `GET /id/<account>/vault` allowed offline guessing by anyone;
  - the **lock set is signed by the recovery key** with a generation counter, because the design let the account key (low
    power) sign locks;
  - recovery key derivation is bound to realm and username, so identities from one key are unlinkable;
  - versions are ordered by extension only; forks are detected (`fork`) and not resolved in v1 (D8, SPEC Appendix A);
  - hosts can rotate keys and change addresses without new instances, login and fetch messages are bound to the address
    the client uses, sessions are checked against the current instance on every use, storage updates are
    compare-and-swap and retries are idempotent (SPEC [HST-17]–[HST-21]); handles are unique per realm;
  - vault and profile revisions are `rev`; "version" means only the log version.
- Phase 2 needs Unicode NFC for passwords (SPEC [LCK-7]): `unicode-normalization` in Rust (D7), only with the `vault`
  feature. The dependency budget per package is in [ARCHITECTURE.md](ARCHITECTURE.md) §5.
- Phase 2's JS `crypto.js` must perform the strict Ed25519 pre-checks itself (SPEC [CRY-3] steps 1–4), since WebCrypto
  verifiers differ on them.

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
- [ ] Events, `verify_log` (including self-signature of every new public key), `extend_log` (incremental, equal to
  `verify_log` on the whole log), `verify_pending`, current instance, `compare_logs` (extension, fork)
- [ ] Reject cases: wrong `prev`, wrong signer, wrong realm, future time, after `retire`, forged inception, tag collision
- [ ] Vectors: `spec/vectors/log.json`

**Acceptance:** both languages accept and reject exactly the same logs with the same error codes, and compare the same
logs the same way.

## Phase 4: vault, public profile, login and proofs

- [ ] Vault: create, unlock with a password or the recovery key, add a lock, revoke (new instance, rewrap to remaining
  locks by their public keys), `restore` and `fresh` instances, private data, recovery-signed lock sets (`gen`), lock
  `auth` keys and fetch messages
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
- [ ] `rootcard-host` (design in [ARCHITECTURE.md](ARCHITECTURE.md) §3): `ChallengeStore` (atomic take, 60 s),
  `IdentityStore` with compare-and-swap and an in-memory implementation, stored log states with `extend_log`, host keys
  with retired keys, accepted addresses, `stale_version` and `fork`, idempotent retries, `LoginResult` and
  `session_valid` (sessions bound to an instance), handlers independent of any HTTP framework, built on the core without
  the `vault` feature
- [ ] A documented SQL schema for the store, and a concurrency test: two handlers on one store racing the same update
- [ ] An example host (`examples/host`, axum) and an end-to-end test: register, log in, export, new instance on a second host,
  the first host answers `not_home`; a host key rotation and an address change with existing identities logging in

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
- Witnesses and pre-rotation (`v: 2`) against a stolen recovery key, together with deterministic fork resolution (SPEC
  Appendix A)
- Host helpers for JavaScript servers (`rootcard/host`), if there is demand; the JS core already verifies everything a
  host checks
- Post-quantum key types (ML-DSA, ML-KEM) by new type tags
- Federation of public logs between hosts
- First application: Xigna (its integration plan is in the Xigna repository)
