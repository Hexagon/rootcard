# Changelog: rootcard (npm)

All notable changes to this package are recorded here.

## Unreleased

- License: MIT OR Apache-2.0, at the user's option (0.1.0 was MIT only). The package now ships `LICENSE-MIT` and
  `LICENSE-APACHE`.
- **Breaking (HTTP binding):** `keytool.html` calls hosts under `<base URL>/v0` (HOST_PROTOCOL.md §1.3). The core
  library makes no requests and is unchanged.
- `API_VERSION` (`"v0"`), `checkBaseUrl` and `isVersionSegment`, equal to the Rust crate's ([HST-22], shared vectors).
- `keytool.html` checks every host address as a base URL; a trailing slash is still removed from typed addresses.
- README points to the project README.

## 0.1.0 - 2026-11-04

- First release of the JavaScript implementation of format version 1, byte for byte equal to the Rust crate on every
  shared vector. Zero dependencies; WebCrypto for Ed25519, X25519, SHA-256, HKDF and AES-GCM; its own BLAKE2b and
  Argon2id (RFC 9106).
- `rootcard`: verification (JSON, encodings, keys, recovery keys, identities, logs, vault and profile checks,
  messages, proofs, account files, cards). `rootcard/vault`: password locks, vault encryption, registration, password
  change, new instances and rotation. `rootcard/testing`: the deterministic stream of the vectors.
- `keytool.html`: the standalone key tool page, works from `file://`.
