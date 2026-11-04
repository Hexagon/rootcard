# Changelog: rootcard (npm)

All notable changes to this package are recorded here.

## Unreleased

## 0.1.0 - 2026-11-04

- First release of the JavaScript implementation of format version 1, byte for byte equal to the Rust crate on every
  shared vector. Zero dependencies; WebCrypto for Ed25519, X25519, SHA-256, HKDF and AES-GCM; its own BLAKE2b and
  Argon2id (RFC 9106).
- `rootcard`: verification (JSON, encodings, keys, recovery keys, identities, logs, vault and profile checks,
  messages, proofs, account files, cards). `rootcard/vault`: password locks, vault encryption, registration, password
  change, new instances and rotation. `rootcard/testing`: the deterministic stream of the vectors.
- `keytool.html`: the standalone key tool page, works from `file://`.
