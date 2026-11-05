# Changelog: rootcard

All notable changes to this package are recorded here.

## Unreleased

- License: MIT OR Apache-2.0, at the user's option (0.1.0 was MIT only). The package now ships `LICENSE-MIT` and
  `LICENSE-APACHE`.

## 0.1.0 - 2026-11-04

- First release of the core, implementing format version 1 of `spec/SPEC.md` (no format change: everything is `v: 1`).
- Canonical JSON (`parse_json`, `parse_limited`, `canonical`), unpadded base64url, Crockford base32, key strings.
- Strict Ed25519 verification with the pre-checks of [CRY-3] (canonical points, no small order, `S < L`, cofactorless).
- Recovery keys: written form, parsing, derivation of the signing and lock keys.
- Identities: deterministic inception, account id, handles, `parse_handle`, `extended_tags`, realm and username rules.
- The identity log: `verify_log`, `extend_log`, `verify_pending`, `compare_logs`, event builders and receipts.
- Vaults: `verify_vault` and `vault_change` (always); with the default `vault` feature, password locks (Argon2id,
  NFC), wrapping, contents, `unlock_vault`, `change_password`, `add_slot`, `regrant`, `instance_vault`.
- Public profiles and data keys, login, fetch and change messages, challenges, proofs and statement challenges,
  account files and recovery cards.
- High-level flows (`account`, feature `vault`): `register`, `new_instance`, `rotate_recovery`.
- `testing::TestRandom`, the deterministic stream the shared vectors are generated with.
