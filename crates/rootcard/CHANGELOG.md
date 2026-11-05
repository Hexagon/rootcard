# Changelog: rootcard

All notable changes to this package are recorded here.

## Unreleased

- **Breaking:** every function that creates a password lock enforces the password rules of SPEC [LCK-8]
  (`weak_password`), not only `register`: `new_password_lock` (and so `add_slot`, `instance_vault`, `new_instance`)
  and `change_password`. `NewSlot` has a new field `username`, and `change_password` a new parameter `username` after
  `password`. `new_instance` refuses a slot whose `username` is not the identity's (`bad_field`). New vectors in
  `spec/vectors/vault.json`.
- **Breaking:** `check_base_url` ([HST-22]) refuses path segments that are `.` or `..` or contain anything other than
  unreserved characters (`A`–`Z`, `a`–`z`, `0`–`9`, `-`, `.`, `_`, `~`), so a base URL has no percent-encoding and
  cannot reach a version segment after normalization (`https://example.com/v0/..`, `https://example.com/%76%30`). New
  vectors in `spec/vectors/proof.json`. No format change: log verification is unchanged.

## 0.2.1 - 2026-11-05

No changes.

## 0.2.0 - 2026-11-05

- License: MIT OR Apache-2.0, at the user's option (0.1.0 was MIT only). The package now ships `LICENSE-MIT` and
  `LICENSE-APACHE`.
- `API_VERSION` (`"v0"`), the version segment of the HTTP binding, and `check_base_url` / `binding::is_version_segment`:
  host addresses are base URLs without a trailing version segment (SPEC [HST-22]), with shared vectors in
  `spec/vectors/proof.json` and the API version in `meta.json`. No format change: log verification is unchanged.
- README points to the project README.

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
