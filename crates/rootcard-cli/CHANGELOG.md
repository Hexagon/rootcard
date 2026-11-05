# Changelog: rootcard-cli

All notable changes to this package are recorded here.

## Unreleased

## 0.2.0 - 2026-11-05

- License: MIT OR Apache-2.0, at the user's option (0.1.0 was MIT only). The package now ships `LICENSE-MIT` and
  `LICENSE-APACHE`.
- **Breaking (HTTP binding):** the key tool calls hosts under `<base URL>/v0` (HOST_PROTOCOL.md §1.3). Host addresses
  are given and stored without the version segment, as before.
- Every host address given to the tool, or read from a log, is checked as a base URL before use ([HST-22]); an address
  ending in `/v0` or with a trailing slash is refused with a hint.
- README points to the project README.

## 0.1.0 - 2026-11-04

- First release of the key tool `rootcard`: `new`, `restore`, `fresh`, `reset-password`, `add-password`,
  `revoke-password`, `rotate-recovery`, `retire`, `card`, `inspect`, `prove`, `verify`.
- Gathers the newest log from the card, the account file and the hosts before signing, and stops on a fork.
