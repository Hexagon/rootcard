# Changelog: rootcard-host

All notable changes to this package are recorded here.

## Unreleased

## 0.1.0 - 2026-11-04

- First release: the host rules of SPEC §17 as framework-independent handlers (registration, new instances, log
  propagation, lookup, lock hints, challenges, vault fetch, login, sessions, vault and profile updates, password
  change, export, peer pushes) over `IdentityStore`, `ChallengeStore` and `SessionStore`, with in-memory stores.
- `http::route`: the recommended HTTP binding of `docs/HOST_PROTOCOL.md`; `peer`: signed peer requests.
- Builds on the core without its `vault` feature.
