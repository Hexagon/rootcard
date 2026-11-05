# Changelog: rootcard-host

All notable changes to this package are recorded here.

## Unreleased

- License: MIT OR Apache-2.0, at the user's option (0.1.0 was MIT only). The package now ships `LICENSE-MIT` and
  `LICENSE-APACHE`.
- **Breaking (HTTP binding):** `http::route` serves every endpoint under the API version segment `/v0`
  (`<base URL>/v0/host`, `<base URL>/v0/id/…`, HOST_PROTOCOL.md §1.3) and answers paths without it, or with another
  version, with `404`. New constant `http::API_VERSION`. Peer request signatures cover the versioned path. Base URLs,
  `home.url` and every signed message are unchanged; no format change.

## 0.1.0 - 2026-11-04

- First release: the host rules of SPEC §17 as framework-independent handlers (registration, new instances, log
  propagation, lookup, lock hints, challenges, vault fetch, login, sessions, vault and profile updates, password
  change, export, peer pushes) over `IdentityStore`, `ChallengeStore` and `SessionStore`, with in-memory stores.
- `http::route`: the recommended HTTP binding of `docs/HOST_PROTOCOL.md`; `peer`: signed peer requests.
- Builds on the core without its `vault` feature.
