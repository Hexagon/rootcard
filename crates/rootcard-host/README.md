# rootcard-host

Helpers for hosts (servers) that store [rootcard](https://github.com/Hexagon/rootcard) identities and accept their
logins (SPEC §17). A library, not a server: the handlers are plain functions over three storage traits, so a host can
run on any number of servers in front of one shared store and with any HTTP framework.

- `Host::register`, `instance`, `events`, `lookup`, `log`, `locks`, `challenge`, `fetch`, `login`, the session endpoints
  and `peer_push` implement the rules of SPEC §17: receipts, idempotent retries, fork and staleness answers, address
  binding, sessions bound to an instance and checked on every use, compare-and-swap updates.
- `store::{IdentityStore, ChallengeStore, SessionStore}` with in-memory implementations for tests and development.
- `http::route` maps the recommended HTTP binding (`docs/HOST_PROTOCOL.md`) onto the handlers: a request in, a response
  out. `examples/host.rs` in the repository wires it to `std::net` for local development.

It builds on the core without its `vault` feature: a host never runs Argon2id, never sees a password and never decrypts a
vault. Time and random bytes are parameters, as in the core.

```rust
let res = rootcard_host::http::route(&host, &request, now, &mut |b| getrandom::fill(b).expect("random"));
```
