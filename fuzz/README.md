# Fuzz targets

`cargo fuzz` targets for the Rust parsers, verifiers and the host's router (AGENTS.md rule 7, PLAN.md phase 6). This
crate is its own workspace and is never published: it needs libFuzzer and a nightly toolchain, which the main workspace
must not.

| Target | Input | What it checks |
|---|---|---|
| `json` | bytes | Canonical JSON (SPEC §2): the parser never panics; an accepted value serializes canonically, parses back to itself and serializes to the same bytes |
| `text` | UTF-8 | base64url, base32 (strict and lenient), hex, typed recovery keys, `ed25519:`/`x25519:` keys, handles, account ids, realms, usernames, `home.url`, base URLs ([HST-22]), origins, data keys, app names and lock labels. Decoders that accept round-trip through their encoders |
| `log` | JSON | `verify_log`, `verify_pending`, `compare_logs`, `LogState::from_value`. An accepted log keeps the invariants of `check_accepted`: its prefixes are accepted, `extend_log` on a prefix gives the same state ([LOG-15]), the state survives its own serialization, and the log compares `same` with itself |
| `log_signed` | control byte + JSON | The same, behind the signatures: `resign` maps every key to one of eight known keys (equal keys stay equal) and, as the control byte asks, recomputes `account`, `prev` and the signatures (a receipt when the signer is the event's `home.key`). Mutated logs reach the checks on kinds, sequence, key reuse, reasons, receipts, rotations and retirement |
| `documents` | selector byte + JSON | `verify_public`, `verify_vault`, `vault_change`, `import_account`, `read_card` and `card_text`, `verify_proof`, `well_known_base` (the result is always on the origin and a valid base URL), statements, challenges, login requests and vault contents. The logs, challenges and recipients they are checked against come from the shared vectors |
| `host` | requests | `rootcard_host::http::route` with the in-memory stores and the vectors' host key: up to 16 requests per input, separated by `\n\0\n`, each a line `METHOD PATH [bearer=<token>] [peer=<key>,<time>,<sig>]` and a body. The state persists across the requests of one input. Every answer has a status of HOST_PROTOCOL.md and a canonical JSON body |

Every target asserts only what the spec promises: a panic is a finding.

## Running

```bash
cd fuzz
cargo run --bin seeds                                    # corpus/<target>/ from spec/vectors (not committed)
cargo +nightly fuzz run -O log_signed -- -max_total_time=300
cargo +nightly fuzz run -O log_signed artifacts/log_signed/crash-…   # reproduce a finding
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings   # stable is enough for these
```

`cargo install cargo-fuzz --version 0.13.2 --locked` installs the tool. CI (`fuzz` in `.github/workflows/ci.yml`) runs
every target for two minutes on each push and pull request, on the dated nightly named there, starting from the seeds,
and keeps a failing input as a build artifact.

The seed writer also checks itself: the re-signer must keep every accepted log of the vectors accepted, and it prints
the statuses of the host seeds (a registration answers `201`, pushed logs `200`), so a vector change that silently
empties a target is noticed.

## A finding

1. Reproduce it with the file from `artifacts/<target>/` and minimize it (`cargo fuzz tmin`).
2. If it is a bug in a core, fix both cores (AGENTS.md rule 2) and add a regression vector (rule 7), with the rule id.
3. If the assertion was wrong, fix the assertion and say why in the commit. The first run found one: `well_known_base`
   returns `https://example.cOm/rootcard` for the origin `https://example.com`, which [HST-23] allows (the host is
   compared without regard to ASCII case).

## Not covered here

- The JS core: `cargo fuzz` reaches only Rust. Differential fuzzing of `packages/rootcard` against the Rust core is a
  plan item.
- `unlock_vault` and the other functions that run Argon2id: one call takes about a second, too slow to fuzz. Their
  inputs are parsed by functions the targets cover (`verify_vault`, `Contents`).
- `cargo deny` and the MSRV job check the main workspace only. This crate adds `libfuzzer-sys`, `arbitrary`, `cc` and
  `jobserver` for testing; nothing from it is shipped.
