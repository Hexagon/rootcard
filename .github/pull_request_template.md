## What and why

## Rules and format

<!-- The spec rule ids this touches ([LOG-12]). Does it change anything hashed or signed (a format change, SPEC §22)? -->

## Checklist

- [ ] Rust and JS changed together, with vectors (`xtask vectors --check` passes)
- [ ] Tests for the accept and the reject cases
- [ ] `CHANGELOG.md` (`## Unreleased`) of every changed package, and every document that describes the change
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, `xtask repo-check`, `npm test` pass
