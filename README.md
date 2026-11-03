# rootcard

**A portable, self-certifying identity for online logins — an ID card you own.**

> Status: **planning.** Nothing is published yet. See [docs/PLAN.md](docs/PLAN.md).

rootcard gives a user an identity that no server owns:

- **Self-certifying id.** The account id is a hash of a signed inception that names the recovery key. It cannot be forged
  without breaking SHA-256 or Ed25519 or stealing a private key. Shown to humans as `Name#XXXX`.
- **No password verifiers on servers.** The password only unlocks an encrypted vault on the client. Login is a fresh
  challenge signed by the account key, bound to the host, the realm and the current version.
- **Two power levels.** The password gives *low power* (log in, edit your data, export). Everything that changes who can
  access the account, where it lives or whether it exists needs the **recovery key**, kept offline.
- **The recovery key is the root.** It can always mint a fresh, complete instance of the account, even if every host and
  backup is gone.
- **One latest version.** Versions are totally ordered. Anyone who has seen a newer verified version rejects the old one.
- **Arbitrary data.** A signed public profile and private data inside the vault, with per-application namespaces.
- **Realms.** An identity is bound to a realm string (an app, a world, or `global`).

## Packages (planned)

| Registry | Package | What |
|---|---|---|
| crates.io | `rootcard` | Core library: formats, verification, vault, proofs. Pure, no I/O |
| crates.io | `rootcard-cli` | The key tool (`rootcard` binary): recovery-key operations |
| crates.io | `rootcard-host` | Helpers for hosts (servers): challenges, stores, HTTP-agnostic handlers |
| npm | `rootcard` | The same core in plain ES modules, zero dependencies, browser and Node (WebCrypto) |

The specification in [`spec/`](spec/) and its test vectors are the source of truth. Rust and JavaScript must produce the same
bytes for the same inputs.

## Origin

rootcard is extracted from the account design of the game Xigna. The original design (Swedish) is kept for reference in
[docs/origin/xigna-IDENTITY.sv.md](docs/origin/xigna-IDENTITY.sv.md).
