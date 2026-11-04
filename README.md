# rootcard

**A portable, self-certifying identity for online logins — an ID card you own.**

> Status: **planning.** Nothing is published yet. See [docs/PLAN.md](docs/PLAN.md).

Accounts today are rows in someone else's database: the server owns your identity, stores a copy of your password secret,
and when it leaks or shuts down, you are gone. rootcard turns that around. Your identity is a **card you hold**: an
account id that only your own key can stand behind, a public signed history, and an encrypted vault. Servers can check that you
are you, but they can never become you, never learn your password, and never keep you from moving. One offline
**recovery key** can always rebuild everything, on any server, forever.

## How it works

1. **Create.** Pick a username, a realm (`global` or an application) and a password. You get a recovery key, printed as a
   recovery card. Your account id is the SHA-256 of a statement signed by that key, so nobody can forge it; people see
   it as `Astra#3F9C`.
2. **Instance.** The recovery key signs an *instance*: a fresh account key and the server that is your **home**. The
   account key and your private data go into a **vault**, encrypted on your device and locked with your password (and
   with the recovery key).
3. **Log in.** Your device proves the password to get the vault, unlocks it locally, and signs the home server's
   one-time challenge with the account key. The password never leaves your device, and the server has nothing it could replay.
4. **Prove.** Anyone, on any server, can ask you to sign a challenge and check the signature against your public log.
5. **Change, download, move.** Change your password in the browser with the old one. Download your whole account as one
   file at any time, and move it to another server with the recovery card; your password comes along.
6. **Recover.** Forgot the password, or lost a device or a whole server? The recovery card signs a new instance, on the
   same server or another one. Every old password, vault and session stops working at once. Your id and handle stay.
   No server can do this for you, so keep the card.

## The map

```
      recovery card  RCR-…-CCCC                              password  ••••••••••••
      offline · high power · key tool only                   in your head · low power · app client
                 │ signs the log, mints instances                        │ unlocks the vault
                 ▼                                                       ▼
 ╭──────────────────────────────────────── rootcard ───────────────────────────────────────────╮
 │  Astra#3F9C        id 3F9C… = SHA-256( inception signed by the recovery key )               │
 │                                                                                             │
 │  LOG      public · append-only · every event signed by the recovery key                     │
 │           incept ──► instance ──► rotate_recovery ──► instance ──► …         version = last │
 │                      account key + home host + the host's receipt                           │
 │                                                                                             │
 │  VAULT    encrypted · one per instance        PROFILE  public · signed by the account key   │
 │           locks: password … recovery                   user.*   app.<name>.*                │
 │           holds: account key, private data                                                  │
 ╰───────────────────┬──────────────────────────────────┬──────────────────────────┬───────────╯
                     │ log · vault · profile            │ log · profile            │ log + proof
                     ▼                                  ▼                          ▼
 ┌─ home host ─────────────────────────┐  ┌─ other hosts ─────────────┐  ┌─ relying party ────────┐
 │ the only vault copy, the only login │  │ verify everything         │  │ any server or user     │
 │ challenge ─► answer ─► session      │  │ share the public log      │  │ challenge ─► proof     │
 │ never sees a password               │  │ answer not_home           │  │ verify against the log │
 └─────────────────────────────────────┘  └───────────────────────────┘  └────────────────────────┘
```

## What you get

- **Self-certifying id.** The account id is a hash of a signed inception that names the recovery key. It cannot be forged
  without breaking SHA-256 or Ed25519 or stealing a private key. Shown to humans as `Name#XXXX`.
- **No password verifiers on servers.** The password only unlocks an encrypted vault on the client. Login is a fresh
  challenge signed by the account key, bound to the host, the realm and the current version.
- **Two power levels.** The password gives *low power* (log in, edit your data, export). Everything that changes who can
  access the account, where it lives or whether it exists needs the **recovery key**, kept offline.
- **The recovery key is the root.** It can always mint a fresh, complete instance of the account, even if every host and
  backup is gone.
- **One latest version.** A log only grows. Anyone who has seen a newer verified version rejects the old one, and forks are
  detected and refused.
- **Built for servers.** Hosts never see a password or run Argon2id, verify logs incrementally, run on many servers over
  one compare-and-swap store, and can rotate keys and change addresses without touching identities.
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

## Documentation

| | |
|---|---|
| [spec/SPEC.md](spec/SPEC.md) | The normative specification, with [test vectors](spec/vectors/) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, server usage, dependencies |
| [docs/HOST_PROTOCOL.md](docs/HOST_PROTOCOL.md) | Recommended HTTP binding for hosts |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Goals, attackers, threats, accepted risks |
| [docs/DESIGN.md](docs/DESIGN.md) · [docs/PLAN.md](docs/PLAN.md) | Motivation · setup plan |

## License

[MIT](LICENSE).

## Origin

rootcard started as the account design of the game Xigna and is developed here as an application-neutral library. The
design is [docs/DESIGN.md](docs/DESIGN.md). How Xigna uses rootcard is documented in the Xigna repository.
