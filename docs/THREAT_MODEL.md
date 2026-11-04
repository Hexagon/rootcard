# rootcard: threat model

This document states what rootcard protects, against whom, where the trust boundaries are, and which risks are accepted.
Rule identifiers (`[LOG-12]`) refer to [spec/SPEC.md](../spec/SPEC.md). Design background is in [DESIGN.md](DESIGN.md)
§2 and §10. Every threat has an identifier (`T1`) and every accepted risk one (`AR1`); both are stable.

---

## 1. Security goals

| # | Goal |
|---|---|
| G1 | **Unforgeable identity.** Nobody but the holder of the recovery key can create an identity with a given account id, add an event to its log, or change who can unlock its vault |
| G2 | **Authentic login.** A host accepts a login only from someone who unlocked the current instance's vault just now, for this host, this realm and this exact version |
| G3 | **No password exposure.** No host, peer or network attacker learns a password or anything that allows checking a password guess, except the primary host's own storage (AR1) |
| G4 | **Confidential private data.** Private data and the account key are readable only by whoever unlocks the vault |
| G5 | **Integrity of public data.** The log and the public profile cannot be altered by anyone but the owner, only withheld |
| G6 | **One latest version.** Every party that has seen a version rejects older ones, and all parties order versions the same way |
| G7 | **Bounded low power.** A stolen password or account key gives only low power ([PWR-1]–[PWR-4]), only in the current instance, and is revoked by one high-power action |
| G8 | **Always recoverable.** The recovery key can always mint a new, complete instance, without any host's cooperation except the new primary host's receipt |
| G9 | **Unlinkability across identities.** Two identities made from one recovery key are not linkable by their public data ([RK-4]) |
| G10 | **Application neutrality.** No application can use rootcard data to act in another application's namespace or realm |

Non-goals: anonymity towards the primary host (it sees logins and network addresses), hiding that an identity exists
(handles and logs are public by design), availability against a host that refuses service (the owner can move, G8), and
protection of a device that the attacker controls while the user unlocks on it.

---

## 2. Assets

| # | Asset | Where it lives | Protected by |
|---|---|---|---|
| A1 | Recovery key (and its derived seeds) | Recovery card, offline; the key tool's memory during use | User custody, [PWR-6], [IMP-2] |
| A2 | Password | The user's head; the client's memory during unlock | Never sent ([LGN-3]), Argon2id ([LCK-6]) |
| A3 | Account key (private) | Vault contents; client memory while unlocked | AES-256-GCM, non-extractable import ([LGN-2]) |
| A4 | Vault key | Wrapped to each lock; memory during unlock | X25519 + HKDF + AES-GCM wraps ([LCK-9]) |
| A5 | Vault (ciphertext and locks) | Primary host; account files | Fetch gating ([FET-1]), never shared ([HST-13]) |
| A6 | Private data | Vault contents | As A4, A5 |
| A7 | Identity log | Everywhere | Signatures, hash chain ([LOG-12]) |
| A8 | Public profile | Hosts, clients | Account-key signature ([DAT-2]) |
| A9 | Host key | The host | Host operations security |
| A10 | Session tokens | Client memory; host stores the hash ([HST-10]) | TLS, bearer header, idle expiry |
| A11 | Account id ↔ person mapping | Hosts, clients | Not secret; tags are not identifiers ([HDL-2]) |

---

## 3. Actors and attacker capabilities

| # | Actor | Capabilities assumed |
|---|---|---|
| X1 | **Network attacker** | Reads, drops, replays and modifies traffic, but cannot break TLS to a host whose certificate the client checks |
| X2 | **Other user** | Registers identities, chooses usernames, brute-forces tags (≈ 2²⁰ work), sends arbitrary data to hosts and clients |
| X3 | **Peer host** (malicious or compromised) | Sends arbitrary logs, profiles and events; withholds data; lies about versions |
| X4 | **Non-primary host** a user talks to | As X3, and serves the client code the user runs on its pages |
| X5 | **Primary host** (malicious operator or full compromise) | Everything the host stores: vaults, sessions, logs; serves the client code; sees every login |
| X6 | **Database thief** of a host | A copy of the host's storage at one point in time |
| X7 | **Password thief** (phishing, shoulder surfing, reuse) | One password of the user |
| X8 | **Account-file thief** | A downloaded account file, possibly old |
| X9 | **Recovery-card thief** | The recovery key (current or rotated out) |
| X10 | **Malicious application** in the same realm or another | Its own client code, its own namespace, the user's trust in it |
| X11 | **Supply-chain attacker** | Tries to ship modified packages or a modified key tool page |
| X12 | **Quantum adversary** (future) | Breaks Ed25519 and X25519 given public keys |

Not in scope: an attacker who controls the user's device or browser while the user enters the password or recovery key,
and side channels on the user's device beyond constant-time comparisons ([IMP-4]).

---

## 4. Trust boundaries

```
 ┌───────────────────────── user's device ─────────────────────────┐
 │  key tool (CLI / keytool.html)      application client          │
 │  sees: recovery key, password       sees: password, account key │
 │  high power                         low power                   │
 └────────────┬──────────────────────────────┬─────────────────────┘
              │ TLS (B1)                     │ TLS (B1)
 ┌────────────▼──────────────┐      ┌────────▼──────────────────────┐
 │ primary host (home)       │◄────►│ other hosts in the realm      │
 │ vault, log, profile,      │ (B2) │ log, profile only             │
 │ sessions, logins          │      │ answer not_home               │
 └───────────────────────────┘      └───────────────────────────────┘
        B3: the primary host serves the application client code
```

- **B1 (client ↔ host):** everything crossing it is either public (log, profile, lock hints), a signature over a fresh
  challenge, or the vault after a lock proof. Secrets never cross it.
- **B2 (host ↔ host):** only public logs and profiles cross it ([HST-13]), and the receiver verifies everything itself
  ([HST-14]).
- **B3 (code served by the host):** a client served by a host can do whatever that host wants with what the user types
  into it. This boundary is the reason for power levels: what is typed into a host-served client (the password) gives
  low power; what gives high power (the recovery key) is typed only into the key tool, which the host does not serve
  (AR2).
- **B4 (key tool):** the key tool is trusted with the recovery key. It is distributed through package registries with
  provenance (CLI, npm) and works offline from a local file (`keytool.html`), so no host can change it after the user
  obtained it.

---

## 5. Assumptions

1. SHA-256 is collision and second-preimage resistant; Ed25519 with strict verification is existentially unforgeable;
   X25519 is a secure key agreement; HKDF-SHA256 is a secure KDF; AES-256-GCM with unique nonces is a secure AEAD;
   Argon2id is memory-hard.
2. Random number generators of operating systems and browsers are secure.
3. TLS protects client ↔ host traffic, and users reach the host they intend (they choose the primary host).
4. The user keeps the recovery card offline and does not type it outside the key tool.
5. Host clocks are within a few minutes of real time; the owner's clock is honest (AR5).

---

## 6. Threats and mitigations

| # | Threat | Actor | Mitigation | Rules | Remaining |
|---|---|---|---|---|---|
| T1 | Create an identity with someone else's account id | X2, X3 | The id is the hash of the signed inception; a second inception with the same hash needs a SHA-256 second preimage; an inception naming the victim's recovery key needs its signature | ID-1, ID-3, LOG-12 | – |
| T2 | Impersonate by handle: same username and a brute-forced tag | X2 | Applications compare full ids; hosts refuse colliding handles; collisions from propagation get extended tags; clients remember full ids and warn | HDL-2, HDL-5, HDL-6, CLT-4 | A user who only reads the plain tag can be fooled once (AR7) |
| T3 | Look-alike usernames (Unicode homographs) | X2 | Usernames are ASCII only; similarity is case-insensitive | USR-1, USR-2, HDL-4 | `l`/`I`, `0`/`O` look-alikes in some fonts; applications may tighten their policy |
| T4 | Add an event without the recovery key (claim an instance, rotate, retire) | X3–X8 | Every event is signed by the current recovery key; new keys self-sign; instances need the home's receipt | LOG-7, LOG-8, LOG-12, PWR-1 | – |
| T5 | Name someone else's public key (as account key, recovery key or home) | X2, X3 | Proof of possession: every key that enters the log signs that event | LOG-7 | – |
| T6 | Replay a login to the same or another host | X1, X3–X5 | Login signs host key, realm, exact version and a single-use 60 s nonce bound to account and purpose | CHL-2, LGN-1 | – |
| T7 | Relay a login through a phishing site | X1, X4 | The client logs in only at `home.url` from the verified log and checks the challenge's host key | LGN-1, CLT-3 | A host-served client that the user reached by phishing is a malicious client (T19) |
| T8 | Cross-protocol signature reuse (a login signature as a proof, an event signature as a receipt) | all | Every signed message is framed with its own label and is a canonical JSON object with the context | DS-1–DS-3 | – |
| T9 | Parser differentials (duplicate members, number forms, Unicode escapes, unknown members) that make two implementations see different content under one signature | X2, X3 | Strict parser, canonical re-serialization before every hash, strict schemas with unknown members rejected, shared reject vectors | CJ-1–CJ-13, CNV-3 | – |
| T10 | Signature malleability and weak keys (small-order points, non-canonical encodings) | X2, X3 | Strict verification with explicit checks, identical in both languages | CRY-3, KEY-3 | – |
| T11 | Download a vault and guess the password offline | X2, X3, X4 | The vault is released only after a lock proof or with a session; lock hints carry no verifier; fetches are rate limited; Argon2id and password rules | FET-1–FET-3, VLT-5, LCK-6, LCK-8 | Online guessing within the rate limits |
| T12 | Steal a host's database and guess passwords offline | X5, X6 | Only the primary host stores vaults, only of its own identities; Argon2id with high memory cost | HST-2, HST-13, LCK-6 | Weak passwords fall (AR1) |
| T13 | Use a stolen password | X7 | Low power only, only at the primary host, only in the current instance; one revocation makes a new instance and ends every session | PWR-1–PWR-5, HST-7, KT-4 | The thief can log in and read or change private data until the owner revokes |
| T14 | A password thief adds their own password, or re-adds a revoked one, to keep access | X7 | The lock set is signed by the recovery key with a generation counter; hosts reject lock changes without it and lock sets going back | LCK-3, VLT-4, HST-12 | – |
| T15 | Use an old account file (with a password) after revocation | X8 | A new instance invalidates the old vault, account key and sessions; hosts and clients that saw the newer version reject the old one | VER-4, VER-6, HST-7 | A party that never sees the newer version (AR4) |
| T16 | Roll an identity back to an older version (replay an old log, profile or vault) | X3–X5 | Total order; monotonic storage; logins bound to the exact version; revisions only increase | VER-2, VER-4, VLT-4, DAT-3, LGN-1 | Withholding (AR4) |
| T17 | A host alters or forges a public profile | X3–X5 | Signed by the account key, bound to the instance and revision | DAT-2 | A host can withhold it or serve an older copy of the current instance until the client sees a newer one |
| T18 | A host forks the log or creates a branch | X3–X5 | A host cannot sign events; only the owner can branch, and branches are resolved deterministically | VER-2, VER-3 | – |
| T19 | The primary host serves a malicious client that captures the password | X5, X4 | The password gives low power only; the recovery key is never typed into an application client; the owner can move to another host | PWR-6, CLT-5, KT-3 | The primary host can capture passwords typed into its own client (AR2) |
| T20 | Phishing for the recovery key with a fake key tool or a fake host page | X4, X11 | Application clients never ask for it, and applications warn; the key tool is installed from registries with provenance or kept as a local file | PWR-6, CLT-5, KT-1 | A user who types the key into a phishing page loses the identity (AR3) |
| T21 | Stolen recovery key | X9 | Kept offline; used only in the key tool | RK-3, PWR-6 | The thief controls the identity (AR3) |
| T22 | A rotated-out recovery key is used to fork the log from before the rotation | X9 | – (format version 1 has no witnesses) | VER-3 | Same as a stolen current key (AR3) |
| T23 | A recovery-key thief retires the identity | X9 | – | VER-3 | Retirement is final (AR3) |
| T24 | Clock manipulation to win a branch | X9, owner | Hosts reject events more than 600 s ahead; receipts require the instance time within ± 600 s of the receipting host's clock | LOG-12, HST-6 | AR5 |
| T25 | Denial of service with expensive inputs (huge or deep JSON, long logs, extreme Argon2id parameters, many signatures) | X2, X3 | Size limits checked before parsing; depth limit; event and lock limits; Argon2id bounds; rate limits | CJ-5, CJ-8, LOG-1, LOG-2, LCK-6, HST-16, §19 | Verifying a maximal log costs about 3 000 signature checks |
| T26 | Lock out the owner by exhausting fetch or login rate limits | X2 | Rate limits per identity and per network address; a cached vault skips the fetch | HST-16, LGN-1 | Partial (AR8) |
| T27 | Stored cross-site scripting through profile or private data | X2, X10 | Data is displayed only as text; keys are restricted; sizes are bounded | DAT-4, DAT-8 | – |
| T28 | An application writes into another application's namespace | X10 | Write functions are restricted to the application's namespace and `user.` | DAT-7 | A malicious client can ignore the library and sign anything with the account key it holds (low power, own identity only) |
| T29 | Linking identities of one person across realms by their recovery public key | X2–X5 | Recovery keys are derived per realm and username | RK-4 | Network addresses, timing and the primary host link them (non-goal) |
| T30 | AES-GCM nonce reuse | – | Random 96-bit nonces, a fresh vault key per instance, a fresh wrap key per wrap, at most 2³² encryptions per key | CRY-7, LCK-9, VLT-4 | Negligible collision probability |
| T31 | Secret material left in memory or exported from WebCrypto | malware after the fact | Zeroization; non-extractable keys | IMP-2, LGN-2 | Garbage-collected copies in JavaScript cannot be fully controlled |
| T32 | Supply-chain compromise of the packages | X11 | Zero npm dependencies; audited Rust crates; `cargo deny`; releases only from CI with trusted publishing and provenance | AGENTS.md rule 6 | Compromise of the CI or registry accounts |
| T33 | Session token theft | X1, X5 | Random 32-byte tokens, stored hashed, sent as a bearer header (no cookies), bound to host, account and instance, idle expiry, revoked on a new instance | HST-10, HST-11 | A thief with a token has low power until expiry or revocation |
| T34 | A host claims an instance that names it without the owner (or names another host) | X3–X5 | The instance must be signed by the recovery key; the receipt must be by `home.key` itself | LOG-8, LOG-12 | – |
| T35 | A host rotates or loses its host key | X5 | – | LOG-8 | Identities homed there must move with a new instance (KT-3) |
| T36 | Malicious lock hints (wrong salt, maximal Argon2id cost) | X5 | Hints are only for the primary host's own identities; Argon2id bounds limit the cost | FET-2, LCK-6 | The primary host can make a login fail or cost up to the bound |
| T37 | Quantum attacks on Ed25519 and X25519 | X12 | Typed keys and versioned structures allow a migration by a later format version | EXT-1, EXT-3 | Recorded traffic and vaults could be attacked later; harvest-now attacks on X25519 wraps of stored vaults |

---

## 7. Secure and feasible: decisions

| Part | Decision | Reason |
|---|---|---|
| Ed25519, X25519, SHA-256, HKDF, AES-GCM | **Used** | Standard, reviewed, available in WebCrypto and in audited Rust crates |
| Argon2id in plain JavaScript | **Used**, tested against RFC 9106 and the shared vectors | WebCrypto has no memory-hard KDF; WASM would add a build step and a dependency |
| Strict Ed25519 with explicit pre-checks | **Used** | Platform verifiers differ on edge cases; both languages must reject the same signatures |
| Self-certifying id from a deterministic inception | **Used** | No registry, and the recovery key can always re-derive the identity |
| Hash chain with a total version order | **Used** | Rollback protection without consensus |
| Vault only at the primary host, released after a lock proof | **Used** | Restricts offline guessing to the primary host's storage and account files |
| Recovery-signed lock sets | **Used** | Makes "who can unlock" high power in the format, not by policy |
| OPAQUE or a server pepper | **Not now** | Needs per-host secrets and heavy client code; conflicts with portability. A primary host may add one later without a format change to the log (AR1) |
| Passkeys (WebAuthn PRF) as a lock | **Later** | Strong against phishing but bound to a host's domain; a new lock `kind` ([EXT-3]) |
| Witnesses and pre-rotation (KERI style) | **Later**, format version 2 | Would make rotation effective against a stolen key (AR3); more complex and two secrets to keep |
| Global handle uniqueness by consensus | **No** | Infeasible; per-host uniqueness and extended tags instead |
| Proof of work in the inception against tag brute force | **No** | Slows registration, gives hosts an expensive check per unknown identity (a DoS vector) and does not stop a determined attacker |
| Protection against the primary host's own client | **Accepted risk** (AR2) | Impossible for code served by that host |
| Recovery without the recovery key | **No, by design** | Would be a backdoor |

---

## 8. Accepted risks

- **AR1: Offline guessing by whoever holds a vault.** The primary host's operator, a thief of its storage, or a thief of
  a current account file can run Argon2id guesses against the vault's locks. *Mitigations:* vaults are never shared or
  handed out without a lock proof, Argon2id at 64 MiB by default with a 46 MiB floor, at least 12 characters and a
  common-password check. *Future:* a primary host may add its own secret (OPAQUE or a pepper) as an additional lock
  layer.
- **AR2: The primary host sees passwords typed into its own client.** The user chooses the primary host; the password
  gives low power; the recovery key is used only in the key tool; the identity can move with one high-power action.
  *Future:* a signed client that is not served by the host.
- **AR3: A stolen recovery key gives control.** This includes a rotated-out key in format version 1: its holder can fork
  the log from before the rotation, and the branch with the later last event wins. Owner and thief can keep minting
  events and neither wins over time; either can retire the identity, which is final. *Advice:* rotate to replace a worn
  or exposed card, destroy old cards, and treat a suspected compromise as the loss of the identity. *Future:* witnesses
  and pre-rotation in format version 2 without changing the id.
- **AR4: A party that never sees the newer version** may believe an old instance is current. Only the previous primary
  host could let an old password in, it is told first ([HST-15]), and the old account key is valid nowhere else. Clients
  and hosts carry newer versions forward ([VER-5]).
- **AR5: The owner's clock decides branches.** Hosts reject times more than 10 minutes ahead and receipts require the
  receipting host's clock; the key tool shows the resulting current instance ([KT-7]).
- **AR6: Public profiles cannot be taken back** once shared.
- **AR7: The tag is not a security feature.** Users who compare only the 4-character tag can be fooled by a collision
  made with about a million attempts. Applications compare full ids and show extended tags; users who need certainty ask
  for a proof (§14 of the spec).
- **AR8: Lock-out by rate limits.** An attacker can exhaust per-identity fetch limits for a while. A client with a
  cached vault is unaffected; hosts should combine per-identity and per-address limits.
- **AR9: Metadata.** Handles, logs (including the primary host and the times of events) and public profiles are public.
  Lookups reveal that an identity exists. The primary host sees when and from where the user logs in.
- **AR10: Lock labels are visible** to anyone who asks the primary host for lock hints.

---

## 9. Review checklist

For every change, reviewers check:

1. Does it add anything that is hashed or signed? Then it is a format change (spec §22) with a new label or `v`, and
   vectors.
2. Does it add a way to change who can access the identity, where it lives or whether it exists? Then it needs the
   recovery key (spec §16).
3. Does any new input reach a parser or verifier? Then it has limits, reject vectors and (before 1.0) a fuzz target.
4. Does any secret cross a trust boundary (§4)? It must not.
5. Is the threat table still true? Update it in the same change.
