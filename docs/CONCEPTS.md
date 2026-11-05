# rootcard: concepts

An informative guide to the five things an identity is built from: the **log**, the **vault**, the **recovery card**,
**proofs** and **verification**. For each one it covers what it is, how it works and when it is used. The rules
themselves live in [spec/SPEC.md](../spec/SPEC.md). This guide only explains them and cites them by id
(`[LOG-12]`, `§11`). Where the two differ, the spec wins. Threats and accepted risks are in
[THREAT_MODEL.md](THREAT_MODEL.md), and the HTTP endpoints are in [HOST_PROTOCOL.md](HOST_PROTOCOL.md).

## The big picture

An identity has one root secret, the **recovery key**: 32 random bytes the user keeps offline and types only into the
key tool ([PWR-6]). Everything else is derived from it or signed by it (SPEC §1):

```
recovery key ─HKDF─► recovery signing key ─signs─► inception ─SHA-256─► account id ─► handle Astra#3F9C
                              └─signs─► instance { account_key, home } ─► account key ─signs─► login, proof, vault, profile
password ─Argon2id─HKDF─► lock keys ─unwrap─► vault key ─decrypts─► account key, private data
```

- The **log** is public and says who the identity is and which key is valid now.
- The **vault** is private and holds the key that does everyday work.
- The **recovery card** is the backup of the root secret.
- **Proofs** and **verification** are how other people and hosts check all of it.

The power split (SPEC §16) runs through all of them. The password unlocks the vault, which is low power. Only the
recovery key changes the log or the vault's grant, which is high power.

## 1. The identity log (SPEC §9, §10)

**What it is.** A public, append-only hash chain of signed events. It holds public keys only.

| Event | What it does | Signed by |
|---|---|---|
| `incept` (seq 0) | Creates the identity: realm, username, recovery public key | recovery key |
| `instance` | Names a new account key and the primary host (`home`). Every earlier instance becomes invalid | recovery key, the new account key, and the host's receipt |
| `rotate_recovery` | Replaces the recovery key | old and new recovery keys |
| `retire` | Closes the identity for good | recovery key |

**How it works.**
- The inception is deterministic ([ID-2]). The account id is its hash ([ID-3]). The id can therefore be re-derived
  from the recovery card alone, and it never changes ([ID-4]).
- Each later event links to the previous one by hash (`prev`). Every key that enters the log signs the event that
  introduces it ([LOG-7]).
- An `instance` event is valid only with the primary host's receipt ([LOG-8]), so no instance exists without the host's
  consent. Clients submit a *pending instance* without the receipt ([LOG-9]).
- Only the current recovery key can add events ([LOG-13], [PWR-1]).
- A log's **version** is its last event. Log `b` is newer than log `a` only if `a` is a strict prefix of `b` ([VER-2]).
  Every party keeps the newest log it has seen and never moves back or switches to a fork ([VER-4]). Forks are detected,
  not resolved, in format version 1 ([VER-3]).

**When it is used.** The log is written at registration and afterwards only by the key tool: restore, revoke, password
reset, moving hosts, rotation and retirement. It is read at every login, at every vault, profile and proof check, and
whenever hosts share identities ([HST-13]–[HST-15]).

## 2. The vault (SPEC §11)

**What it is.** An encrypted blob bound to exactly one instance. It holds:
- the instance's private account key (`account_seed`);
- the private data (§12.2);
- `known`: the identities the user has dealt with, so a client can warn about look-alike handles ([VLT-7], [CLT-4]).

It never holds the recovery key ([VLT-9]). It is stored only at the primary host and in account files the user
downloads ([VLT-5]).

**How it works.**
- **Encryption.** The contents are encrypted under a random **vault key**, which is wrapped once for each **lock**
  ([LCK-9], [VLT-6]).
- **Locks.** There are up to 15 password locks, derived with Argon2id, and one recovery lock, derived from the recovery
  key ([LCK-7], [RK-4]). Password locks do not depend on the instance, so they carry over to a new instance ([KT-3]).
- **Grant and list.** The **grant** says who may unlock: the slots and the recovery lock key. Only the recovery key signs
  it ([LCK-3]), so a password holder cannot add a slot of their own. The **list** holds each lock's key material. A
  password change replaces one slot's material, using the old password ([LCK-10], §13.4).
- **Signature and rollback.** The account key signs the whole vault ([VLT-2]). `rev` and `grant.gen` only increase,
  which stops rollback ([VLT-4]).
- **Unlocking.** Unlocking happens on the client and ends by checking that the decrypted account key is the one the log
  names ([VLT-8]). A host never decrypts a vault and never runs Argon2id (§17).

**When it is used.**
- **Registration:** created with one password slot and the recovery lock ([CLT-1]).
- **Login:** fetched by proving a lock ([FET-1]), then unlocked locally (§13.3).
- **Data edits:** replaced with a session ([HST-12] case 1).
- **Password change:** replaced with a session and a proof made with the old password ([CHG-1]).
- **Adding a password slot:** a new grant from the key tool ([KT-4]).
- **Revoke, reset, restore and fresh:** a new instance gets a new vault ([KT-3], [KT-8]).

## 3. The recovery card (SPEC §6, §15.2)

**What it is.** Everything needed to mint a new instance when nothing else is left ([CRD-1]): the recovery key in its
written form `RCR-…` ([RK-1]), the realm, the username, and the account id as a check.

**How it works.**
- The written key carries a checksum, so typos are caught ([RK-2]).
- The keys are derived with the realm and the username ([RK-4]), so identities made from the same recovery key cannot be
  linked.
- `read_card` re-derives the inception and checks that its id equals the card's account id ([CRD-3]).
- After a rotation, the inception can no longer be derived from the new key, so the card also carries the log up to the
  `rotate_recovery` event ([CRD-2]).
- The canonical JSON doubles as the QR payload ([CRD-4]).

**When it is used.**
- **Creation:** generated once at registration, shown to the user and erased from the application client ([CLT-1]). It
  is reissued after every rotation ([KT-5]).
- **Use:** entered only in the key tool ([PWR-6]), for every high-power operation:
  - resetting a forgotten password ([KT-8]);
  - adding or revoking passwords ([KT-4]);
  - restoring or moving to another host ([KT-3]);
  - rotating the recovery key ([KT-5]);
  - retiring the identity ([KT-6]);
  - root proofs ([PRF-2]).

  There is no reset by e-mail or by the host ([PWR-5]). Without the card, a forgotten password cannot be recovered.

## 4. Proofs (SPEC §14)

**What it is.** A signed statement that shows a verifier, another user or another host, that the prover controls an
identity now.

| Kind | Signed by | Valid while | Made in |
|---|---|---|---|
| Account proof ([PRF-1]) | the account key of the named instance | that instance is current | any client, with the password |
| Root proof ([PRF-2]) | the recovery signing key | that key is the current recovery key | the key tool only |

**How it works.**
- `recipient` names the verifier, so a proof cannot be forwarded to a third party ([PRF-3]).
- An interactive proof signs a fresh challenge from the verifier.
- A statement proof signs the hash of a statement. It is replayable by design, so the statement should say what it is
  for and until when ([PRF-5]).

**When it is used.** Whenever someone other than the primary host needs to know "is this really `Astra#3F9C`, now?"
Examples are a service keyed by the account id, linking two identities, or a host checking a peer's user. Logins are
not proofs: they have their own message and happen only at the primary host (§13.3). A standard sign-in flow at other
services built on proofs is a proposal ([proposals/signin.md](proposals/signin.md)).

## 5. Verification

Every party verifies everything itself. A host never trusts another host's claim ([HST-14]), and every check is
strict Ed25519, a hash or a size ([CRY-3], §17).

- **Logs:** `verify_log` ([LOG-12]) checks the inception, then each event in order: chain, sequence, time, the exact
  signers, key reuse, signatures and receipt. It returns a **log state** with the current recovery key, the current
  instance and the version. `extend_log` ([LOG-15]) does the same for new events only, starting from a stored state, so
  a host never re-checks old signatures.
- **Everything else** is checked against a log state:

  | Function | Checks | Rule |
  |---|---|---|
  | `verify_vault` | the vault | [VLT-3] |
  | `verify_public` | the public profile | [DAT-2] |
  | `verify_proof` | a proof, after merging the log the prover sent | [PRF-4] |
  | `import_account` | an account file | [FIL-3] |
  | `read_card` | a recovery card | [CRD-3] |

- **Logins** are checked by the primary host ([LGN-1] step 6):
  - a single-use challenge ([CHL-2]);
  - the address the client actually connected to ([LGN-4]);
  - the exact version;
  - two signatures, one by the account key and one by the lock that was unlocked ([LGN-5]).
- **Freshness:** vaults, profiles and account proofs are valid only for the current instance of the newest log the
  verifier knows ([VER-6]). A new instance minted with the recovery key therefore ends every old vault copy, password,
  session and account proof at once ([HST-7], [HST-11]).

## The flows at a glance

| Flow | Log | Vault | Card | Checked by |
|---|---|---|---|---|
| Register ([CLT-1], [HST-3]) | inception + `instance` (`register`) | created: one password slot + recovery lock | generated, shown once | host: `verify_log`, `verify_pending`, `verify_vault` |
| Log in ([LGN-1]) | synced to the newest | fetched with the password, unlocked locally | — | host: challenge, version, two signatures |
| Edit data or profile ([HST-12]) | unchanged | `rev + 1` | — | `verify_vault`, `verify_public` |
| Change password ([CHG-1]) | unchanged | one slot's lock replaced | — | host: proof with the old password |
| Forgot password, revoke, move ([KT-3], [KT-4], [KT-8]) | new `instance` | new vault for the new instance | required | old sessions and vaults end |
| Rotate the recovery key ([KT-5]) | `rotate_recovery` | new grant signed by the new key | new card with `log` | — |
| Prove to a third party ([PRF-4]) | read | — | root proofs only | `verify_proof` |
| Retire ([KT-6]) | `retire` | deleted by hosts ([HST-8]) | required | everything answers `account_retired` |
