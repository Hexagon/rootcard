# rootcard specification

Format version **1**. Status: **draft** (phase 1 of [docs/PLAN.md](../docs/PLAN.md)). Nothing is stable before `1.0.0`,
but every change to anything hashed or signed follows §22 already.

This document is the normative definition of rootcard: a portable, self-certifying identity for online logins. It is
complete on its own: an implementation can be written from this document and `spec/vectors/` without reading
[docs/DESIGN.md](../docs/DESIGN.md), which holds the motivation. The threat model is
[docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md). The recommended HTTP binding is
[docs/HOST_PROTOCOL.md](../docs/HOST_PROTOCOL.md).

## Contents

0. [Conventions](#0-conventions)
1. [Overview](#1-overview-informative)
2. [Canonical JSON](#2-canonical-json)
3. [Byte encodings](#3-byte-encodings)
4. [Cryptographic primitives](#4-cryptographic-primitives)
5. [Domain separation](#5-domain-separation)
6. [The recovery key](#6-the-recovery-key)
7. [Realm, username, inception and account id](#7-realm-username-inception-and-account-id)
8. [Handles and tags](#8-handles-and-tags)
9. [The identity log](#9-the-identity-log)
10. [Versions](#10-versions)
11. [The vault](#11-the-vault)
12. [Arbitrary data: public profile and private data](#12-arbitrary-data-public-profile-and-private-data)
13. [Vault fetch and login](#13-vault-fetch-and-login)
14. [Proofs](#14-proofs)
15. [Account file and recovery card](#15-account-file-and-recovery-card)
16. [Power levels](#16-power-levels)
17. [Hosts](#17-hosts)
18. [Clients and the key tool](#18-clients-and-the-key-tool)
19. [Limits](#19-limits)
20. [Error codes](#20-error-codes)
21. [Test vectors](#21-test-vectors)
22. [Versioning and extension](#22-versioning-and-extension)
- [Appendix A: the version order is total](#appendix-a-the-version-order-is-total)
- [Appendix B: changes from DESIGN.md](#appendix-b-changes-from-designmd)

---

## 0. Conventions

- **[CNV-1]** The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT and MAY are to be interpreted as described in
  RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.
- **[CNV-2]** Every normative rule has an identifier in square brackets, `[AREA-n]`. Identifiers are stable: a rule that
  is removed leaves a gap, and its number is never reused. Tests refer to rules by these identifiers.
- **[CNV-3]** Each rule that a verifier checks names the **error code** (§20) reported when the rule is violated,
  written `→ code`. Algorithms are given as numbered steps. An implementation MUST check the steps in the order given
  and MUST report the code of the **first** step that fails, so that every implementation rejects the same input with
  the same code.
- **[CNV-4]** `spec/vectors/*.json` are part of this specification. A conforming implementation MUST reproduce every
  vector exactly, including the error code of every reject vector. Where the prose and a vector disagree, that is a bug
  in this specification, to be fixed in both.
- Sections marked *(informative)* and notes starting with *Note:* or *Rationale:* are not normative.

### 0.1 Notation

- `‖` is byte concatenation. `0x00` is a single zero byte. Strings are UTF-8 bytes when used as bytes.
- `canonical(x)` is the canonical JSON encoding of `x` (§2). `x without f` is the object `x` with the member `f`
  removed.
- `b64u(bytes)` is unpadded base64url (§3.1). `b32(bytes)` is Crockford base32 (§3.2).
- `SHA-256(m)`, `HKDF(ikm, salt, info)`, `Ed25519.sign(sk, m)` and so on are the primitives of §4.
- `frame(label, m) = utf8(label) ‖ 0x00 ‖ m` (§5), and for an object `x`, `frame(label, x)` means `frame(label,
  canonical(x))`.
- Times are integers: seconds since the Unix epoch, UTC, ignoring leap seconds.
- `KiB` is 1 024 bytes. Every size limit is measured on canonical bytes (§2) unless stated otherwise.

### 0.2 Terms

| Term | Meaning |
|---|---|
| **identity** | One account: an id, a log, a vault per instance and a public profile |
| **application** | Software that uses rootcard (a game, a web service). It chooses a realm, a username policy and a data namespace |
| **realm** | The string an identity is bound to: an application, a world, or `global` (§7.1) |
| **host** | A server that stores identities and accepts logins for one or more realms. It has an Ed25519 **host key** |
| **primary host**, **home** | The host named by the current instance. The only host that stores the vault and accepts logins |
| **client** | Software acting for the user with low power: an application's login page or app |
| **key tool** | The only software that takes the recovery key as input: the `rootcard` CLI and `keytool.html` |
| **verifier** | Any party checking rootcard data: a host, a client, the key tool, another user |
| **instance** | One generation of the identity: an account key, a primary host, a vault. Created by an `instance` event |
| **version** | The last event of a valid log, written `{ seq, hash }` (§10) |
| **low power**, **high power** | What the password, respectively the recovery key, can do (§16) |

---

## 1. Overview *(informative)*

An identity is three things:

1. **The identity log** (§9): public, signed, a hash chain of events holding public keys only. Its first event, the
   **inception**, is derived deterministically from the recovery key, the username and the realm, and its hash is the
   **account id**. Later events add instances, rotate the recovery key or retire the identity. Only the recovery key can
   add events.
2. **The vault** (§11): encrypted, bound to one instance, holding the instance's private **account key** and private
   data. It is unlocked with a password or with the recovery key and lives only on the primary host and with the user.
3. **The public profile** (§12): arbitrary public data signed by the account key.

```
recovery key ─HKDF─► recovery signing key ─signs─► inception ─SHA-256─► account id ─► handle Astra#3F9C
                              │
                              └─signs─► instance { account_key, home } ─► account key ─signs─► login, proof,
                                                                                               vault, profile
password ─Argon2id─HKDF─► lock keys ─unwrap─► vault key ─decrypts─► account key, private data
```

A login is a fresh challenge from the primary host signed by the account key, bound to the host, the realm and the exact
version. Hosts store no password verifier that they hand out, and they can check that someone *is* an identity but can
never *become* it. Whoever holds the recovery key can always mint a new instance (§9.4), which invalidates every earlier
instance, vault, password and session.

---

## 2. Canonical JSON

Everything that is hashed or signed is canonical JSON. The encoding is the JSON Canonicalization Scheme (RFC 8785,
"JCS") restricted to a subset of JSON values in which JCS and every mainstream JSON library agree.

### 2.1 Values

- **[CJ-1]** A rootcard JSON value is one of: an **object**, an **array**, a **string**, an **integer**, `true` or
  `false`. `null` and non-integer numbers do not exist in rootcard. An optional member is absent, never `null`. →
  `bad_json`
- **[CJ-2]** An integer is in the range −(2⁵³−1) … 2⁵³−1 (the "safe integers"). → `bad_json`
- **[CJ-3]** A string is a sequence of Unicode scalar values (no unpaired surrogates). → `bad_json`
- **[CJ-4]** Object member names are strings and are unique within their object, compared after unescaping. → `bad_json`
- **[CJ-5]** Arrays and objects nest at most **32** levels deep. The outermost object or array is level 1. → `bad_json`

### 2.2 Parsing

- **[CJ-6]** A parser accepts exactly the JSON texts of RFC 8259 whose value satisfies §2.1, with these additional
  restrictions, each → `bad_json`:
  1. The text is UTF-8 without a byte order mark, and is well-formed UTF-8.
  2. A number token matches `0|-?[1-9][0-9]*` exactly. A fraction, an exponent and `-0` are rejected even when the value
     is integral (`1.0`, `1e2`).
  3. A `\u` escape that encodes a lone surrogate, or a high surrogate not followed by a low-surrogate escape, is
     rejected.
  4. Insignificant whitespace (space, tab, line feed, carriage return) is accepted between tokens. Nothing follows the
     value.
- **[CJ-7]** A verifier MUST NOT hash or verify the bytes it received. It parses them (§2.2), checks the structure's
  schema, and computes hashes and signatures over `canonical()` of the parsed value.
- **[CJ-8]** Size limits (§19) are checked on the received bytes **before** parsing, against `⌊1.25 × limit⌋` for the
  structure (room for insignificant whitespace), and again on the canonical bytes after parsing. → `too_large`

### 2.3 Serialization

- **[CJ-9]** `canonical(x)` is the RFC 8785 serialization of `x`:
  1. No insignificant whitespace.
  2. Object members sorted by their names compared as sequences of **UTF-16 code units** (RFC 8785 §3.2.3). *Note:* for
     names made only of ASCII, this is plain byte order.
  3. Integers in shortest decimal form: an optional `-`, no leading zeros, no `+`, no exponent.
  4. Strings in double quotes. `"` is written `\"`, `\` is written `\\`. U+0008, U+0009, U+000A, U+000C and U+000D are
     written `\b`, `\t`, `\n`, `\f` and `\r`. Every other code point below U+0020 is written `\u00xx` with lower-case
     hex. **Every other code point is written as itself in UTF-8**, including `/`, U+007F, U+2028 and U+2029. No Unicode
     normalization is applied to strings (passwords are the one exception, §11.4, and they are never serialized).
  5. `true` and `false` as themselves.
- **[CJ-10]** Every producer of a structure in this specification MUST emit `canonical()` bytes when it serializes for
  storage or transport, so that files and messages are byte-identical across implementations.

### 2.4 Schemas

- **[CJ-11]** Every structure in this specification has a schema: a list of required and optional members with their
  types. A member not in the schema is rejected (no extension by unknown members), a required member that is missing is
  rejected, and a member of the wrong JSON type is rejected. → `bad_field`. The only members whose contents are not
  constrained by a schema are named in their section (`data` in §12, `host_data` in §15.1).
- **[CJ-12]** A structure with a `v` member is checked in this order: `v` is present and an integer, otherwise
  `bad_field`; `v` is a version the implementation supports (only `1` in this specification), otherwise
  `unsupported_version`; then the rest of the schema.
- **[CJ-13]** A string member with an encoding (base64url, base32, key, label) that fails its encoding rule is
  `bad_field`, except key strings (§3.3), which are `bad_key`.

---

## 3. Byte encodings

### 3.1 base64url

- **[B64-1]** Byte strings in JSON are base64url (RFC 4648 §5) **without padding**. Encoders emit no `=` and no line
  breaks.
- **[B64-2]** A decoder rejects: any character outside `A–Z a–z 0–9 - _`, a `=`, a length ≡ 1 (mod 4), and **non-zero
  unused bits** in the last character (so every byte string has exactly one encoding). → `bad_base64` (`bad_field`
  inside a structure, [CJ-13])
- **[B64-3]** Every byte-string field has a fixed decoded length or a stated maximum. A wrong length is rejected like a
  bad encoding.

### 3.2 Crockford base32

- **[B32-1]** The alphabet is `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (value 0 to 31; no `I L O U`).
- **[B32-2]** Encoding reads the input as a big-endian bit string, most significant bit first, takes 5 bits per
  character and pads the final group with zero bits. 32 bytes give 52 characters (4 padding bits).
- **[B32-3]** **Strict decoding** (machine fields: account ids in JSON, tags in stored data) accepts only upper-case
  characters of the alphabet, the exact length for the expected byte count, and zero padding bits. → `bad_base32`
- **[B32-4]** **Lenient decoding** (human input only: a typed recovery key, a typed handle or account id) first maps
  lower case to upper case, `I` and `L` to `1`, `O` to `0`, and removes every `-` and space, then decodes strictly. `U`
  is never accepted. → `bad_base32`

### 3.3 Keys and signatures

- **[KEY-1]** A public key is written `"<type>:" + b64u(raw)`. The types of format version 1 are:

  | Type tag | Key | Raw length |
  |---|---|---|
  | `ed25519` | Ed25519 public key (RFC 8032 encoding) | 32 bytes |
  | `x25519` | X25519 public key (RFC 7748 u-coordinate) | 32 bytes |

  An unknown type tag, a wrong length, or a bad base64url payload is rejected. → `bad_key`
- **[KEY-2]** Every field that holds a key states which type it requires. A key of another type is rejected. → `bad_key`
- **[KEY-3]** An `ed25519` key is rejected unless it passes the point checks of [CRY-3] steps 3 and 4 (canonical and not
  of small order). → `bad_key`
- **[KEY-4]** A signature is `b64u` of the 64-byte Ed25519 signature. → `bad_field` if it is not 64 bytes.
- **[KEY-5]** Two keys are equal if and only if their strings are equal. (Encodings are canonical, so this is the same
  as comparing the raw bytes.)

---

## 4. Cryptographic primitives

- **[CRY-1]** Format version 1 uses exactly these primitives. Implementations MUST use reviewed implementations of them.
  The only primitive a reference implementation may implement itself is Argon2id (with BLAKE2b) in JavaScript, which has
  no platform implementation; it MUST pass the RFC 9106 test vectors and the shared vectors.

  | Purpose | Primitive |
  |---|---|
  | Hash | SHA-256 (FIPS 180-4) |
  | Key derivation | HKDF-SHA256 (RFC 5869), output 32 bytes unless stated otherwise |
  | Password hashing | Argon2id, version `0x13` (RFC 9106) |
  | Signatures | Ed25519 (RFC 8032, pure, no context, no pre-hash), strict verification [CRY-3] |
  | Key agreement | X25519 (RFC 7748) |
  | Encryption | AES-256-GCM (NIST SP 800-38D), 96-bit nonce, 128-bit tag |
  | Randomness | A cryptographically secure random number generator of the operating system or platform |

- **[CRY-2]** An Ed25519 private key is a 32-byte seed (RFC 8032 §5.1.5). An X25519 private key is 32 bytes, clamped as
  in RFC 7748 §5 when used.
- **[CRY-3]** **Strict Ed25519 verification.** `verify_strict(A, M, sig)` succeeds only if all of these hold, checked in
  order (each failure → `bad_signature`, or `bad_key` when checking a key on its own per [KEY-3]):
  1. `A` is 32 bytes and `sig` is 64 bytes; `R` is the first 32 bytes of `sig` and `S` the last 32.
  2. `S`, read as a little-endian integer, is less than the group order `L = 2^252 +
     27742317777372353535851937790883648493`.
  3. `A` and `R` are **canonical** encodings: the little-endian integer formed by the low 255 bits is less than `p =
     2^255 − 19`, and the encoding is not one of the two encodings with `x = 0` and the sign bit set (`0100…0080` and
     `ecff…ffff`).
  4. Neither `A` nor `R` is a point of **small order** (order dividing 8). In canonical encoding these are exactly the
     eight encodings
     ```
     0100000000000000000000000000000000000000000000000000000000000000   (order 1)
     ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f   (order 2)
     0000000000000000000000000000000000000000000000000000000000000000   (order 4)
     0000000000000000000000000000000000000000000000000000000000000080   (order 4)
     26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05   (order 8)
     26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85   (order 8)
     c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a   (order 8)
     c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa   (order 8)
     ```
     and an implementation MAY check them as a byte blocklist.
  5. `A` decodes to a curve point, and the **cofactorless** equation of RFC 8032 §5.1.7 holds with `k = SHA-512(R ‖ A ‖
     M) mod L`: the encoding of `[S]B − [k]A` equals `R` byte for byte.

  *Note:* libraries differ on steps 2–4 (WebCrypto implementations in particular, and `ed25519-dalek`'s `verify_strict`
  does not check every non-canonical encoding of `A`), so each implementation performs steps 1–4 itself before calling
  its library for step 5. The vectors include every rejected class, among them non-canonical `A` and `R`, small-order
  `A` and `R`, `S ≥ L`, and mixed-order keys that only a cofactored verifier would accept.
- **[CRY-4]** **X25519.** `X25519(sk, pk)` is computed as in RFC 7748. If the 32-byte result is all zeros (the peer key
  has small order), the operation fails. → `bad_key`
- **[CRY-5]** **HKDF.** `HKDF(ikm, salt, info)` is HKDF-SHA256 extract-then-expand with a 32-byte output. An empty
  `salt` is the zero-length byte string (which RFC 5869 treats as 32 zero bytes).
- **[CRY-6]** **Argon2id.** `Argon2id(password, salt, m, t, p)` uses version `0x13`, no secret key, no associated data,
  and a 32-byte tag. `m` is in KiB. Parameters are bounded by [LCK-6].
- **[CRY-7]** **AES-256-GCM.** Every encryption uses a fresh random 96-bit nonce. A ciphertext field holds the
  ciphertext followed by the 16-byte tag. A failed tag check fails the operation. A key MUST NOT be used for more than
  2³² encryptions (this bounds [VLT-4]).
- **[CRY-8]** Ed25519 signing is deterministic (RFC 8032). Nothing in rootcard depends on a random signature.

---

## 5. Domain separation

- **[DS-1]** Every hash, signature, key derivation and authenticated-data input in rootcard is **framed**: `frame(label,
  m) = utf8(label) ‖ 0x00 ‖ m`, where `m` is the canonical JSON of an object or, where stated, raw bytes. A label never
  contains `0x00`, so the frame is unambiguous.
- **[DS-2]** A label has the form `rootcard/<purpose>/v<n>`: the prefix `rootcard/`, a purpose of lower-case ASCII words
  separated by `/`, and the format version that introduced it. A label is used for exactly one purpose and never reused.
- **[DS-3]** The labels of format version 1 are exactly these. `spec/vectors/meta.json` lists the same set and the test
  suites check that it matches this table.

  | Label | Used for | Section |
  |---|---|---|
  | `rootcard/id/v1` | Account id from the inception | §7.3 |
  | `rootcard/event/v1` | Hash of a log event, and the owner signatures on it | §9.2 |
  | `rootcard/receipt/v1` | The primary host's receipt on an `instance` event | §9.3 |
  | `rootcard/locks/v1` | The recovery key's signature on a vault's lock set | §11.3 |
  | `rootcard/vault/v1` | The account key's signature on a vault | §11.2 |
  | `rootcard/contents/v1` | Authenticated data of the vault contents encryption | §11.5 |
  | `rootcard/wrap/v1` | Key wrapping of the vault key to a lock | §11.4 |
  | `rootcard/public/v1` | The account key's signature on the public profile | §12.1 |
  | `rootcard/login/v1` | Answer to a login challenge | §13.3 |
  | `rootcard/fetch/v1` | Answer to a vault fetch challenge | §13.2 |
  | `rootcard/proof/v1` | Proof of identity | §14 |
  | `rootcard/statement/v1` | Challenge derived from a statement | §14.2 |
  | `rootcard/recovery/check/v1` | Checksum of the written recovery key | §6.1 |
  | `rootcard/recovery/sign/v1` | Recovery signing key from the recovery key | §6.3 |
  | `rootcard/recovery/box/v1` | Recovery lock key from the recovery key | §6.3 |
  | `rootcard/password/auth/v1` | Vault fetch key from a password | §11.4 |
  | `rootcard/password/box/v1` | Lock key from a password | §11.4 |
  | `rootcard/peer/v1` | Host-to-host request signatures (HTTP binding) | HOST_PROTOCOL.md |

---

## 6. The recovery key

The recovery key is the root of an identity. It is 32 bytes from a secure random generator, kept by the user offline,
and entered only in the key tool ([PWR-6]).

### 6.1 Written form

- **[RK-1]** The written form is `RCR-` followed by 56 Crockford base32 characters in 14 groups of 4 separated by `-`:
  the first 52 characters are `b32(key)` ([B32-2]), the last 4 are the **checksum**, the first 4 characters of
  `b32(SHA-256(frame("rootcard/recovery/check/v1", key)))` (raw 32 key bytes as `m`).

  ```
  RCR-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-CCCC
  ```
  The written form is 73 characters. Producers emit exactly this form, upper case.
- **[RK-2]** Parsing a typed recovery key: remove every `-` and space; if 59 characters remain and the first three are
  `RCR` in any case, remove them; exactly 56 characters must remain → `bad_base32`; decode them leniently ([B32-4]) →
  `bad_base32`; the first 52 must decode to 32 bytes with zero padding bits → `bad_base32`; the last 4 must equal the
  checksum of those bytes → `bad_checksum`. *Note:* the prefix is removed by length, not by content, because a key's
  base32 can itself begin with `RCR`.

### 6.2 Generation

- **[RK-3]** A recovery key is generated only from a secure random generator ([CRY-1]): 32 bytes, used as is. It is
  never derived from a password or other human-chosen input.

### 6.3 Derived keys

- **[RK-4]** From a recovery key `rk`, an identity's two recovery key pairs are derived with the identity's realm and
  username (§7):
  ```
  ctx            = canonical({ "realm": realm, "username": username })
  sign_seed      = HKDF(rk, "", frame("rootcard/recovery/sign/v1", ctx))     Ed25519 seed: the recovery signing key
  box_secret     = HKDF(rk, "", frame("rootcard/recovery/box/v1", ctx))      X25519 private key: the recovery lock key
  ```
  The public recovery signing key appears in the log as `recovery`. The public recovery lock key is the `box` of the
  recovery lock (§11.3).

  *Rationale:* binding the derivation to realm and username makes identities created from the same recovery key
  unlinkable (their recovery public keys differ), and no key is shared between identities. No Argon2id is needed: the
  key already has 256 bits of entropy.
- **[RK-5]** The key tool MUST check that the derived recovery signing key equals the **current** recovery key of the
  log it operates on before signing anything with it. → `wrong_recovery_key`

---

## 7. Realm, username, inception and account id

### 7.1 Realm

- **[RLM-1]** A realm is 1 to 64 characters from `a–z 0–9 . _ -`, beginning and ending with `a–z` or `0–9`. →
  `bad_realm`
- **[RLM-2]** The realm `global` means "not bound to one application". It has no other special meaning in the format.
- **[RLM-3]** Every verifier is configured with the realms it accepts (a host: the realms it serves). A log whose realm
  is not accepted is rejected. → `realm_not_accepted`

### 7.2 Username

- **[USR-1]** **Format rule** (checked by every verifier): a username is 1 to 32 characters from ASCII `A–Z a–z 0–9 _
  -`, beginning with `A–Z a–z 0–9`. → `bad_username`
- **[USR-2]** A username is **case-preserving**: `Astra` and `astra` are different usernames and give different ids. Two
  usernames are **similar** when they are equal after ASCII lower-casing (§8.2).
- **[USR-3]** An application chooses a **username policy**, a predicate that is at least as strict as [USR-1]. The
  **default policy** is 3 to 20 characters, beginning with `A–Z a–z`. Hosts apply the policy of the realm at
  registration ([HST-3]) → `username_policy`; verifiers of logs received from elsewhere apply only [USR-1].
- **[USR-4]** A username never changes. It is part of the inception.

### 7.3 Inception and account id

- **[ID-1]** The **inception** is the log event with `seq` 0:
  ```
  { "v": 1, "kind": "incept", "seq": 0,
    "body": { "realm": realm, "username": username, "recovery": "ed25519:<recovery signing public key>" },
    "sigs": [ { "key": "ed25519:<recovery signing public key>", "sig": "<signature>" } ] }
  ```
  where `sig = Ed25519.sign(sign_seed, frame("rootcard/event/v1", inception without sigs))`. The inception has no
  `time`, no `account` and no `prev`.
- **[ID-2]** The inception is **deterministic**: the same recovery key, realm and username always give byte-identical
  inceptions, because the derivation ([RK-4]), the canonical encoding and Ed25519 signatures are deterministic.
- **[ID-3]** The **account id** is `SHA-256(frame("rootcard/id/v1", inception without sigs))`, written as 52 characters
  of Crockford base32 ([B32-2]) in strict form. Ids are compared as strings. In JSON, an account id is always the strict
  52-character form. → `bad_field`
- **[ID-4]** The account id never changes: instances, passwords and recovery keys change, the id stays.

---

## 8. Handles and tags

### 8.1 Handle

- **[HDL-1]** The **tag** of an identity is the first 4 characters of its account id. The **handle** is `username + "#"
  + tag`, for example `Astra#3F9C`.
- **[HDL-2]** Applications display the handle and **compare the full account id**, never the handle. The tag is a human
  aid (20 bits); it can be matched by brute force, the id cannot (THREAT_MODEL.md T2).
- **[HDL-3]** Parsing a typed handle: split at the **last** `#`; the part before is a username ([USR-1]) → `bad_handle`;
  the part after is a tag of exactly 4 characters, optionally followed by `-` and 1 to 48 further characters (an
  extended tag, §8.2), decoded leniently ([B32-4]) and re-encoded in strict upper case → `bad_handle`.

### 8.2 Collisions and extended tags

- **[HDL-4]** Two identities **collide** when their usernames are similar ([USR-2]) and their tags are equal.
- **[HDL-5]** A host never registers an identity that collides with one it already stores, retired identities included
  ([HST-4]). → `handle_taken`
- **[HDL-6]** When a verifier knows a set `C` of two or more colliding identities (collisions can arrive by propagation,
  [HST-15]), it displays each of them with an **extended tag**: let `n` be the smallest integer ≥ 5 such that the first
  `n` characters of the ids in `C` are pairwise distinct; the extended tag of an id is its first 4 characters, `-`, and
  its characters 5 to `n`. Example: `Astra#3F9C-K2`. Identities that collide with nothing keep the plain tag.
- **[HDL-7]** A lookup by a plain handle that matches more than one identity fails and returns the candidates with their
  extended tags. → `ambiguous_handle`

---

## 9. The identity log

### 9.1 Events

- **[LOG-1]** A log is a non-empty array of at most **1 000** events. Event `i` has `seq` `i`. → `too_many_events`
- **[LOG-2]** Each event is at most **4 KiB**. → `too_large`
- **[LOG-3]** Every event after the inception has this schema:
  ```
  { "v": 1, "account": "<account id>", "seq": n, "prev": "<b64u event hash of event n−1>",
    "kind": "<kind>", "time": t, "body": { ... }, "sigs": [ { "key": "ed25519:…", "sig": "…" }, ... ] }
  ```
  `time` is an integer 0 … 2⁵³−1, the owner's clock in Unix seconds. `prev` decodes to 32 bytes.
- **[LOG-4]** The kinds of format version 1 and their bodies:

  | `kind` | `body` | `sigs`, in this order | Effect |
  |---|---|---|---|
  | `incept` | `realm`, `username`, `recovery` (§7.3) | current recovery key | The identity exists, with no instance |
  | `instance` | `account_key` (`ed25519`), `home` `{ key: "ed25519:…", url }`, `reason` | current recovery key, `account_key`, `home.key` (receipt) | A new instance; every earlier one becomes invalid |
  | `rotate_recovery` | `recovery` (`ed25519`): the new recovery key | current recovery key, new `recovery` | The new key is the current recovery key |
  | `retire` | `{}` (empty object) | current recovery key | The identity is closed forever |

  `home.url` is a string of 1 to 256 printable ASCII characters (`0x21`–`0x7E`) → `bad_field`; its meaning is defined by
  the binding (HOST_PROTOCOL.md: the host's https base URL). `reason` is one of `register`, `revoke`, `restore`, `fresh`
  → `bad_reason`.

### 9.2 Hash and signatures

- **[LOG-5]** The **event hash** of any event `e`, the inception included, is `SHA-256(frame("rootcard/event/v1", e
  without sigs))`. Signatures are not part of the hash.
- **[LOG-6]** An owner signature (the recovery keys, the account key) on event `e` is `Ed25519.sign(sk,
  frame("rootcard/event/v1", e without sigs))`. Each `sigs` entry names its key in `key` and holds the signature in
  `sig`.
- **[LOG-7]** **Proof of possession:** every key that enters the log (`recovery` in `incept` and `rotate_recovery`,
  `account_key` and `home.key` in `instance`) signs the event that introduces it. Nobody can name someone else's public
  key.

### 9.3 Receipt

- **[LOG-8]** The receipt is the primary host's signature `Ed25519.sign(host_sk, frame("rootcard/receipt/v1", e without
  sigs))`, the third entry of an `instance` event's `sigs`. A host creates it only after the checks of [HST-6]. An
  `instance` event without a valid receipt is invalid, so no instance exists without the consent of its primary host. →
  `bad_receipt`
- **[LOG-9]** An `instance` event that is complete except for the receipt (its `sigs` has the first two entries) is a
  **pending instance**. It is what a client or the key tool submits to a host; it never appears in a log.
  `verify_pending(log_state, event, now)` checks it like [LOG-12] step 4 against the log it extends, with `now` given,
  expecting the two owner entries in `sigs` and skipping the receipt check.

### 9.4 Instances

- **[LOG-10]** The **current instance** of a log is its last `instance` event, if there is one and the log is not
  retired. Its `account_key` is the only valid account key of the identity and its `home` is the primary host.
- **[LOG-11]** `reason` is informational, with these constraints → `bad_reason`: `register` only when the log has no
  earlier `instance`; `revoke` and `restore` only when it has one; `fresh` always. *Meaning:* `register` is the first
  instance; `revoke` drops password locks; `restore` carries the vault over, usually to another host; `fresh` starts
  with an empty vault and profile.

### 9.5 Verifying a log

**[LOG-12]** `verify_log(events, options)` takes the events and the options `realms` (the accepted realms) and
optionally `now` (Unix seconds; when given, enables the future-time check), and returns the **log state** or an error.
It performs these steps in order:

1. `events` is an array of 1 to 1 000 entries. → `bad_field` if it is empty, `too_many_events` if it is longer
2. Every event satisfies [LOG-2] and the schema of its kind ([LOG-3], [LOG-4], [ID-1]), checked event by event in order.
   The schema fixes member names, types, encodings and the sets of `kind` and `reason`; other values are checked in the
   steps below. Event 0 has `kind` `incept`, and no later event does. → `too_large`, `bad_field`, `unsupported_version`,
   `bad_key`, `bad_reason`; a kind other than the four of [LOG-4], or `incept` after event 0 → `bad_kind`
3. **Inception:** `seq` is 0 → `bad_seq`; `body.realm` is valid → `bad_realm` and accepted → `realm_not_accepted`;
   `body.username` is valid → `bad_username`; `sigs` has exactly one entry with `key` equal to `body.recovery` →
   `wrong_signer`; the signature verifies strictly ([CRY-3]) → `bad_signature`. Set `account` = the account id ([ID-3]),
   `recovery` = `body.recovery`, `last_time` = 0, `keys` = { `body.recovery` } (every recovery and account key so far),
   `homes` = { } (every home key so far), no current instance, not retired.
4. For each later event `e` at index `i`, in order:
   1. The log is not retired. → `account_retired`
   2. `e.account` equals `account`. → `account_mismatch`
   3. `e.seq` equals `i`. → `bad_seq`
   4. `e.prev` equals the event hash of event `i − 1`. → `bad_prev`
   5. `e.time` ≥ `last_time`. → `time_backwards`
   6. If `now` is given: `e.time` ≤ `now + 600`. → `future_time`
   7. `sigs` has exactly the entries of [LOG-4] for the kind, in that order, each `key` equal to the expected key. →
      `wrong_signer`
   8. The keys named in the event's body are pairwise distinct; `body.recovery` and `body.account_key` are in neither
      `keys` nor `homes`; `body.home.key` is not in `keys` (a host may be the home of several instances). → `key_reuse`
   9. `reason` satisfies [LOG-11]. → `bad_reason`
   10. Every owner signature verifies strictly against `frame("rootcard/event/v1", e without sigs)` → `bad_signature`;
       for `instance`, the receipt verifies against `frame("rootcard/receipt/v1", e without sigs)` with `home.key` →
       `bad_receipt`.
   11. Apply the effect: `instance` sets the current instance to `e`, adds `account_key` to `keys` and `home.key` to
       `homes`; `rotate_recovery` sets `recovery` to `body.recovery` and adds it to `keys`; `retire` marks the log
       retired. Set `last_time` = `e.time`.
5. Return the log state:
   ```
   { account, realm, username, handle, recovery,          the current recovery key
     instance?: { hash, seq, account_key, home, reason },  absent if none or retired
     retired, version: { seq, hash }, time }              the last event; time is 0 for a log of only the inception
   ```

- **[LOG-13]** Only the recovery key current after event `n − 1` can create event `n` (step 4.7). Nothing reachable with
  a password or an account key can change the log ([PWR-1]).
- **[LOG-14]** After `retire` no event is valid (step 4.1), no instance is current and nobody can log in.

---

## 10. Versions

- **[VER-1]** The **version** of a valid log is `{ "seq": s, "hash": "<b64u>" }` of its last event. Two logs of the same
  account with the same version are the same log (the hash chain covers every earlier event).
- **[VER-2]** **Total order.** For two valid logs `a` and `b` of the same account, `newer(a, b)` is true if and only if
  the key `(retired, time, seq)` of `a`'s log state is greater than that of `b` in lexicographic order (`retired` counts
  as 1 and not retired as 0; `time` is the log state's `time`), or the keys are equal and `a`'s version hash is
  **smaller** than `b`'s as unsigned bytes. Logs of different accounts are not ordered. → `account_mismatch`
- **[VER-3]** Consequences (Appendix A proves them):
  1. If `b` extends `a` (`a` is a proper prefix of `b`), `b` is newer.
  2. A retired log is newer than every log that is not retired: retiring is final.
  3. Of two branches (logs that share a prefix and then differ, which only a recovery-key holder can create), the one
     whose last event has the later `time` wins; on equal time the longer, then the lower hash. Every party applies the
     same rule and converges.
  4. The order is total and transitive, so "the latest version" is well defined among any set of valid logs.
- **[VER-4]** **Monotonicity.** Every host, client and key tool keeps, per identity, the newest valid log it has seen
  and replaces it only with a newer one ([VER-2]). It never moves back to an older version. → `stale_version`
- **[VER-5]** **Carrying forward.** A party that holds a newer log than a host it talks to SHOULD send it the missing
  events ([HST-14]). A host that holds a newer log than a request refers to answers `stale_version` with its version and
  events.
- **[VER-6]** Vaults and public profiles have a per-instance revision `rev` (§11, §12) that only increases. They are
  valid only for the current instance of the newest log the verifier knows.

---

## 11. The vault

A vault belongs to exactly one instance. It holds the instance's account key and the private data, encrypted under a
32-byte random **vault key**, which is wrapped to each **lock**.

### 11.1 Structure

```
Vault {
  "v": 1,
  "account":  "<account id>",
  "instance": "<b64u event hash of the instance event>",
  "rev":      n,                                       1 … 2^32, increases with every change within the instance
  "locks": {
    "gen":  g,                                         1 … 2^32, increases with every change of the lock set
    "list": [ Lock, ... ],                             1 … 16 locks
    "sig":  "<recovery key signature, [LCK-3]>"
  },
  "nonce": "<b64u 12 bytes>",
  "ct":    "<b64u AES-256-GCM(vault key, contents) ‖ tag>",
  "sig":   "<account key signature, [VLT-2]>"
}
```

### 11.2 Signature and validity

- **[VLT-1]** A vault is at most **96 KiB**. → `too_large`
- **[VLT-2]** `sig` is `Ed25519.sign(account key, frame("rootcard/vault/v1", vault without sig))` by the account key of
  the instance named in `instance`.
- **[VLT-3]** `verify_vault(vault, log_state)` performs, in order: schema ([CJ-11]) → `bad_field`/`unsupported_version`;
  `account` equals the log's account → `account_mismatch`; the log is not retired → `account_retired`; the log has a
  current instance → `no_instance`; `instance` equals its hash → `wrong_instance`; the lock set is valid ([LCK-1],
  [LCK-2], [LCK-6]) → `bad_locks`, `bad_field`, `kdf_params`; `locks.sig` verifies with the log's current recovery key
  ([LCK-3]) → `bad_signature`; `sig` verifies with the instance's `account_key` → `bad_signature`.
- **[VLT-4]** Within an instance, a party that stores a vault replaces it only with one that has a greater `rev` →
  `stale_rev`, a `locks.gen` not smaller than the stored one → `stale_locks`, and, if `locks.gen` is equal, a
  byte-identical `locks` member → `stale_locks`. `rev` and `gen` start at 1 in each new instance.
- **[VLT-5]** A vault never leaves the primary host except to a party that has proven a lock ([FET-1]) or holds a
  session ([HST-10]), and in account files the user downloads (§15.1). Hosts never pass vaults to other hosts
  ([HST-13]).

### 11.3 Locks

```
password lock  { "id": "<b64u 8 random bytes>", "kind": "password", "label": "<1–64 characters>",
                 "kdf": { "alg": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": "<b64u 16 random bytes>" },
                 "auth": "ed25519:<fetch key>", "box": "x25519:<lock key>",
                 "wrap": { "epk": "x25519:<ephemeral key>", "nonce": "<b64u 12 bytes>", "ct": "<b64u 48 bytes>" } }
recovery lock  { "id": "recovery", "kind": "recovery", "box": "x25519:<recovery lock key>",
                 "wrap": { "epk": "…", "nonce": "…", "ct": "…" } }
```

- **[LCK-1]** `locks.list` has 1 to 16 locks, ids are unique, exactly one lock has `kind` `recovery` and its id is
  `recovery`, and every other lock has `kind` `password` and an id of 8 bytes. → `bad_locks`
- **[LCK-2]** A `label` is 1 to 64 Unicode scalar values with no code point below U+0020 and no U+007F. → `bad_field`.
  Labels can be read by anyone who can look a vault's locks up at its primary host ([FET-2]); they SHOULD NOT hold
  secrets.
- **[LCK-3]** `locks.sig` is `Ed25519.sign(recovery signing key, frame("rootcard/locks/v1", { "account": …, "instance":
  …, "gen": g, "list": [ … ] }))` by the recovery key **current at the verifier's newest log**. Only the recovery key
  can change who can unlock a vault ([PWR-2]).
- **[LCK-4]** Whoever creates a lock set MUST make the recovery lock's `box` the public key of the recovery lock key
  ([RK-4]) of the current recovery key. Hosts cannot check this (they never see a recovery key); the recovery signature
  ([LCK-3]) vouches for it. A `rotate_recovery` therefore requires a new lock set with a new recovery lock ([KT-5]).
- **[LCK-5]** A vault MAY have no password lock (all were revoked). It can then be unlocked only with the recovery key.
- **[LCK-6]** Argon2id parameters: `alg` is `argon2id`; `p` = 1; `47104 ≤ m ≤ 1048576` (46 MiB to 1 GiB); `2 ≤ t ≤ 16`.
  The default for new locks is `m = 65536, t = 3, p = 1`. A lock outside these bounds is invalid, and a client MUST NOT
  run Argon2id with parameters outside them. → `kdf_params`

### 11.4 Key derivation and wrapping

**[LCK-7]** **Password lock keys.** For the identity `account`, the lock id `lock` (the decoded 8 bytes are not used;
the `id` string is) and a password `pw`:
```
pw_bytes   = UTF-8(NFC(pw))                                     Unicode Normalization Form C
a          = Argon2id(pw_bytes, salt, m, t, p)
ctx        = canonical({ "account": account, "lock": lock })
auth_seed  = HKDF(a, "", frame("rootcard/password/auth/v1", ctx))     Ed25519 seed  → "auth"
box_secret = HKDF(a, "", frame("rootcard/password/box/v1",  ctx))     X25519 secret → "box"
```
`auth` and `box` do not depend on the instance, so a lock carries over to a new instance unchanged ([KT-3]) and the key
tool can wrap a new vault key to it without knowing the password.

**[LCK-8]** **Password rules** (checked by whatever creates a lock, since no host ever sees a password): at least 12
Unicode scalar values after NFC, at most 1 024 UTF-8 bytes, not equal to the username compared with ASCII case folding →
`weak_password`. A client SHOULD also reject passwords from a list of common passwords and SHOULD show a strength
estimate that suggests a passphrase.

**[LCK-9]** **Wrapping** the vault key `vk` to a lock with public key `B` (its `box`), for vault `account` and
`instance`:
```
e      = 32 random bytes (X25519 secret);  E = X25519 public key of e  → wrap.epk
s      = X25519(e, B)                                                   fails on all-zero output [CRY-4]
ctx    = canonical({ "account": account, "instance": instance, "lock": lock id })
wk     = HKDF(s, E ‖ B, frame("rootcard/wrap/v1", ctx))                 salt: raw 32-byte E then raw 32-byte B
wrap.ct = AES-256-GCM(wk, wrap.nonce, vk, aad = empty)                   48 bytes
```
**Unwrapping** with the lock secret `b`: check that the public key of `b` equals the lock's `box` → `unlock_failed`; `s
= X25519(b, E)` → `bad_key`; derive `wk` as above; decrypt → `unlock_failed`. The result is 32 bytes → `unlock_failed`.

*Note:* the `box` check makes a wrong password fail without decryption; it adds nothing an attacker who holds the vault
does not already have.

### 11.5 Contents

- **[VLT-6]** The contents are encrypted as `ct = AES-256-GCM(vk, nonce, canonical(contents), aad)` with `aad =
  frame("rootcard/contents/v1", vault without nonce, ct and sig)`. Each encryption uses a fresh nonce ([CRY-7]).
- **[VLT-7]** The contents have this schema, and their canonical form is at most **64 KiB** → `too_large`:
  ```
  Contents { "v": 1,
             "account_seed": "<b64u 32-byte Ed25519 seed of the instance account key>",
             "data":  { "<key>": <value>, ... },                           private data, §12.2
             "known"?: { "<account id>": { "handle": "<handle>", "version": { "seq", "hash" } }, ... } }
  ```
  Keys of `data` follow [DAT-4] → `bad_data_key`, and `data` is at most 48 KiB ([DAT-6]). The keys of `known` are
  account ids in strict form → `bad_field`. `known` records identities the user has dealt with, the user's own included:
  their full id, their handle as last seen and the newest version seen ([CLT-4], [VER-4]).
- **[VLT-8]** `unlock(vault, log_state, secret)` performs, in order: `verify_vault` ([VLT-3]); select the lock (by id
  for a password, `recovery` for the recovery key) → `bad_locks` if absent; derive the lock secret ([LCK-7] or [RK-4])
  and unwrap ([LCK-9]); decrypt the contents → `unlock_failed`; parse and check the contents ([VLT-7]) → `bad_json`,
  `bad_field`, `too_large`; the Ed25519 public key of `account_seed` equals the instance's `account_key` →
  `wrong_account_key`.
- **[VLT-9]** The contents never hold the recovery key.

---

## 12. Arbitrary data: public profile and private data

### 12.1 Public profile

```
PublicProfile { "v": 1, "account": "<account id>", "instance": "<b64u instance event hash>", "rev": n,
                "data": { "<key>": <value>, ... },
                "sig": "<Ed25519.sign(account key, frame("rootcard/public/v1", profile without sig))>" }
```

- **[DAT-1]** A public profile is at most **16 KiB**. → `too_large`
- **[DAT-2]** `verify_public(profile, log_state)` performs, in order: schema → `bad_field`/`unsupported_version`;
  `account` → `account_mismatch`; not retired → `account_retired`; current instance exists → `no_instance`; `instance`
  is its hash → `wrong_instance`; every data key is valid ([DAT-4]) → `bad_data_key`; `sig` verifies with the instance's
  `account_key` → `bad_signature`. `rev` is 1 … 2³² → `bad_field`.
- **[DAT-3]** A party that stores a profile replaces it only with a valid one of a greater `rev` for the same instance →
  `stale_rev`. `rev` starts at 1 in each instance. A profile of any other instance is invalid ([VER-6]).

### 12.2 Keys, values and namespaces

- **[DAT-4]** A data key (in a public profile's or the contents' `data`) is 1 to 64 characters from `a–z 0–9 . _ -` and
  has a namespace prefix: `user.` (belongs to the user) or `app.<name>.` (belongs to one application), where `<name>` is
  1 to 32 characters from `a–z 0–9 -` beginning with `a–z 0–9`, and at least one character follows the prefix. Other
  prefixes are reserved for future versions. → `bad_data_key`
- **[DAT-5]** A data value is any rootcard JSON value (§2.1). It is subject only to the size and depth limits.
- **[DAT-6]** The private data (`data` in the contents) is at most **48 KiB** in canonical form. → `too_large`
- **[DAT-7]** An application client writes only its own namespace `app.<name>.` and `user.`; it MAY read every key. The
  libraries' write functions take the application's namespace and refuse keys outside it and `user.`. → `bad_data_key`
- **[DAT-8]** Hosts and clients display data values only as text or data, never interpret them as HTML, script, markup
  or URLs to load, and enforce the limits on everything they accept.
- **[DAT-9]** A public profile is public and can be copied by anyone; an update does not remove older copies. A client
  SHOULD say so before saving.

---

## 13. Vault fetch and login

Both start with a **challenge** from the primary host.

### 13.1 Challenges

- **[CHL-1]** A challenge is `{ "nonce": "<b64u 32 random bytes>", "host": "ed25519:<host key>", "realm": realm,
  "version": { seq, hash }, "expires": t }`, issued for one account and one purpose (`fetch` or `login`).
- **[CHL-2]** A challenge is valid **once**, for its account and purpose, and until `expires`, which is at most **60 s**
  after issue. Using an unknown, used or other-purpose nonce → `challenge_unknown`; an expired one →
  `challenge_expired`. The host consumes a nonce on its first use, whether the answer verifies or not.

### 13.2 Vault fetch

- **[FET-1]** To obtain the vault without a session, a party proves a lock: it signs `frame("rootcard/fetch/v1", {
  "account": …, "host": …, "lock": "<lock id>", "nonce": … })` with the lock's `auth` key (a password lock, [LCK-7]) or
  with the current recovery signing key (the `recovery` lock). The host verifies the signature against the lock's `auth`
  key, respectively the log's current recovery key, and returns the vault. → `bad_signature`
- **[FET-2]** Before a fetch, the primary host gives anyone who asks the **lock hints**: for each password lock, `id`,
  `label` and `kdf`, and nothing else (not `auth`, `box` or `wrap`). A client needs them to run Argon2id. Hints are not
  signed.
- **[FET-3]** Fetches and lock hints are rate limited per identity and per network address ([HST-16]). Each failed fetch
  is one online password guess.

### 13.3 Login

**[LGN-1]** A login runs at the primary host:
1. The client obtains the host's newest log for the identity, merges it with its own ([VER-4]) and, if its own is newer,
   sends the missing events first ([VER-5]).
2. The client checks that the current instance's `home` is the host it is talking to: `home.key` equals the host's key
   and the connection goes to `home.url` → otherwise it stops with `not_home`.
3. The client obtains a vault of the current instance: from its own storage if it has one, otherwise by a vault fetch
   (§13.2). It unlocks it ([VLT-8]).
4. The client requests a `login` challenge and checks `challenge.host` = `home.key`, `challenge.realm` = the log's realm
   → `wrong_host`, and `challenge.version` = its version → `stale_version` (it then fetches the newer log and restarts).
5. The client signs the **login message** with the account key and sends `{ account, nonce, version, sig }`:
   ```
   sig = Ed25519.sign(account key, frame("rootcard/login/v1",
           { "account": …, "host": "ed25519:<host key>", "nonce": …, "realm": …, "version": { seq, hash } }))
   ```
6. The host checks, in order: the account exists and is not retired → `unknown_account`, `account_retired`; it is the
   home of the current instance → `not_home`; the nonce ([CHL-2]) → `challenge_unknown`, `challenge_expired`; `version`
   equals its current version exactly → `stale_version`; the signature with the current instance's `account_key` →
   `bad_signature`. It then opens a session ([HST-10]).

- **[LGN-2]** The account key exists only in the unlocked vault in the client's memory. Clients import it
  non-extractable where the platform allows it and erase the raw bytes ([IMP-2]).
- **[LGN-3]** No step sends the password, a value derived from it, the vault key or the account key's private part to
  any host. A host learns only signatures and, at a fetch, which lock was used.

---

## 14. Proofs

A proof shows a verifier, who may be another user or another host, that the prover controls an identity now.

### 14.1 Structure

```
Proof { "v": 1, "by": "account" | "recovery", "account": "<account id>",
        "instance": "<b64u instance hash>",         present if and only if by = "account"
        "challenge": "<b64u 32 bytes>", "recipient": "<1–256 bytes>",
        "sig": "<Ed25519.sign(key, frame("rootcard/proof/v1", proof without sig))>" }
```

- **[PRF-1]** An **account proof** (`by` `account`) is signed by the account key of the instance it names. It is valid
  while that instance is current: a later `rotate_recovery` does not invalidate it, a new instance or `retire` does.
- **[PRF-2]** A **root proof** (`by` `recovery`) is signed by the recovery signing key and is independent of instances.
  It is valid while that key is the current recovery key. It is made only in the key tool ([PWR-6]), for example to show
  that two identities have the same owner.
- **[PRF-3]** `recipient` names the verifier (its account id, its host key, or another identifier the verifier chooses
  and checks), so that a proof cannot be forwarded to a third party. It is 1 to 256 UTF-8 bytes.

### 14.2 Verification

**[PRF-4]** `verify_proof(proof, log, expected)` takes the proof, the newest log the verifier knows for the account
(after merging what the prover sent, [VER-4]), and the expected `challenge` and `recipient`. In order:
1. Schema → `bad_field`/`unsupported_version`; `verify_log` → its code; `account` equals the log's account →
   `account_mismatch`; the log is not retired → `account_retired`.
2. `challenge` equals the expected challenge → `wrong_challenge`; `recipient` equals the expected recipient →
   `wrong_recipient`.
3. For `account`: the log has a current instance → `no_instance`, and `instance` is its hash → `stale_version`; the key
   is its `account_key`. For `recovery`: the key is the log's current recovery key.
4. The signature verifies strictly → `bad_signature`.

- **[PRF-5]** An interactive proof uses a fresh random challenge from the verifier. A proof that is not interactive
  signs a **statement**: `challenge = SHA-256(frame("rootcard/statement/v1", { "statement": <any rootcard JSON value>
  }))`. A statement proof is replayable by design while the instance is current, and the statement SHOULD therefore say
  what it is for and until when.

---

## 15. Account file and recovery card

### 15.1 Account file

```
{ "format": "rootcard-account", "v": 1, "realm": …, "account": …, "handle": …, "version": { seq, hash },
  "log": [ … ], "public"?: PublicProfile, "vault"?: Vault, "host_data"?: { … } }
```

- **[FIL-1]** An account file is at most **5 MiB**. Its file name SHOULD be `<username>-<tag>.rootcard.json`. →
  `too_large`
- **[FIL-2]** A logged-in user can always export the account file of the current instance: the log, the current public
  profile, the current vault, and optionally `host_data`, an object of at most 16 KiB that the primary host adds for
  information. `host_data` is not signed and MUST NOT be trusted or used for any decision.
- **[FIL-3]** `import_account(file, options)` performs, in order: `format` is `rootcard-account` → `bad_field`; schema →
  `bad_field`/`unsupported_version`; `verify_log` → its code; `account`, `realm`, `handle` and `version` equal the log
  state's → `account_mismatch`; `public` and `vault`, if present, verify against the log state ([DAT-2], [VLT-3]) →
  their codes.
- **[FIL-4]** An account file contains no plaintext secret, but its vault can be attacked offline with password guesses
  (THREAT_MODEL.md AR1). It is current only while its version is the newest: a file whose log is older than the
  verifier's still serves as evidence for the log, but its vault and profile are no longer valid ([VER-6]).

### 15.2 Recovery card

```
{ "format": "rootcard-card", "v": 1, "realm": …, "username": …, "account": "<account id>",
  "key": "RCR-…",                                  written form, [RK-1]
  "log"?: [ … ] }                                  only after a rotation, [CRD-2]
```

- **[CRD-1]** The recovery card holds everything needed to mint a new instance when nothing else is left ([KT-2],
  [KT-3]): the recovery key, the realm and the username, and the account id as a check.
- **[CRD-2]** If the card's key is not the inception's recovery key (it was rotated), `log` MUST hold the complete log
  from the inception up to and including the `rotate_recovery` event that introduced this key, because the inception
  cannot be re-derived from a rotated key.
- **[CRD-3]** `read_card(card)` performs, in order: `format` → `bad_field`; schema → `bad_field`/`unsupported_version`;
  `key` parses ([RK-2]) → `bad_base32`/`bad_checksum`; derive the keys ([RK-4]); without `log`: derive the inception
  ([ID-1]) and check its id equals `account` → `account_mismatch`; with `log`: `verify_log`, check `account`, `realm`
  and `username` → `account_mismatch`, and check the derived signing key is the log's current recovery key →
  `wrong_recovery_key`.
- **[CRD-4]** The machine form is the canonical JSON above, which is also the **QR payload** (byte mode, UTF-8). A card
  with `log` may be too large for a QR code and is then kept as a file. The printable text form SHOULD show the handle,
  realm, account id and the written key, with a warning that anyone who has the card controls the identity, and the
  account id and key SHOULD be printed in groups of 4.

---

## 16. Power levels

**The rule:** anything that changes **who can access** the identity, **where it lives** or **whether it exists** needs
the recovery key. Everything else needs at most the password. In doubt, a new feature is high power.

| | **Low power**: a password (the unlocked account key) | **High power**: the recovery key |
|---|---|---|
| Log in | At the primary host | (the key tool can log in with the account key it unlocks) |
| Data | Read and change private data and the public profile in the current instance | Clear or replace them with a new instance |
| Identity | Export the account file, give account proofs | Every log event, root proofs |
| Locks | None, not even changing one's own password | Add, revoke and replace locks |
| Instances, primary host | None | Mint instances (`restore`, `fresh`, `revoke`), choose and change the primary host |
| Root | None | Rotate the recovery key, retire |

- **[PWR-1]** Every log event requires the signature of the current recovery key ([LOG-13]).
- **[PWR-2]** Every lock set requires the signature of the current recovery key ([LCK-3]); a vault signed only by the
  account key cannot add, change or re-add a lock ([VLT-4]).
- **[PWR-3]** The account key can sign only: vaults (contents and `rev`, with a lock set the recovery key signed),
  public profiles, login messages, account proofs, and its self-signature on its own `instance` event.
- **[PWR-4]** A password lock's `auth` key can sign only vault fetches.
- **[PWR-5]** A password cannot be changed with the old password. Changing a password is adding a lock and revoking the
  old one, both with the recovery key ([KT-4]).
- **[PWR-6]** The recovery key is entered only in the key tool. An application client MUST NOT accept a recovery key as
  input. At registration, an application client MAY generate a recovery key; it then shows it once, uses it only to sign
  the registration, and erases it ([CLT-1]).

---

## 17. Hosts

A host serves one or more realms, has one Ed25519 host key, and is identified by it. These rules are normative for hosts
whatever binding they use. HOST_PROTOCOL.md maps them to HTTP.

### 17.1 Storage

- **[HST-1]** A host stores per identity: the newest valid log it has seen ([VER-4]); if it is the current primary host,
  the newest vault ([VLT-4]); the newest public profile of the current instance ([DAT-3]). Hosts map account ids to
  internal ids that never leave the host.
- **[HST-2]** A host stores no password, no password hash and nothing derived from a password other than what the vault
  it holds as primary host contains. It never hands out a vault except per [VLT-5].

### 17.2 Registration and instances

- **[HST-3]** **Registration** submits `[inception, pending instance]` with `reason` `register`, a vault and optionally
  a public profile. The host checks, in order: the realm is one it serves → `realm_not_accepted`; the username satisfies
  the realm's policy → `username_policy`; `verify_log([inception])` and `verify_pending` ([LOG-9]) → their codes; the
  host does not already store a log for the account → `stale_version`, answered with its log (an owner who wants an
  instance here uses the key tool, [KT-3]); the instance's `home.key` is this host's key → `wrong_host`; the time window
  ([HST-6]) → `bad_time`; the handle is free ([HST-4]) → `handle_taken`; the vault ([VLT-3]) and profile ([DAT-2])
  verify → their codes; the vault has a password lock → `bad_locks`. It then adds the receipt, stores everything and
  answers with the account id, the handle and the version.
- **[HST-4]** **Handle uniqueness:** a host never stores two identities that collide ([HDL-4]) unless the collision
  arrived by propagation ([HST-15]). Retired identities keep their handle reserved.
- **[HST-5]** **New instance** submits a pending instance, the events the host may be missing before it, a vault and
  optionally a profile. The host merges the missing events ([HST-14]) and then requires the pending instance's `prev` to
  be the hash of its current version → otherwise `stale_version`, answered with its version and the events the submitter
  lacks.
- **[HST-6]** A host adds its receipt only when: the event is the next event of its newest log; `home.key` is this
  host's key and `home.url` this host's address → `wrong_host`; the event's `time` is within **600 s** of the host's
  clock (`|time − now| ≤ 600`) → `bad_time`; the realm is one it serves; the vault for the new instance verifies. The
  receipt therefore attests that the instance was made at about `time`.
- **[HST-7]** On adopting a log whose current instance differs from its previous one, a host immediately revokes every
  session of the previous instances ([HST-11]). If it is no longer the primary host, it deletes the vault and answers
  logins and fetches with `not_home` and the address of the primary host. A session that was revoked is never restored,
  even if a branch switch ([VER-3]) makes an older instance current again.
- **[HST-8]** On adopting a retired log, a host revokes every session, deletes the vault and the public profile, keeps
  the complete log so that the id is never reused, and answers with `account_retired`.

### 17.3 Fetch, login and sessions

- **[HST-9]** Only the primary host gives lock hints, fetches vaults ([FET-1]) and accepts logins ([LGN-1]); every other
  host answers `not_home` with the primary host's `home`.
- **[HST-10]** A session is created only by a successful login. It belongs to one host, one account and one instance. A
  session token is at least 32 random bytes and the host stores only its SHA-256 hash. With a session, the user may read
  and replace the vault ([VLT-4]) and the public profile ([DAT-3]), and export the account file ([FIL-2]).
- **[HST-11]** A session ends on logout, after at most **24 h** without use, and on any new instance or retirement
  ([HST-7], [HST-8]).
- **[HST-12]** The primary host accepts a vault replacement only if the new vault verifies ([VLT-3]) and satisfies
  [VLT-4], and either the request carries a session of the current instance, or the new `locks.gen` is greater than the
  stored one (a new lock set signed by the current recovery key authorizes the replacement, so the key tool needs no
  session) → `unauthorized`. A session alone cannot change the lock set: [VLT-4] and [LCK-3] require a recovery
  signature for it. After adopting a `rotate_recovery`, a stored vault no longer verifies ([LCK-3]) until it is replaced
  this way; the key tool therefore submits a rotation to the primary host together with the new vault ([KT-5]).

### 17.4 Sharing between hosts

- **[HST-13]** **Only the public log and the public profile are shared** between hosts. Vaults and anything derived from
  passwords never leave the primary host ([VLT-5]).
- **[HST-14]** A host accepts events and logs from anyone (clients, peers) and verifies them itself ([LOG-12] with
  `now`); it never trusts another host's claim. It adopts a received log only if it is newer ([VER-2]); otherwise it
  answers `stale_version` with its version.
- **[HST-15]** Hosts that serve the same realm MAY be configured as **peers** by exchanging host keys. A host SHOULD
  push new events and profiles to its peers, MUST push a new `instance` to the previous primary host when it can reach
  it, and SHOULD pull from its peers periodically. Collisions revealed by sharing are shown with extended tags
  ([HDL-6]).
- **[HST-16]** A host SHOULD rate limit registrations, lock hints, challenges, fetches, logins and event submissions per
  network address and per identity. HOST_PROTOCOL.md gives recommended limits. → `rate_limited`

---

## 18. Clients and the key tool

### 18.1 Application clients

- **[CLT-1]** **Registration** in an application client: the user picks a username, a realm the host serves and a
  password ([LCK-8]). The client generates a recovery key ([RK-3]), shows it once as text and as a recovery card
  ([CRD-4]), SHOULD require the user to retype two groups chosen at random, builds the inception, the pending instance
  (`reason` `register`, `home` = this host), a vault with one password lock and the recovery lock, and an empty public
  profile (`rev` 1), submits them ([HST-3]) and erases the recovery key. The safest alternative is to register in the
  key tool.
- **[CLT-2]** A client stores, per identity it has seen, the newest verified log ([VER-4]) and never logs in with, or
  accepts a vault or profile of, an older version.
- **[CLT-3]** A client logs in only at the primary host ([LGN-1] step 2) and checks every challenge ([LGN-1] step 4).
- **[CLT-4]** A client SHOULD record the full id of identities the user deals with in `known` ([VLT-7]) and MUST warn
  when a handle it knows appears with a different account id.
- **[CLT-5]** An application links to the key tool for every high-power operation and warns: "Only enter your recovery
  key in the key tool."

### 18.2 The key tool

- **[KT-1]** The key tool is the `rootcard` CLI or `keytool.html`. It makes no network request except to hosts the user
  chooses, and it works without a network for every operation that needs none.
- **[KT-2]** **Finding the newest version:** before any operation that creates an event or a lock set, the key tool
  gathers the logs it can reach (the chosen hosts, account files, the card) and uses the newest ([VER-2]). If it found
  none, it builds on the inception derived from the card.
- **[KT-3]** **Restore and fresh** (a new instance, on the same or another host): generate a new account key and a new
  vault key, build a pending instance on top of the newest version ([KT-2]) with `home` = the chosen host, and submit it
  with the new vault and profile ([HST-5]). `restore`: unlock the current vault with the recovery lock (fetched with a
  recovery-key fetch, [FET-1], or taken from an account file), copy `data` and `known` into new contents with the new
  `account_seed`, and build a new vault (`rev` 1, `gen` 1) whose locks are the old password locks with new wraps
  ([LCK-9]) and a new recovery lock; re-sign the public profile's `data` for the new instance (`rev` 1). `fresh`: a new
  empty vault with the recovery lock and a password lock chosen now, and an empty profile. If the host answers
  `stale_version`, rebuild on top of the events it returns.
- **[KT-4]** **Add a password:** unlock with the recovery lock, add a lock with a new id and salt, sign the lock set
  with `gen + 1`, increase `rev`, re-encrypt, sign with the account key, replace the vault at the primary host
  ([HST-12]). The log does not change. **Revoke a password:** a new instance with `reason` `revoke`, as `restore` but
  without the revoked locks. Revocation takes effect as soon as the primary host receipts it ([HST-7]).
- **[KT-5]** **Rotate the recovery key:** a `rotate_recovery` event signed by the old and the new key, and in the same
  submission a vault whose lock set (`gen + 1`) has a new recovery lock for the new key and is signed by it ([LCK-4]);
  then a new recovery card with `log` ([CRD-2]). The old card SHOULD be destroyed. *Note:* in format version 1, a
  rotation does not protect against someone who already holds the old key (THREAT_MODEL.md AR3).
- **[KT-6]** **Retire:** a `retire` event, after the user confirms that the identity is closed forever.
- **[KT-7]** The key tool shows the result of every operation as the newest version and the current instance, and warns
  when it detects a branch ([VER-3]).

### 18.3 Implementation requirements

- **[IMP-1]** The cores (`crates/rootcard`, `packages/rootcard`) do no I/O, read no clock and draw no randomness
  themselves. Time and random bytes are parameters, so every function is deterministic and testable with vectors.
- **[IMP-2]** Secrets (recovery key, derived seeds, Argon2id output, vault key, account key, lock secrets, passwords)
  are erased from memory as soon as they are no longer needed. JavaScript imports private keys into WebCrypto as
  non-extractable and overwrites the raw buffers.
- **[IMP-3]** A JavaScript environment without WebCrypto `Ed25519` and `X25519` is rejected with `unsupported_browser`.
  There is no weaker fallback.
- **[IMP-4]** Comparisons of secrets and of session tokens are constant-time.
- **[IMP-5]** Nothing that failed verification is used, stored, displayed as valid or passed on.

---

## 19. Limits

| What | Limit | Rule |
|---|---|---|
| JSON nesting depth | 32 | [CJ-5] |
| Event | 4 KiB | [LOG-2] |
| Events per log | 1 000 | [LOG-1] |
| Vault | 96 KiB | [VLT-1] |
| Vault contents | 64 KiB | [VLT-7] |
| Private data | 48 KiB | [DAT-6] |
| Locks per vault | 16 | [LCK-1] |
| Public profile | 16 KiB | [DAT-1] |
| Data key | 64 characters | [DAT-4] |
| Account file | 5 MiB | [FIL-1] |
| `host_data` | 16 KiB | [FIL-2] |
| `home.url` | 256 characters | [LOG-4] |
| Proof `recipient` | 256 bytes | [PRF-3] |
| Lock `label` | 64 characters | [LCK-2] |
| Challenge lifetime | 60 s | [CHL-2] |
| Future time | 600 s | [LOG-12] |
| Receipt time window | ± 600 s | [HST-6] |
| Session idle | 24 h | [HST-11] |
| Argon2id | `p = 1`, `46 MiB ≤ m ≤ 1 GiB`, `2 ≤ t ≤ 16` | [LCK-6] |
| `rev`, `gen` | 1 … 2³² | [VLT-4], [DAT-3] |

## 20. Error codes

Error codes are lower-case ASCII strings, stable across versions, for applications to translate. A reject vector names
its code ([CNV-4]).

| Code | Meaning | Rules |
|---|---|---|
| `bad_json` | Not rootcard JSON | CJ-1–CJ-6 |
| `bad_field` | A structure violates its schema: missing, unknown or mistyped member, bad encoding or length | CJ-11–CJ-13 |
| `unsupported_version` | A `v` this implementation does not support | CJ-12 |
| `too_large` | A size limit is exceeded | CJ-8, §19 |
| `bad_base64` | Not canonical unpadded base64url | B64-2 |
| `bad_base32` | Not valid Crockford base32 | B32-3, B32-4, RK-2 |
| `bad_checksum` | The recovery key's checksum does not match | RK-2 |
| `bad_key` | Unknown key type, wrong length, non-canonical or small-order point, X25519 zero output | KEY-1–KEY-3, CRY-4 |
| `bad_signature` | A signature does not verify strictly | CRY-3 and every signature rule |
| `bad_realm` | Not a valid realm | RLM-1 |
| `realm_not_accepted` | A realm the verifier does not accept | RLM-3 |
| `bad_username` | Not a valid username | USR-1 |
| `username_policy` | A valid username the realm's policy refuses | USR-3 |
| `bad_handle` | Not a valid handle | HDL-3 |
| `handle_taken` | The handle collides with a stored identity | HDL-5, HST-4 |
| `ambiguous_handle` | A plain handle matches several identities | HDL-7 |
| `account_mismatch` | Data of another account | LOG-12, VER-2, FIL-3, CRD-3 |
| `wrong_recovery_key` | The recovery key is not the current one | RK-5, CRD-3 |
| `too_many_events` | More than 1 000 events | LOG-1 |
| `bad_kind` | An unknown kind, or `incept` after event 0 | LOG-12 |
| `bad_seq` | `seq` is not the event's index | LOG-12 |
| `bad_prev` | `prev` is not the hash of the previous event | LOG-12 |
| `time_backwards` | `time` is before the previous event's | LOG-12 |
| `future_time` | `time` is more than 600 s ahead | LOG-12 |
| `bad_time` | A new instance's `time` is outside the receipt window | HST-6 |
| `wrong_signer` | The signers of an event are not exactly the required keys | LOG-12 |
| `key_reuse` | A key already used in the log, or twice in an event | LOG-12 |
| `bad_receipt` | The primary host's receipt does not verify | LOG-8 |
| `bad_reason` | `reason` is unknown or not allowed here | LOG-11 |
| `account_retired` | The identity is retired | LOG-14, HST-8 |
| `no_instance` | The log has no current instance | VLT-3, DAT-2, PRF-4 |
| `stale_version` | Not the newest version | VER-4, LGN-1, HST-5, PRF-4 |
| `wrong_instance` | A vault or profile of another instance | VLT-3, DAT-2 |
| `stale_rev` | `rev` does not increase | VLT-4, DAT-3 |
| `stale_locks` | The lock set goes backwards or changes without a new `gen` | VLT-4 |
| `bad_locks` | The lock set is malformed or lacks a required lock | LCK-1, VLT-8, HST-3 |
| `kdf_params` | Argon2id parameters out of bounds | LCK-6 |
| `weak_password` | The password breaks the password rules | LCK-8 |
| `unlock_failed` | Wrong password or recovery key, or a corrupted wrap or ciphertext | LCK-9, VLT-8 |
| `wrong_account_key` | The vault's account key is not the instance's | VLT-8 |
| `bad_data_key` | A data key is invalid or outside the writer's namespace | DAT-4, DAT-7 |
| `wrong_challenge` | A proof answers another challenge | PRF-4 |
| `wrong_recipient` | A proof is for another recipient | PRF-4 |
| `challenge_unknown` | An unknown, used or other-purpose nonce | CHL-2 |
| `challenge_expired` | An expired nonce | CHL-2 |
| `not_home` | This host is not the primary host | LGN-1, HST-7, HST-9 |
| `wrong_host` | A challenge or instance names another host | LGN-1, HST-3 |
| `unknown_account` | The host does not know the account | LGN-1 |
| `unauthorized` | No valid session, or a vault replacement that is not authorized | HST-10, HST-12 |
| `rate_limited` | Too many requests | HST-16 |
| `unsupported_browser` | WebCrypto lacks Ed25519 or X25519 | IMP-3 |

## 21. Test vectors

- **[VEC-1]** Vectors are generated by the Rust implementation (`cargo run -p xtask -- vectors --update`) and checked by
  both implementations. They are never edited by hand.
- **[VEC-2]** Each vector file is a JSON object with a `vectors` array. Each vector has a `name`, the `rules` it
  exercises, its inputs (secrets and random bytes included, so that outputs are deterministic, [IMP-1]) and either the
  expected output or the expected `error` code.
- **[VEC-3]** Files: `meta.json` (format version and the label registry, [DS-3]), `primitives.json` (canonical JSON,
  base64url, base32, recovery keys, strict Ed25519 including every rejected class of [CRY-3], X25519, HKDF, Argon2id),
  `log.json` (inceptions, ids, handles, extended tags, logs, the version order), `vault.json`, `profile.json`,
  `proof.json` (login and fetch messages, proofs), `file.json` (account files and cards).
- **[VEC-4]** Every rule that a verifier checks has at least one accept and one reject vector, and every
  security-relevant fix adds a regression vector.

---

## 22. Versioning and extension

- **[EXT-1]** Every structure has a `v` and every key a type tag. A change to anything that is hashed or signed is a
  **format change**: it increases the structure's `v`, adds labels with the new version (`rootcard/<purpose>/v2`) and
  vectors, and never changes the meaning of `v: 1`.
- **[EXT-2]** Verifiers MUST keep accepting `v: 1` forever. Ids, logs and signatures made with `v: 1` stay valid.
- **[EXT-3]** New algorithms (for example ML-DSA and ML-KEM) are new key type tags, adopted by a `rotate_recovery` or an
  `instance` event in a later format version. New lock types (for example passkeys with the WebAuthn PRF extension) are
  new lock `kind`s. New Argon2id defaults apply to new locks; clients SHOULD suggest re-locking below the default.
- **[EXT-4]** Unknown members, kinds, key types and reasons are rejected in format version 1 ([CJ-11], [LOG-12]). A
  verifier never skips what it does not understand.

---

## Appendix A: the version order is total

*(informative)* Let `κ(x) = (r, t, s, −h)` for a valid log `x`, where `r` is 1 if `x` is retired, `t` the `time` of its
last event (0 for the inception), `s` its last `seq` and `h` its version hash as a 256-bit unsigned integer. [VER-2]
says `a` is newer than `b` exactly when `κ(a) > κ(b)` lexicographically.

1. **Total and transitive.** `κ` maps logs to a lexicographic product of total orders, which is a total order. Two logs
   of one account with equal `κ` have equal version hashes and are therefore the same log (second-preimage resistance of
   SHA-256 over the hash chain). Hence the order is a strict total order on distinct logs.
2. **Extension is newer.** If `b` extends `a`, nothing follows a `retire` ([LOG-14]), so `a` is not retired and `r(b) ≥
   r(a)`. If `r(b) > r(a)`, `b` is newer. Otherwise times never decrease along a log ([LOG-12] step 4.5), so `t(b) ≥
   t(a)`, and `s(b) > s(a)`, hence `κ(b) > κ(a)`.
3. **Retiring is final.** Every retired log has `r = 1` and every other `r = 0`.
4. **Who can create a competing branch.** Every event after the inception needs the current recovery key ([PWR-1]), and
   every `instance` the receipt of its primary host. A host or a thief of a password or an account key cannot create a
   log that is newer than the owner's; they can only withhold newer logs (THREAT_MODEL.md AR4).

*Rationale for comparing the last events rather than the events at the fork point:* the owner's latest action wins, so a
new instance minted from an old account file on a host that could not see the newest version (§18.2, [KT-3]) supersedes
the branch it did not see, which is what the owner just asked for.

---

## Appendix B: changes from DESIGN.md

*(informative)* The specification fills in what the design left open and corrects it where it was ambiguous or unsafe.
Each change keeps the design's intent.

1. **Framing.** Every hash, signature and derivation input is `label ‖ 0x00 ‖ canonical JSON` ([DS-1]). The design
   concatenated fields directly for the login and proof messages (`realm ‖ host ‖ nonce ‖ …`), which is ambiguous; they
   are now canonical JSON objects.
2. **Canonical JSON is RFC 8785** restricted to safe integers, with `null` excluded and duplicate members, fractions and
   exponents rejected ([CJ-1]–[CJ-9]).
3. **The inception has no `time`, `account` or `prev`**, and its fields are in `body` like every other event, so it is
   deterministic ([ID-1]).
4. **Recovery key derivation is bound to realm and username** ([RK-4]), so identities created from one recovery key are
   not linkable by their recovery public key.
5. **Vault fetch needs a lock proof** ([FET-1]). The design served vaults to anyone at `GET /id/<account>/vault`, which
   would let anyone run an offline password search, contrary to its own accepted risk (DESIGN §10.1). Each password lock
   now has an `auth` key derived from the same Argon2id output, and only the lock hints are public.
6. **The lock set is signed by the recovery key** ([LCK-3]) with a generation counter `gen`. The design said locks were
   high power but had the vault signed only by the account key, which would have let a password thief add a password of
   their own. The vault's `revoked` list is dropped: revocation is a new instance.
7. **`rev` instead of `version`** for vault and profile revisions, so that "version" always means the log version (`{
   seq, hash }`).
8. **The version order** compares `(retired, time, seq, hash)` of the last events ([VER-2]). The design's wording
   ("latest `time`, then lower hash") was not transitive with the extension rule on equal times; `seq` fixes that, and
   `retired` makes retirement final as the design intended.
9. **Receipts** require the new instance's `time` to be within 600 s of the receipting host's clock ([HST-6]).
10. **Instance body field `account_key`** (the design reused `account`, which is also the account id).
11. **Sizes:** the vault limit is 96 KiB and the contents 64 KiB, since the design's 64 KiB vault could not hold 48 KiB
    of private data after base64url and the locks. `null` is not a value.
12. **Registration** has no separate challenge signature: the account key's proof of possession is its signature on the
    `instance` event ([LOG-7]), and replay to another host fails on `home.key`. Registering in an application client
    generates the recovery key there but never accepts one as input ([PWR-6]); the design's "paste a key created in the
    key tool" is replaced by registering in the key tool.
13. **Recovery cards after a rotation** carry the log up to the rotation ([CRD-2]), since a rotated key cannot re-derive
    the inception.
14. **Key reuse** across roles and instances is rejected ([LOG-12] step 4.8).
15. **The recovery key checksum** is framed with its own label (`rootcard/recovery/check/v1`).
