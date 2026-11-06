# Proposal: signing in to other services with a rootcard identity

Status: **draft proposal, not normative.** Nothing here is part of [spec/SPEC.md](../../spec/SPEC.md) or
[HOST_PROTOCOL.md](../HOST_PROTOCOL.md) yet. Rule identifiers in this document (`[SIN-1]`) are provisional. Adopting
the proposal means moving the rules into the spec and the HTTP binding, the threats into
[THREAT_MODEL.md](../THREAT_MODEL.md) and the roles into [ARCHITECTURE.md](../ARCHITECTURE.md), all in one change
(see §9).

---

## 1. Goal

A user has **one rootcard identity** and wants **an account at many services** (relying parties, RPs), with the
identity as the login. Requirements:

1. An RP verifies the user **by itself**, using the public log. It does not trust the primary host's word and does not
   call a "verification API" (SPEC [HST-14], [PRF-4]).
2. The password is typed **only** into the primary host's client or the key tool, as today ([PWR-6], AR2). An RP never
   sees the password, the vault or the account key.
3. A sign-in proof made for one RP cannot be used at another, cannot be replayed and cannot be obtained by a phishing
   site that relays the flow (compare [LGN-4] for host logins).
4. The account at the RP survives the user moving to another primary host or resetting the password, because the RP
   keys it by the **account id**, which never changes.
5. No format change to existing structures. The proof stays `Proof v1` (SPEC §14).

Non-goals: single logout across RPs, sharing private data with RPs (only the public profile is shared), and
anonymity towards the primary host in the redirect flow (§7.6).

## 2. Roles

| Role | Holds | Trusted with |
|---|---|---|
| **User** | Password, recovery card | – |
| **Primary host** (home) | Log, vault, public profile; serves the sign-in page | Passwords typed into its own page (AR2, unchanged) |
| **Relying party** (RP) | Per account: the newest verified log, its own local account | Nothing of the identity's secrets |
| **Any host in the realm** | Public logs and profiles | Nothing. Used only to look up and fetch logs, which the RP verifies |

The RP does **not** have to be a rootcard host. It needs the verifying half of the core (`verify_log`,
`verify_proof`, `compare_logs`, the proposed `signin_challenge`), which builds without the `vault` feature
(ARCHITECTURE.md §4).

The user therefore does not choose between "use rootcard at one service only" and "register at a central verification
service". They choose a **primary host** (any host, their own, or one of the services) that keeps the vault and shows
the sign-in page. Every other service verifies the user itself.

## 3. Overview of the flow

```
 Browser                     RP (https://shop.example)              Primary host (https://id.example)
    |  "Sign in with rootcard", Astra#3F9C  |                                 |
    |-------------------------------------->|  lookup + fetch log, verify     |
    |                                       |-------------------------------->|
    |   302 to <signin page>?account&nonce&return   (flow cookie set)         |
    |<--------------------------------------|                                 |
    |  GET signin page (shows "shop.example wants to confirm you are Astra#3F9C")
    |------------------------------------------------------------------------>|
    |  user unlocks (password) in the home's page, confirms                   |
    |  page signs Proof v1: by=account, recipient="https://shop.example",     |
    |       challenge = signin_challenge(nonce, recipient)                    |
    |  auto-submitted form POST to the return URL (proof)                     |
    |-------------------------------------->|                                 |
    |                                       |  fetch newest log, verify_proof |
    |                                       |-------------------------------->|
    |   RP session for local account(account id)                              |
    |<--------------------------------------|                                 |
```

## 4. Proposed format addition: the sign-in challenge

A new label in the registry (SPEC §5, [DS-3]):

| Label | Used for | Section |
|---|---|---|
| `rootcard/signin/v1` | Challenge of a sign-in proof for a relying party | (new) |

- **[SIN-1]** `signin_challenge(nonce, recipient) = SHA-256(frame("rootcard/signin/v1", { "nonce": "<b64u 32 bytes>",
  "recipient": recipient }))`. The proof is an ordinary `Proof v1` with `by` `account`, `challenge` the result above
  and `recipient` the RP's origin ([SIN-3]).
- **[SIN-2]** A client that signs a sign-in proof MUST derive the challenge with `signin_challenge` and MUST NOT sign a
  challenge received from an RP as is.

*Rationale.* Without the label, an RP chooses the 32 challenge bytes that the user signs. A malicious RP can then send
`challenge = statement_challenge(S)` ([PRF-5]) for a statement `S` of its choice and receive, from a user who believes
they are signing in, a statement proof of `S`. The label makes sign-in proofs a separate purpose (THREAT_MODEL.md T8).
This adds a label and a function, with vectors in `spec/vectors/proof.json`; it changes no existing structure, so ids,
logs and proofs made so far stay valid.

## 5. Proposed rules

### 5.1 Recipient

- **[SIN-3]** The `recipient` of a sign-in proof is the **web origin** of the RP's return URL, serialized as
  `scheme://host[:port]` (lower-case host, no default port, no path), for example `https://shop.example`. Only
  `https` is allowed, except loopback origins during development. At most 256 bytes ([PRF-3]).
- **[SIN-4]** The signing client takes the recipient **only from the return URL it will deliver the proof to**, never
  from a separate parameter. The proof is delivered by a top-level navigation (or `postMessage` with `targetOrigin` set
  to the recipient), so the browser guarantees that only that origin receives it.

### 5.2 Starting the flow at the RP

- **[SIN-5]** The RP finds the account: from a remembered account id for a returning user, or from a typed handle by
  `GET /id/lookup` at hosts it is configured with. It checks that the account id starts with the typed tag
  ([HDL-1]), fetches and verifies the log ([LOG-12]) with its accepted realms ([RLM-3]), checks the username, and merges
  it with the log it already stores ([VER-4]). A lookup answer is never trusted on its own.
- **[SIN-6]** The RP takes the primary host's address from `home.url` of the current instance in the **verified log**,
  never from a lookup answer, and the sign-in page from that host's descriptor (§6.1).
- **[SIN-7]** The RP draws a fresh 32-byte nonce and stores the flow `{ nonce, account, recipient, expires }` server
  side, bound to the browser by a flow cookie (`__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=None`, random id).
  A flow expires at most **300 s** after it starts (longer than [CHL-2] because the user types a password and Argon2id
  runs) and is used once.

### 5.3 The sign-in page at the primary host

- **[SIN-8]** The page shows the RP's origin prominently, the handle and the start of the account id, and asks for
  explicit confirmation. It refuses a return URL that is not `https` (or loopback).
- **[SIN-9]** The page unlocks the vault as for a login ([LGN-1] steps 1–3), checks that the account is the one the RP
  asked for and that the instance is current at this host, signs the proof ([SIN-1], [SIN-3]) and delivers it with an
  auto-submitted form `POST` to the return URL. It sends nothing else of the vault.
- **[SIN-10]** The page MUST NOT be framed (`Content-Security-Policy: frame-ancestors 'none'`) and follows the rules for
  host-served clients (HOST_PROTOCOL.md §1: strict CSP, no third-party script, HSTS).
- **[SIN-11]** The page MAY keep the unlocked account key between sign-ins as a **non-extractable** WebCrypto key in
  the host origin's storage, if the user opts in on this device, for at most 30 days, and MUST still ask for
  confirmation of each sign-in. This reduces how often the user types the password (see T-S5).

### 5.4 Finishing the flow at the RP

- **[SIN-12]** On the callback the RP, in order: finds the flow by the flow cookie and consumes it, whether the rest
  succeeds or not → `challenge_unknown`, `challenge_expired`; checks the proof's `account` equals the flow's →
  `account_mismatch`; fetches the newest log from `home.url` (from its stored `seq`) and merges it ([VER-4], [VER-5]);
  then `verify_proof(proof, log, { challenge: signin_challenge(nonce, recipient), recipient })` with the recipient
  being **its own origin** ([PRF-4]).
- **[SIN-13]** The RP keys its local account by the **full account id** ([HDL-2]), never by the handle, and displays
  the handle with extended tags where needed ([HDL-6]).
- **[SIN-14]** The RP's session records the account id and the instance hash. It is valid only while that instance is
  current in the newest log the RP knows. The RP re-fetches the log at least every **10 minutes** while a session is in
  use and before any action it considers sensitive, and ends sessions of a replaced instance or a retired identity.
  The RP SHOULD limit a session to **24 h** and then run a new sign-in.
- **[SIN-15]** A sign-in proof gives the RP low power **at the RP only**: it shows that the user unlocked the current
  instance just now. It does not let the RP change anything about the identity, and the RP MUST NOT treat it as a
  recovery-key action.

## 6. HTTP binding (sketch for HOST_PROTOCOL.md)

Host paths are relative to the host's API root `<base URL>/v0` (HOST_PROTOCOL.md §1.3). The RP's sign-in API is
versioned the same way: `<signin>` below ends in its own version segment (`https://shop.example/rootcard/v0`), which
becomes `v1` when the binding is stable. Well-known URLs carry no version: they only point to versioned ones.

### 6.1 Descriptor

`GET /host` gains an optional member `"signin": "<https URL of the sign-in page>"`. A host without it does not offer
the flow; the RP then shows an error.

### 6.2 Redirect to the home

```
GET <signin>?v=1&account=<account id>&nonce=<b64u>&return=<URL-encoded return URL>
```

### 6.3 Callback at the RP

```
POST <return URL>            Content-Type: application/x-www-form-urlencoded
rootcard_proof=<canonical JSON of the proof>
```

The RP answers with its own session (cookie) and a redirect. Errors are shown to the user; codes are those of spec
§20.

### 6.4 Discovery with well-known URLs

- **The RP**, not the home, is what a non-browser client needs to discover: `GET
  https://<rp>/.well-known/rootcard-rp` → `{ "v": 1, "signin": { "v0": "<https URL of the RP's sign-in API, v0>" },
  "realms": [ … ] }` (RFC 8615). Listing the API versions lets a client pick the newest one both sides serve.
- **The home** MAY answer the host pointer `GET https://<domain>/.well-known/rootcard`, now a rule of the spec
  ([HST-23], HOST_PROTOCOL.md §2), so that a user can name a host by its domain; the descriptor is then at
  `<base>/v0/host`. It is a convenience only: the address an RP or client relies on is `home.url` in the verified log
  ([SIN-6]), which is never resolved through a pointer.
- **The challenge always comes from the RP.** Freshness is the verifier's own guarantee ([PRF-5]): a nonce issued by
  the home would make the RP trust the home's word that it is fresh and unused, which [HST-14] rules out. The home
  serves the sign-in page; it never issues challenges for RPs.

### 6.5 Sign-in API for non-browser clients

```
POST <signin>/start    { "account": "<account id>" }          → { "flow", "nonce", "expires" }
POST <signin>/finish   { "flow": "<flow id>", "proof": Proof } → { "account", "handle", "token", "expires" }
```

`flow` is a random 32-byte id that replaces the flow cookie of [SIN-7]; the same client calls both endpoints over TLS,
so there is no browser to bind to and no login CSRF. `token` is the RP's own credential (bearer token), with the
lifetime and refresh of [SIN-14]. The RP checks the proof exactly as in [SIN-12].

- **[SIN-16]** A non-browser client derives the recipient from the RP URL **it connects to itself** (the origin of
  `signin`, as configured or typed by the user), never from a value the RP or another program sends, as [LGN-4] does
  for host logins.

### 6.6 Three ways to sign in without a browser

1. **The key tool signs in directly** (`rootcard signin https://shop.example --handle Astra#3F9C`). It discovers the
   RP (§6.4), gathers the log ([KT-2]), fetches the vault from the home with the password ([FET-1]), unlocks it,
   calls `start`, signs the proof with the recipient from [SIN-16], calls `finish` and hands the token to the user
   (stdout or a credential file chosen by the user). Only the password is used: this is low power. The strongest
   variant, since the client knows the real origin, and nothing but the trusted key tool sees the password.
2. **An agent for other programs** (`rootcard agent`, like `ssh-agent`). *Later, not in the first version (owner's
   decision).* It keeps the account key unlocked in memory,
   non-extractable where possible, for a time the user chooses. An RP's own CLI asks it over a local socket to "sign
   in to `https://shop.example`"; the agent runs the whole flow of 1 itself, so the recipient is the origin the agent
   connects to, and the RP's CLI receives only the token. The agent asks for confirmation per sign-in or per RP, as
   the user configures.
3. **Device approval for a headless machine** (compare RFC 8628). The RP's CLI calls `start` with a `device: true`
   flag, gets a short user code and the RP's approval URL, and polls `finish`. The user opens the approval URL on any
   device with a browser, types the code, and completes the browser flow of §3 there; the RP attaches the proof to the
   waiting flow. The RP shows the device's name and network address on the approval page, and the code expires with
   the flow (300 s). Residual risk: **device-code phishing**, where an attacker starts a flow and persuades the victim
   to approve the attacker's code. Prefer 1 or 2 where the user can run the key tool.

The RP's own CLI MUST NOT ask for the rootcard password and unlock the vault itself: that is the rejected alternative of
§8 in another form.

*Note on the existing key tool:* `rootcard prove --challenge <hex>` signs a raw 32-byte challenge. It must not be used
for sign-in ([SIN-2]); `rootcard signin` would be the only sign-in command.

### 6.7 Libraries (sketch)

- Core, both languages: `signin_challenge(nonce, recipient)` / `signinChallenge(nonce, recipient)`, with vectors.
- `rootcard-host`: an optional `RelyingParty` helper: flow store (trait, like the challenge store), `start(handle |
  account) → redirect`, `finish(flow_id, proof) → { account, handle, instance }`, log cache with `from=` refresh.
- `packages/rootcard`: the signing side for host-served sign-in pages.

## 7. Security analysis

### 7.1 Threats addressed

| # | Threat | Mitigation |
|---|---|---|
| T-S1 | A proof made for one RP is used at another | `recipient` is the RP's origin, checked by the RP against its own origin ([PRF-3], [SIN-3], [SIN-12]) |
| T-S2 | Replay of a sign-in proof | Fresh RP nonce, single use, 300 s, bound to the browser's flow cookie ([SIN-7], [SIN-12]) |
| T-S3 | Real-time relay phishing: `evil.example` starts a flow at the RP and gets the victim to sign | If the return URL is the RP's, the proof goes to the RP in the victim's browser, which lacks the attacker's flow cookie: rejected. If the return URL is evil's, the recipient is evil's origin: useless at the RP ([SIN-4]) |
| T-S4 | A malicious RP gets the user to sign a statement or another proof | Dedicated label ([SIN-1], [SIN-2]) |
| T-S6 | Login CSRF (the victim ends up signed in to the attacker's account) | The proof must match the flow bound to the victim's own browser ([SIN-7]) |
| T-S7 | Clickjacking the confirmation | `frame-ancestors 'none'` ([SIN-10]) |
| T-S8 | A host lies in a lookup or serves a forged log | The RP verifies the log itself and takes `home.url` from it ([SIN-5], [SIN-6]) |
| T-S9 | An old instance is used after a password reset or a move | Proof is bound to the current instance ([PRF-1]); RP refreshes the log and ends stale sessions ([SIN-14]) |
| T-S10 | DoS with long logs | Spec limits ([LOG-1]); the RP caches logs and fetches with `from=` |
| T-S11 | A program on the user's machine asks the agent for a proof for another origin | The agent connects to the RP itself and derives the recipient from that connection ([SIN-16]); a program gets only a token for the RP it named. Malware that controls the user's session is out of scope (THREAT_MODEL.md §3) |
| T-S12 | Device-code phishing | Codes typed by the user, device details on the approval page, 300 s expiry; still a residual risk (§6.6) |

### 7.2 Residual risks (would become accepted risks)

- **T-S5: Password phishing becomes more attractive.** Redirect flows teach users to type their password after being
  sent somewhere, as with OAuth/OIDC. A fake sign-in page gets the password, which is low power, only in the current
  instance, and ended by a reset ([KT-8]). The recovery key stays safe because only the key tool asks for it.
  Mitigations: [SIN-11] (fewer password prompts), users recognizing their home's domain, and later passkeys as a lock
  type (PLAN.md "Later") or a browser extension that signs with the real origin.
- **Lookup spoofing for first-time sign-in.** A malicious lookup host, or a brute-forced tag collision (AR7), can map
  a typed handle to another identity whose `home.url` is a phishing page. The proof that comes back is then for the
  wrong account, so the RP never signs the attacker in as the victim, but the victim may type their password on the
  phishing page. Mitigations: RPs look up only at hosts they trust, show the extended handle and home domain before
  redirecting, and remember the account id after the first sign-in.
- **The primary host can sign in as the user anywhere.** It serves the signing page, so a malicious home can capture the
  password and the account key (AR2, unchanged in kind, but now it reaches every RP, as an OIDC provider would). Unlike
  OIDC, the user can move to another home with the recovery key, keeping every RP account, and the old home's power ends
  at each RP once that RP sees the new log.
- **Stale RPs (AR4 extended).** An RP that has not seen a new instance may accept a proof from the old one, for up to the
  refresh interval of [SIN-14], or longer if the old home withholds the new log. The new home pushes to the old one
  ([HST-15]); RPs SHOULD also fetch from a second host they trust.
- **Linkability.** Every RP sees the same account id, so RPs can link the user's accounts. Users who do not want this
  create separate identities from the same recovery key, which are unlinkable ([RK-4], G9). The primary host learns
  which RPs the user signs in to (AR9 extended).

### 7.3 What stays unchanged

- No secret crosses B1 or B2 (THREAT_MODEL.md §4): the RP receives only a proof and public logs.
- Power levels: sign-in is low power. Nothing in the flow touches the log, the locks or the instance (spec §16).
- The recovery key is never entered on any page in this flow ([PWR-6]).

## 8. Alternatives considered

| Alternative | Verdict |
|---|---|
| The RP's own page unlocks the vault (user types the password at the RP) | **Rejected.** Every RP would learn the password and the account key and could sign in as the user at every other RP. |
| A central "verification API" that RPs call | **Not needed.** RPs verify proofs themselves; a central service would only add a party to trust. |
| Making every service a host and replicating the vault | **Rejected.** Vaults stay at the primary host ([HST-13]); more copies mean more offline guessing (AR1). |
| Signing the RP's raw challenge | **Rejected** (T-S4). |
| Browser extension or native wallet that signs with the real origin | **Later.** Strongest against phishing and hides RPs from the home, but needs a distributed signer. Uses the same proof and the same RP side. |

## 9. Work if adopted

1. SPEC: §5 label, a new section with [SIN-*] rules, §19 limits, §21 vectors. THREAT_MODEL: threats and accepted
   risks. HOST_PROTOCOL: descriptor member, §6 endpoints, §7 flow. ARCHITECTURE: the relying-party workflow.
2. `xtask`: `LABEL_PURPOSES` and vectors for `signin_challenge` (accept and reject cases).
3. Both cores: `signin_challenge` / `signinChallenge`. `rootcard-host`: the `RelyingParty` helper and its tests,
   including the JSON API of §6.5. `rootcard-cli`: `signin` (the agent is left for later).
4. CHANGELOGs under `## Unreleased`.

## 10. Open questions for the owner

Decided: the agent (§6.6, 2) is not part of the first version.


1. Is the redirect flow acceptable for a first version, with the extension/wallet flow later?
2. Should `/host` advertise the sign-in page, or should it be fixed at `<home.url>/signin`?
3. Is 300 s for an RP flow and 10 minutes for session refresh the right balance?
4. Should RPs be able to request public profile keys (for example a display name) in the same flow, or read them from
   `GET /id/{account}/public` afterwards (recommended, since the profile is public and signed)?
