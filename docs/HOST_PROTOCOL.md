# rootcard: host protocol (HTTP binding)

This is the **recommended** HTTP binding of the host rules in [spec/SPEC.md](../spec/SPEC.md) §13 and §17. It is not
required: a host may use another transport as long as it keeps the rules of the specification. Clients, the key tool and
`rootcard-host` implement this binding, so hosts that follow it work with them unchanged. Rule identifiers (`[HST-6]`)
refer to the specification.

---

## 1. General

- **Base URL.** A host is reached at its base URL, the `home.url` of the instances it receipts: `https://` followed by a
  host name, an optional port and an optional path without a trailing slash (`https://id.example.com`,
  `https://example.com/rootcard`). Every path below is relative to it. Plain `http://` is allowed only for loopback
  addresses during development.
- **Encoding.** Request and response bodies are JSON (`Content-Type: application/json`, UTF-8). Clients SHOULD send
  canonical JSON; hosts parse strictly ([CJ-6]) and always verify over canonical bytes ([CJ-7]). Hosts send canonical
  JSON for every rootcard structure.
- **Body size.** A host rejects request bodies over 6 MiB with `413 too_large` before parsing, and applies the limits of
  spec §19 per structure.
- **Authentication.** Session endpoints take `Authorization: Bearer <token>`, where the token is `b64u` of at least 32
  random bytes ([HST-10]). Hosts MUST NOT use cookies for rootcard sessions, so that no endpoint acts on ambient
  credentials.
- **CORS.** Every endpoint except `/peer/*` answers with `Access-Control-Allow-Origin: *` and allows the `Authorization`
  and `Content-Type` request headers, so that `keytool.html` (served from `file://`, origin `null`) and application
  clients on other origins can reach the host. This is safe because no endpoint relies on cookies.
- **Caching.** Responses that contain a vault, a session token, lock hints or a challenge carry `Cache-Control:
  no-store`.
- **Host-served clients** SHOULD be served with a strict Content Security Policy (no inline script, no third-party
  script), `X-Content-Type-Options: nosniff` and HSTS, since they handle passwords (THREAT_MODEL.md T19).

### 1.1 Errors

Every error is a JSON object with the specification's error code (spec §20):

```
{ "error": "<code>", "message"?: "<English text for developers>", ... }
```

| Status | Codes | Extra members |
|---|---|---|
| 400 | `bad_json`, `bad_field`, `unsupported_version`, `bad_base64`, `bad_base32`, `bad_key`, `bad_signature`, `bad_realm`, `bad_username`, `username_policy`, `bad_handle`, `account_mismatch`, `bad_kind`, `bad_seq`, `bad_prev`, `time_backwards`, `future_time`, `bad_time`, `wrong_signer`, `key_reuse`, `bad_receipt`, `bad_reason`, `no_instance`, `wrong_instance`, `bad_locks`, `kdf_params`, `wrong_account_key`, `bad_data_key`, `wrong_host`, `too_many_events` | – |
| 401 | `unauthorized`, `challenge_unknown`, `challenge_expired` | – |
| 403 | `realm_not_accepted` | `realms`: the realms the host serves |
| 404 | `unknown_account` | – |
| 409 | `stale_version` | `version` and `events` (see §1.2) |
| 409 | `handle_taken` | – |
| 409 | `ambiguous_handle` | `candidates`: `[ { account, handle } ]` with extended tags |
| 409 | `stale_rev`, `stale_locks` | `rev` and `gen` the host has |
| 409 | `not_home` | `home`: `{ key, url }` of the primary host |
| 410 | `account_retired` | `version` |
| 413 | `too_large` | – |
| 429 | `rate_limited` | `Retry-After` header |

### 1.2 Versions in responses

Wherever a response carries `version`, it is the host's newest version for the account ([VER-4]). A `stale_version`
answer carries `events`: the host's events from the first `seq` the request did not share with the host (the fork point
or the end of the shorter log), so the client can merge them ([VER-4]) and retry.

---

## 2. Public endpoints

### `GET /host`

The host descriptor. Not signed; it is trusted as far as the TLS connection to the base URL.
```
{ "v": 1, "key": "ed25519:<host key>", "url": "<base URL>",
  "realms": [ { "realm": "global", "username_policy"?: { "min": 3, "max": 20, "first": "letter" } } ],
  "peers"?: [ "ed25519:<host key>", ... ] }
```
A client registering an identity uses `key` and `url` as the new instance's `home` ([CLT-1]).

### `GET /id/lookup?handle=<handle>`

Resolves a handle ([HDL-3]) or an extended handle. Any host that knows the identity answers.
```
200 { "account", "handle", "version", "home": { "key", "url" }?, "retired": false }
```
`home` is absent for a log with no current instance. Errors: `bad_handle`, `unknown_account`, `ambiguous_handle`.

### `GET /id/{account}/log?from=<seq>`

The host's newest log, from `seq` `from` (default 0).
```
200 { "version", "events": [ ... ] }
```

### `GET /id/{account}/public`

The current public profile ([DAT-3]). `404 unknown_account` if the host has none.

### `POST /id/{account}/events`

Carries newer events to a host ([VER-5], [HST-14]). Anyone may call it.
```
{ "events": [ ... ], "vault"?: Vault }
```
`events[0].seq` is any `s ≥ 1` for which `events[0].prev` is the hash of the host's event `s − 1`; the host combines its
events `0 … s − 1` with the submitted ones, verifies the result ([LOG-12] with `now`) and adopts it if it is newer
([VER-2]). A client that does not know the host's log sends the complete log. `vault` is accepted only by the primary
host, only together with a `rotate_recovery` ([KT-5]), and is verified against the resulting log state ([VLT-3],
[VLT-4]); the events and the vault are adopted together or not at all.
```
200 { "version" }                    the host's version after the request
409 stale_version                    the host's log is newer, or events[0].prev does not match
```

### `POST /id/register`

Registration ([HST-3]).
```
{ "log": [ inception, pending instance ], "vault": Vault, "public"?: PublicProfile }
201 { "account", "handle", "version", "receipt": "<b64u receipt signature>" }
```
The receipt lets the client complete its copy of the instance event without fetching the log.

### `POST /id/{account}/instance`

A new instance on this host ([HST-5], [KT-3]); the host becomes the primary host.
```
{ "events"?: [ ... ], "instance": pending instance, "vault": Vault, "public"?: PublicProfile }
201 { "version", "receipt" }
409 stale_version                    rebuild on top of the returned events
```
`events` are prior events the host may lack, with the same rules as `POST /id/{account}/events`. After `201` the host
pushes the instance to its peers and to the previous primary host ([HST-15]).

---

## 3. Fetch, login and vault replacement (primary host only)

Every endpoint in this section answers `409 not_home` on a host that is not the primary host ([HST-9]).

### `GET /id/{account}/locks`

The lock hints ([FET-2]).
```
200 { "instance": "<b64u>", "locks": [ { "id", "label", "kdf": { "alg", "m", "t", "p", "salt" } }, ... ] }
```
Only password locks are listed.

### `POST /id/{account}/challenge`

```
{ "purpose": "fetch" | "login" }
200 { "nonce", "host", "realm", "version", "expires" }
```
The challenge ([CHL-1]) is bound to the account and the purpose and is valid once, for 60 s ([CHL-2]).

### `POST /id/{account}/fetch`

The vault after a lock proof ([FET-1]).
```
{ "lock": "<lock id or recovery>", "nonce", "sig" }
200 { "vault": Vault }
```

### `PUT /id/{account}/vault`

A vault replacement without a session, authorized by a new lock set: the new `locks.gen` must be greater than the stored
one ([HST-12]). The key tool uses it to add a password ([KT-4]) and after a rotation ([KT-5]).
```
{ "vault": Vault }
200 { "rev" }
```
Errors: `unauthorized` if `locks.gen` does not increase, `stale_rev`, and the codes of [VLT-3].

### `POST /id/{account}/login`

The login ([LGN-1] step 6).
```
{ "nonce", "version", "sig" }
200 { "token": "<b64u>", "handle", "instance": "<b64u>", "idle_timeout": 86400 }
```

---

## 4. Session endpoints (primary host only)

All take `Authorization: Bearer <token>` and answer `401 unauthorized` without a valid session ([HST-10], [HST-11]).

| Endpoint | Body | Answer | Rules |
|---|---|---|---|
| `POST /session/logout` | – | `204` | HST-11 |
| `GET /session/vault` | – | `200 { "vault" }` | HST-10 |
| `PUT /session/vault` | `{ "vault" }` | `200 { "rev" }` | VLT-3, VLT-4, HST-12 |
| `PUT /session/public` | `{ "public" }` | `200 { "rev" }` | DAT-2, DAT-3 |
| `GET /session/export` | – | `200` the account file, `Content-Disposition: attachment; filename="<username>-<tag>.rootcard.json"` | FIL-2 |

A session belongs to one instance: after a new instance or retirement every request with an old token answers `401
unauthorized`.

---

## 5. Peer endpoints

Peers are hosts that serve the same realm and have added each other's host keys ([HST-15]). Peer requests are signed:

```
Rootcard-Peer-Key:  ed25519:<sender host key>
Rootcard-Peer-Time: <Unix seconds>
Rootcard-Peer-Sig:  b64u(Ed25519.sign(sender host key, frame("rootcard/peer/v1",
                      { "method": "GET" | "POST", "path": "<path and query as sent>", "time": t,
                        "to": "ed25519:<receiver host key>", "body": "<b64u SHA-256 of the request body bytes>" })))
```
The receiver accepts a peer request only if the key is one of its peers, `|time − now| ≤ 60`, and the signature verifies
strictly. Peer authentication only decides who may use the peer endpoints and their rate limits: everything a peer sends
is verified like data from anyone ([HST-14]).

### `GET /peer/changes?since=<cursor>`

```
200 { "cursor": "<opaque>", "changes": [ { "account", "version", "public_rev"? }, ... ] }
```
The identities whose log or public profile changed after `cursor` (an empty `since` lists everything). The caller
fetches what it lacks with `GET /id/{account}/log` and `GET /id/{account}/public`. Peers SHOULD poll every 30 s.

### `POST /peer/push`

```
{ "account", "events"?: [ ... ], "public"?: PublicProfile }
200 { "version" }
```
The same processing as `POST /id/{account}/events` and a profile update without a session: the profile is adopted if it
verifies ([DAT-2]) and is newer ([DAT-3]). Vaults are never pushed ([HST-13]).

---

## 6. Recommended rate limits

| Operation | Per network address | Per identity |
|---|---|---|
| `POST /id/register` | 3 per hour | – |
| `GET /id/lookup`, `/log`, `/public` | 120 per minute | – |
| `GET /id/{account}/locks` | 30 per hour | 30 per hour |
| `POST /id/{account}/challenge` | 10 per minute | 30 per hour |
| `POST /id/{account}/fetch` | 30 per hour | 10 per hour |
| `POST /id/{account}/login` | 10 per minute | 30 per hour |
| `POST /id/{account}/events`, `/instance` | 30 per hour | 10 instances per day |
| Session endpoints | 120 per minute | 120 per minute |

Failed fetches are online password guesses (THREAT_MODEL.md T11); a host SHOULD count them separately and MAY add a
delay that grows with consecutive failures. Limits per identity let an attacker delay the owner (AR8); a host SHOULD
exempt clients that present a valid session.

---

## 7. Flows *(informative)*

**Registration** (application client, [CLT-1]): `GET /host` → build the inception and the pending instance with `home =
{ key, url }` → `POST /id/register` → log in.

**Login** ([LGN-1]):
```
GET  /id/lookup?handle=Astra%233F9C          → account, version, home   (any host; then go to home.url)
GET  /id/{account}/log?from=<n>              → merge; POST /id/{account}/events if the client's log is newer
GET  /id/{account}/locks                     → lock hints               (skipped with a cached vault)
POST /id/{account}/challenge {fetch}         → sign the fetch message with the lock's auth key
POST /id/{account}/fetch                     → vault; unlock it
POST /id/{account}/challenge {login}         → sign the login message with the account key
POST /id/{account}/login                     → token
```

**New instance on another host** (key tool, [KT-3]):
```
GET  /id/{account}/log at every reachable host, and read account files → the newest version
POST /id/{account}/challenge {fetch} and /fetch with the recovery key at the old primary host (restore only)
GET  /host at the new host
POST /id/{account}/instance at the new host   → receipt; the new host pushes to the old one, which answers not_home
```
