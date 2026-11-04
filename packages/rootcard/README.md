# rootcard (npm)

[rootcard](https://github.com/Hexagon/rootcard) in plain ES modules: a portable, self-certifying identity for online
logins. Zero dependencies, no build step, WebCrypto only; runs in browsers and Node 20 or later. It produces and checks
exactly the bytes of the Rust crate `rootcard`; both are tested against the shared vectors of the specification.

```js
import { verifyLog, verifyProof } from "rootcard";             // verification: hosts, relying parties, clients
import { register, unlockVault, changePassword } from "rootcard/vault"; // passwords, Argon2id, vault encryption

const state = await verifyLog(events, { realms: ["global"], now: Math.floor(Date.now() / 1000) });
```

- `rootcard` is the verification core: canonical JSON, keys, recovery keys, identities and handles, logs
  (`verifyLog`, `extendLog`, `compareLogs`), vault and profile checks, login and fetch messages, proofs, account files
  and recovery cards.
- `rootcard/vault` adds password locks (Argon2id implemented in this package, the only primitive not taken from
  WebCrypto), vault encryption and the high-level flows: registration, password change, new instances and rotation.
  A server bundle that does not import it never loads it.
- `keytool.html` is the standalone key tool page: open it from your own disk (`file://`). It talks only to the hosts you
  enter. It is generated from these modules by `npm run build`.

Functions that need randomness take `random(n)`; pass `systemRandom` (WebCrypto `getRandomValues`). Errors are
`RootcardError` with the stable `code` of SPEC §20.
