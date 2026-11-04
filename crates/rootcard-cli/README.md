# rootcard-cli

The key tool for [rootcard](https://github.com/Hexagon/rootcard) identities, binary `rootcard`. It is the only place
besides `keytool.html` where a recovery key is entered (SPEC [PWR-6]).

```sh
cargo install rootcard-cli
rootcard new --realm global --username Astra --host https://id.example.com
rootcard restore --card Astra-3F9C.card.json --account Astra-3F9C.rootcard.json --host https://other.example
rootcard reset-password --card Astra-3F9C.card.json --from https://other.example
rootcard add-password --card Astra-3F9C.card.json --from https://other.example --label Phone
rootcard rotate-recovery --card Astra-3F9C.card.json --from https://other.example
rootcard inspect Astra-3F9C.rootcard.json
rootcard help
```

Before it signs anything, the tool gathers the newest log from the card, the account file and every host given, and
stops on a fork (SPEC [KT-2], [KT-7]). It talks only to the hosts you name, over HTTPS.
