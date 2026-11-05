# rootcard-cli

The key tool for [rootcard](https://github.com/Hexagon/rootcard) identities, binary `rootcard`. It is the only place
besides `keytool.html` where a recovery key is entered (SPEC [PWR-6]).

> **New to rootcard?** Start with the [project README](https://github.com/Hexagon/rootcard#readme): what rootcard is,
> the two ways to use it (a safer username-and-password login for your own service, or an ID card across services),
> how it compares with other login methods, and the roadmap.

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

Host addresses are base URLs without the API version (`https://id.example.com` or `https://example.com/rootcard`, never
`…/v0`); the tool calls `<base URL>/v0/…` itself (HOST_PROTOCOL.md §1.3, SPEC [HST-22]).

## License

Licensed under either of MIT or Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`).
