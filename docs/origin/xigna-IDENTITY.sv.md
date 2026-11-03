# Xigna: konton, identitet och säkerhet

Det här dokumentet beskriver **hur ett konto fungerar**: vad det är, hur man loggar in och bevisar vem man är, vilken
version av kontot som gäller, hur lösenord läggs till och spärras, hur fri information sparas i identiteten, hur kontot
laddas ner och hur återställningsnyckeln alltid kan skapa en ny, fullständig instans. Det är källan till sanningen för
användarhanteringen. [ARCHITECTURE.md §8](ARCHITECTURE.md#8-autentisering) beskriver inloggningen som finns i dag (bara
användarnamn) och sammanfattar den här designen i §8.1.

> **Status:** planerat, före den öppna alfan (se [ROADMAP.md](ROADMAP.md), "Riktig inloggning"). Spridningen av den
> offentliga loggen mellan servrar kommer i v0.7. Sektionsnumren är stabila.

---

## 1. Mål och krav

| # | Krav | Hur (avsnitt) |
|---|---|---|
| K1 | Spelaren väljer **användarnamn**, **världsfrö** och **lösenord** och får en **återställningsnyckel** | §6.1 |
| K2 | Ett konto är **låst till ett världsfrö**. Det gäller bara i den galaxen | §4.1, §5.1 |
| K3 | Kontots riktiga id är **unikt** | §4.1 |
| K4 | Det visade id:t är alltid **`Användarnamn#XXXX`**, där `XXXX` är de fyra första tecknen i det unika id:t | §4.2 |
| K5 | Återställningsnyckeln kan **lägga till ett lösenord** och **spärra ett gammalt** | §6.3, §6.4 |
| K6 | Profilen är **krypterad** och används vid inloggning, och vid inloggning **räcker lösenordet** | §5.2, §6.2 |
| K7 | Ett konto kan **bara verifieras när användaren är online och har låst upp sitt konto** | §2.2, §6.2 |
| K8 | Ett inloggat konto kan **laddas ner** | §6.6 |
| K9 | Den kompletta identiteten **sprids inte automatiskt**. Den ligger på den **primära servern** och hos spelaren | §5.4, §7 |
| K10 | Ett konto ska kunna **leva för evigt** | §9 |
| K11 | **Återställningsnyckeln kan alltid skapa en ny, fräsch version av en fullständig instans** | §6.8, §9.1 |
| K12 | Det finns alltid **en senaste version**. Har en klient eller server sett en nyare verifierad version är **den gamla ogiltig för inloggning** | §5.5 |
| K13 | En spelare kan **bevisa vem den är** för andra, också på andra servrar | §6.9 |
| K14 | Det är **omöjligt att förfalska en identitet med samma id**. Kontot bevisar att det har den **privata nyckeln** till den **publika nyckel** som id:t bygger på | §4.4, §6.9 |
| K15 | Det går att **spara och uppdatera fri information** i identiteten, både offentlig och privat | §5.6 |
| K17 | **Lösenordet ger liten makt.** All större makt kräver återställningsnyckeln | §5.7 |
| K16 | Identiteten kan **flyttas ut till ett eget bibliotek** och bli en global, säker identitet (som ett id-kort) som andra program och tjänster kan använda | §8.5 |

---

## 2. Grundidé, hotmodell och vad som är säkert och görbart

### 2.1 Grundidé
Ett konto är ett **eget nyckelpar** och inte en rad i en servers databas. Den **kompletta identiteten** har tre delar:

1. **Identitetsloggen** (§5.1). Den är offentlig och signerad, en kedja av händelser som bara innehåller *publika* nycklar:
   vem kontot är, vilken instans som gäller nu (kontonyckel och primär server) och vilken återställningsnyckel som styr
   kontot. Loggens senaste händelse är kontots **version** (§5.5).
2. **Den krypterade profilen** (valvet, §5.2). Den hör till en viss instans och innehåller kontots *privata* nyckel och
   spelarens privata information. Den låses upp med ett lösenord eller med återställningsnyckeln, och bara hos spelaren.
3. **Den offentliga profilen** (§5.6). Fri, offentlig information som kontot har signerat.

Den kompletta identiteten finns bara på den **primära servern** och i spelarens nedladdade kontofiler (§5.4). Bara den
primära servern tar emot inloggningar, och där räcker lösenordet. Den offentliga loggen och den offentliga profilen får
spridas, eftersom de saknar hemligheter. Loggen är det som gör att alla kan se vilken version som är den senaste.

En server kan kontrollera att någon *är* kontot, men den kan aldrig *bli* kontot. Den som har återställningsnyckeln kan när som
helst skapa en ny instans av kontot, och det gör alla tidigare instanser, valv, lösenord och sessioner ogiltiga.

### 2.2 Verifiering bara online och upplåst (K7)
- Servrarna sparar **ingen lösenordsverifierare**: ingen hash, inget salt och inget publikt värde som räknats fram ur
  lösenordet. I det offentliga finns inget att gissa lösenord mot.
- Inloggning sker alltid med en **ny utmaning** som gäller en gång och i 60 s. Klienten svarar med en signatur av
  kontonyckeln, som bara finns i den upplåsta profilen i klientens minne. Signaturen binds till servern, världsfröet och
  **kontots version** (§5.5).
- Det finns inga sparade signaturer och inga långlivade bevis som kan spelas upp igen. En session gäller en server, en
  anslutning och en instans. Den försvinner vid utloggning och när en nyare version tar bort instansen.

### 2.3 Hotmodell

| Hot | Skydd | Kvarstår |
|---|---|---|
| Någon skapar en egen identitet med samma id | Id:t är en hash av en signerad födelse med återställningsnyckelns publika nyckel. Att förfalska det kräver återställningsnyckelns privata del eller ett brott mot SHA-256 eller Ed25519 (§4.4) | – |
| Någon utger sig för en spelare (samma namn) | Hela id:t skiljer sig alltid. Bevis med signatur (§6.9) | Taggen på fyra tecken kan krocka (§4.3) |
| Databasen på en server läcker | Bara publika loggar och profiler, och valv bara för konton som har servern som primär. Inga lösenordshashar | Den primära serverns valv kan gissas offline (§10.1) |
| Någon gissar lösenord via inloggningen | Lösenordet skickas aldrig. Valvet lämnas ut med takt | – |
| Någon gissar lösenord offline mot ett stulet valv | Valvet finns bara på den primära servern och hos spelaren. Argon2id och krav på lösenordet (§3.3) | Ett svagt lösenord kan knäckas av den som har valvet (§10.1) |
| Lösenordet stjäls | Lösenordet ger bara liten makt (§5.7): inloggning, bara på den primära servern och bara i den nuvarande instansen. Återställningsnyckeln spärrar det med verkan direkt (§6.4) | Tjuven kan spela tills ägaren spärrar |
| En kontofil och ett lösenord stjäls | Räcker inte för att flytta kontot. En gammal fil är ogiltig så fort det finns en nyare version (§5.5) | – |
| En gammal version används (gammal fil, gammal server, återspelning, gammal offentlig profil) | Total ordning av versioner. Inloggningen binds till versionen. Den som har sett en nyare version vägrar den gamla och sprider den nya (§5.5) | En part som *aldrig* har sett den nya versionen (§10.4) |
| En server spelar upp en inloggning igen | Utmaningen binds till serverns nyckel, världsfröet, versionen och en `nonce` | – |
| En server ändrar den offentliga profilen | Den är signerad av kontonyckeln och har en version (§5.6) | En server kan låta bli att visa den |
| En elak server serverar en elak webbklient | Lösenordet skrivs bara in på den primära servern, som spelaren har valt. Återställningsnyckeln skrivs aldrig in i spelklienten (§6.5) | Den primära servern ser lösenord som skrivs in i dess klient (§10.2) |
| Återställningsnyckeln stjäls | Den förvaras offline och används bara i nyckelverktyget | Tjuven äger kontot (§10.3) |
| Kvantdatorer | Algoritmerna har typtaggar och kan bytas (§9.2) | – |

### 2.4 Säkert och görbart: besluten

| Del | Säkert? | Görbart? | Beslut |
|---|---|---|---|
| Ed25519, X25519, SHA-256, HKDF, AES-GCM | Ja, standard och granskat | Ja, finns i WebCrypto i aktuella webbläsare och i RustCrypto/dalek | **Används** |
| Argon2id för lösenord | Ja, rekommenderat (RFC 9106) | Ja i Rust. I webbläsaren finns det inte i WebCrypto, men en ren JS-implementation går att testa mot RFC-vektorerna. Den är långsammare än WASM, så parametrarna väljs för cirka 1–3 s på en vanlig telefon | **Används**, egen JS-implementation, parametrar i varje lås |
| Ett självcertifierande id (hash av en signerad födelse) | Ja, inget register behövs för att lita på det | Ja | **Används** (§4.1, §4.4) |
| En hashkedja med versioner och skydd mot återgång | Ja | Ja, enkla datastrukturer | **Används** (§5.1, §5.5) |
| Valvet bara på den primära servern | Ja, inga valv att gissa mot på andra servrar | Ja | **Används** (§5.4) |
| Kontot återskapas ur återställningsnyckeln | Ja, den är kontots rot | Ja, om födelsen räknas fram deterministiskt ur nyckeln (§4.1) | **Används** (§9.1) |
| Fri information: signerad offentlig profil och privat information i valvet | Ja, så länge storleken begränsas och allt visas som data | Ja | **Används** (§5.6) |
| OPAQUE (lösenord utan offline-gissning) | Ja | Kräver en hemlighet per server och tung kod i JS. Krockar med att kontot ska kunna flyttas | **Inte nu.** Kan bli en extra spärr på den primära servern senare (§10.1) |
| Passkeys (WebAuthn med PRF) som lås | Ja, mycket starkt mot nätfiske | Ja i nyare webbläsare, men en passkey är knuten till serverns domän | **Senare**, som en ny låstyp på den primära servern (§9.2) |
| Vittnen (KERI) och en förhandsåtagen nästa återställningsnyckel | Ja, skyddar mot en stulen återställningsnyckel | Mer komplext, och spelaren skulle behöva förvara två hemligheter | **Senare**, i `v: 2` utan att id:t ändras (§10.3) |
| Global unikhet för handtag (konsensus, blockkedja) | – | Orimligt för ett spel | **Nej.** Unikt per server, och synliga förlängda taggar vid krock (§4.3) |
| Skydd mot en elak server som serverar webbklienten | – | Inte möjligt i en webbklient som kommer från servern | **Accepterat.** Lösenordet ger bara spel, och kontot kan flyttas (§10.2) |
| Återställning utan återställningsnyckeln | Skulle kräva en bakdörr | – | **Nej, med avsikt** (§9.1) |

---

## 3. Kryptografi

### 3.1 Algoritmer

| Syfte | Algoritm | Rust | JS |
|---|---|---|---|
| Signaturer | Ed25519 (RFC 8032), deterministiska, strikt verifiering | `ed25519-dalek` (`verify_strict`) | WebCrypto `Ed25519` |
| Nyckelöverenskommelse (valvets lås) | X25519 (RFC 7748) | `x25519-dalek` | WebCrypto `X25519` |
| Hash | SHA-256 | `sha2` | WebCrypto `SHA-256` |
| Härledning av nycklar | HKDF-SHA256 (RFC 5869) | `hkdf` | WebCrypto `HKDF` |
| Lösenord till nyckel | Argon2id (RFC 9106) | `argon2` | `web/js/identity/argon2.js` (egen, med `blake2b.js`) |
| Kryptering | AES-256-GCM, slumpad nonce på 96 bitar, ny nyckel för varje instans | `aes-gcm` | WebCrypto `AES-GCM` |
| Slump | OS:ets CSPRNG | `getrandom` (finns redan) | `crypto.getRandomValues` |

- **Ingen egen kryptografi i servern.** De nya Rust-craterna kommer från RustCrypto och dalek, som är granskade och
  välanvända. Det är motiveringen för de nya beroendena (AGENTS.md regel 13).
- **I webbklienten** finns allt utom Argon2id i WebCrypto, så inga npm-beroenden behövs (regel 9). Argon2id testas mot RFC
  9106:s vektorer och mot Rust (§11). Sidokanaler spelar mindre roll där, eftersom det bara är spelarens egen dator som räknar
  på spelarens eget lösenord.
- **Strikt verifiering** överallt: publika nycklar av liten ordning och icke-kanoniska signaturer nekas, så att en signatur
  inte kan göras om till en annan giltig signatur och en nyckel inte kan väljas så att den godtar flera meddelanden.
- Webbläsare utan Ed25519 och X25519 i WebCrypto får ett tydligt fel (`unsupported_browser`). Det finns ingen svagare reserv.

### 3.2 Domänseparation
Allt som signeras eller härleds har en egen etikett, så att en signatur för ett syfte aldrig duger för ett annat. Etiketterna
börjar med bibliotekets namn (`xid`) och inte med spelets, så att de inte behöver bytas när biblioteket flyttas ut (§8.5):

```
xid/id/v1              id ur födelsen
xid/event/v1           händelser i identitetsloggen
xid/vault/v1           valvets huvud
xid/public/v1          den offentliga profilen
xid/login/v1           svar på en inloggningsutmaning
xid/proof/v1           bevis för vem man är (§6.9)
xid/receipt/v1         serverns kvitto på en ny instans
xid/recovery/sign/v1, xid/recovery/box/v1   nycklar ur återställningsnyckeln
xid/password/box/v1    nyckel ur lösenordet
xid/wrap/v1            inslagning av valvnyckeln
```

### 3.3 Lösenord
- Argon2id med startparametrarna `m = 64 MiB, t = 3, p = 1` och 32 byte utdata. Saltet är 16 slumpade byte per lås.
  Parametrarna sparas i varje lås, så att de kan höjas för nya lås utan att gamla slutar fungera. Klienten mäter tiden vid
  registreringen och varnar om den blir över 5 s. Golvet (`m ≥ 46 MiB, t ≥ 2`, OWASP:s miniminivå) kontrolleras av klienten och
  nyckelverktyget.
- Lösenordet normaliseras med Unicode NFC före härledningen.
- Kraven gäller i klienten, eftersom servern aldrig ser lösenordet: minst 12 tecken, inte användarnamnet, inte i en lista över
  vanliga lösenord, och en mätare som föreslår en lösenfras.

### 3.4 Kanonisk kodning
Allt som hashas eller signeras kodas som **kanonisk JSON**: nycklarna sorterade, inga blanksteg, bara strängar, heltal (högst
2⁵³), booleska värden, listor och objekt, och **inga flyttal**. Bytesträngar skrivs som base64url utan utfyllnad. Rust och JS
kodar till exakt samma byte, och det kontrolleras med gemensamma testvektorer (§11).

### 3.5 Återställningsnyckeln
- 32 slumpade byte, visade som `XGR-` + 52 tecken Crockford base32 + 4 tecken kontrollsumma (SHA-256), i grupper om 4.
- Signeringsnyckeln är `HKDF(nyckel, "xid/recovery/sign/v1") → Ed25519` och lås-nyckeln `HKDF(nyckel, "xid/recovery/box/v1")
  → X25519`. Ingen Argon2id, eftersom nyckeln redan har full entropi.

---

## 4. Kontots id och det visade id:t

### 4.1 Det riktiga id:t (K2, K3)
Födelsen räknas fram **deterministiskt** ur återställningsnyckeln, användarnamnet och världsfröet:

```
födelse   = { v: 1, kind: "incept", seq: 0, realm: "xigna:world:<världsfrö>", username: "<namn>",
              recovery: "ed25519:<publik>" }
            signerad av återställningsnyckeln (Ed25519-signaturer är deterministiska)
konto-id  = SHA-256("xid/id/v1" ‖ kanonisk(födelse utan signaturer))
```
- Id:t är 256 bitar och skrivs med **Crockford base32** (52 tecken, versaler, inga `I L O U`).
- **Världsfröet ingår** som kontots `realm` (det område identiteten gäller i), så kontot är låst till galaxen (K2). En
  Xigna-server godtar bara konton med `realm = "xigna:world:<sitt frö>"`. För biblioteket är `realm` bara en sträng (§8.5).
- Eftersom födelsen bara beror på återställningsnyckeln, namnet och fröet kan **samma återställningsnyckel alltid räkna fram
  samma konto-id och samma födelse igen** (§9.1). Det är grunden för K11.
- Id:t **ändras aldrig**, inte ens när instanser, lösenord och återställningsnyckeln byts.
- Internt mappar varje server konto-id:t till sitt `PlayerId(u64)` (`AccountStore`). `PlayerId` lämnar aldrig servern.

### 4.2 Det visade id:t (K4)
```
handtag = användarnamn + "#" + de fyra första tecknen i konto-id:t      t.ex.  Astra#3F9C
```
- Användarnamnet följer dagens regler (3–20 tecken, `A–Z a–z 0–9 _ -`, börjar med en bokstav). Bara ASCII, så det finns inga
  Unicode-tecken som ser likadana ut.
- Användarnamnet ligger i födelsen och **kan inte bytas**. Handtaget är lika stabilt som id:t.
- Spelet visar alltid handtaget (radio, skanningar, namngivare, kartan). Klienter och servrar jämför alltid **hela** id:t.

### 4.3 Krockar i taggen
Fyra tecken i base32 ger 20 bitar. Den som vill kan prova runt en miljon återställningsnycklar och få samma *tagg* som någon
annan, men aldrig samma *id* (§4.4). **Taggen är en hjälp för människor och inget säkerhetsbevis.** Därför gäller:

1. **En server tillåter aldrig två konton med samma handtag** (skiftlägesokänsligt). Den som kommer först får det, och en ny
   registrering med ett krockande handtag nekas (`handle_taken`). Klienten skapar då en ny återställningsnyckel.
2. **Krockar som uppstår genom spridning** syns alltid: båda kontona visas med en **förlängd tagg** med så många tecken som behövs
   för att skilja dem åt (`Astra#3F9C-K2`).
3. **Klienten kommer ihåg hela id:t** för spelare man har haft kontakt med (i valvet) och varnar om samma handtag dyker upp med ett
   annat id. Den som vill vara säker begär ett bevis (§6.9).

*Förkastat:* ett minneskrävande arbetsbevis i födelsen. Det skulle göra registreringen långsam, ge servrarna en dyr kontroll för
varje okänt konto (en väg för DoS) och ändå inte stoppa den som verkligen vill.

### 4.4 Varför ingen kan förfalska ett konto med samma id (K14)
Id:t är **självcertifierande**: det är en hash av födelsen, och födelsen innehåller återställningsnyckelns publika del och är
signerad med dess privata del. Den som vill visa upp en identitet med ett visst id måste därför

1. visa en födelse vars hash är id:t, vilket bara den äkta födelsen har (SHA-256 är motståndskraftig mot andra förbilder), och
2. visa att den har den **privata nyckeln** till den publika nyckel som födelsen namnger. Det sker genom signaturer: födelsen är
   signerad av återställningsnyckeln, varje senare händelse av den återställningsnyckel som gällde då, och varje inloggning och
   varje bevis av den gällande instansens kontonyckel, som i sin tur är signerad in av återställningsnyckeln.

Kedjan *id → födelse → återställningsnyckel → instans → kontonyckel → signatur över en ny utmaning* kontrolleras helt med
publika uppgifter, och varje länk kräver en privat nyckel som bara ägaren har. En server, en ansluten server eller någon annan
spelare kan därför inte skapa en identitet med samma id, inte ändra en befintlig och inte spela upp ett gammalt bevis. Att
förfalska kräver att man bryter Ed25519 eller SHA-256, eller stjäl en privat nyckel. Det enda som går att få lika är taggen (§4.3).

Varje gång en ny publik nyckel kommer in i loggen (`incept`, `instance`, `rotate_recovery`) måste den också **signera själv**
(bevis på att nyckeln finns). Det går alltså inte att skriva in någon annans publika nyckel som sin egen.

---

## 5. Kontots delar

### 5.1 Identitetsloggen (offentlig, signerad, en hashkedja)

```
Händelse {
  v: 1, account: "<konto-id>" (saknas i födelsen), seq: n, prev: "<hash av händelse n-1>" (saknas i födelsen),
  kind: ..., time: <unix-s enligt ägarens klocka>, body: { ... },
  sigs: [{ key: "ed25519:<publik>", sig: "<base64url>" }]
}
händelsens hash = SHA-256("xid/event/v1" ‖ kanonisk(händelsen utan sigs))
```

| `kind` | Innehåll | Signeras av | Verkan |
|---|---|---|---|
| `incept` | `realm`, `username`, `recovery` (§4.1) | återställningsnyckeln | Kontot finns. Ingen instans än |
| `instance` | `account` (ny publik kontonyckel), `home` (den primära serverns publika nyckel och adress), `reason` (`register`, `revoke`, `restore`, `fresh`) | återställningsnyckeln, den nya kontonyckeln **och** den primära servern (kvitto, `xid/receipt/v1`) | **En ny fullständig instans.** Alla tidigare instanser, valv, lösenord som inte följde med och sessioner blir ogiltiga |
| `rotate_recovery` | ny `recovery` | den gamla **och** den nya återställningsnyckeln | Ny återställningsnyckel. Instansen gäller fortfarande |
| `retire` | – | återställningsnyckeln | Kontot stängs för alltid |

Regler som varje server och klient kontrollerar (`xg-identity::verify_log`):
- Födelsen ska ha `seq = 0`, ett giltigt användarnamn och en `realm` som servern godtar (för Xigna: `"xigna:world:<WorldInfo.seed>"`).
  Konto-id:t ska stämma.
- Varje följande händelse ska ha `seq = n`, `prev` lika med hashen av händelse `n−1`, och signeras av **den återställningsnyckel
  som gällde efter händelse `n−1`**. **Bara återställningsnyckeln kan ändra loggen.** Kontonyckeln och lösenorden kan det inte.
- `time` får inte ligga mer än 10 minuter fram i tiden enligt den server som tar emot händelsen och får inte gå bakåt i kedjan.
- **Gällande instans** är den senaste `instance`. Dess `account` är den enda kontonyckel som gäller, och dess `home` är den primära
  servern.
- Efter `retire` godtas inga fler händelser, och ingen kan logga in.

### 5.2 Valvet (den krypterade profilen)
Valvet hör alltid till **en** instans.

```
Valv {
  v: 1, account: "<konto-id>", instance: "<hash av instans-händelsen>", version: n,
  locks: [
    { id: "<8 byte>", kind: "password", label: "laptop",
      kdf: { alg: "argon2id", m: 65536, t: 3, p: 1, salt: "<16 byte>" },
      box: "x25519:<publik>",                          härledd ur lösenordet
      wrap: { epk: "<efemär X25519>", nonce, ct } },  valvnyckeln inslagen till box
    { id: "recovery", kind: "recovery", box: "x25519:<publik>", wrap: {...} }
  ],
  revoked: ["<lås-id>", ...],
  nonce, ct,                                           AES-256-GCM(valvnyckel, innehåll), huvudet som AAD
  sig: { key: "ed25519:<instansens kontonyckel>", sig }
}
```

- **Innehåll** (krypterat): kontonyckelns privata del, högsta sedda version för kontot och för kända spelare, kända spelares hela
  id (§4.3) och **den privata fria informationen** (§5.6). Aldrig återställningsnyckeln.
- **Lås:** ur lösenordet räknas `Argon2id → HKDF("xid/password/box/v1") → X25519`. Valvnyckeln (32 slumpade byte) slås in till
  låsets publika nyckel med en efemär nyckel: `ECDH → HKDF("xid/wrap/v1") → AES-GCM`. Återställningslåset fungerar likadant.
- Eftersom varje lås har en **publik** nyckel kan återställningsnyckeln slå in en ny valvnyckel till lösenorden som finns kvar
  **utan att känna till dem** (§6.4).
- Valvet är giltigt bara om `instance` är den gällande instansen (§5.1) och det är signerat av instansens kontonyckel. Ett valv
  från en äldre instans går inte att logga in med, även om lösenordet stämmer.
- `version` räknas upp vid varje ändring inom instansen (nytt lås, ny information). Den primära servern sparar bara ett valv med
  högre `version`.

### 5.3 Nycklarna och vad de får göra

| Nyckel | Var den finns | Får |
|---|---|---|
| **Återställningsnyckel** | Bara hos spelaren, på papper eller i en fil, offline | Signera alla händelser i loggen, skapa en ny instans (alltid, §6.8), låsa upp valvet, lägga till och spärra lösenord, byta sig själv, stänga kontot |
| **Kontonyckel** (en per instans) | Krypterad i valvet, upplåst bara i klientens minne | Svara på inloggningsutmaningar, signera valvet och den offentliga profilen inom instansen, ge bevis för vem man är (§6.9) |
| **Lösenord** (ett per lås) | I spelarens huvud | Låsa upp valvet i den gällande instansen, och därmed liten makt (§5.7) |
| **Servernyckel** (Ed25519, en per server) | `data/server_key` | Binda utmaningar, kvittera nya instanser, signera anrop mellan servrar (§7) |

**Ett stulet lösenord kan aldrig låsa ute ägaren**, och **en stulen kontonyckel slutar gälla vid nästa instans.**

### 5.4 Var den kompletta identiteten finns

| Plats | Logg | Offentlig profil | Valv | Inloggning med lösenord |
|---|---|---|---|---|
| **Primära servern** (`home` i den gällande instansen) | Ja | Ja | Ja, det enda valvet på en server | Ja |
| **Spelarens kontofil** (§6.6) | Ja | Ja | Ja (krypterat) | – (säkerhetskopia, används vid återställning) |
| **Spelarens webbläsare** | Ja (högsta sedda version, §5.5) | Ja | Kan sparas krypterat | – |
| **Andra servrar i samma galax** | Den offentliga loggen (§7) | Ja (§7) | Aldrig | Nej, svarar `not_home` |

- Den kompletta identiteten **sprids aldrig automatiskt**. Den flyttas bara med återställningsnyckeln (§6.8).
- Loggen och den offentliga profilen är små och utan hemligheter. Att de sprids gör att handtaget är reserverat, att nya versioner
  når alla och att gamla versioner därmed blir ogiltiga överallt.

### 5.5 Versioner: vad som är senast (K12)
Kontots **version** är loggens senaste händelse, `(seq, hash)`. Alla giltiga versioner av ett konto har en **total ordning**:

1. **Förlängning:** om B bygger vidare på A (A är en början på B) är B nyare.
2. **Gren:** två giltiga händelser med samma `seq` och samma `prev` kan bara komma från återställningsnyckeln, alltså från ägaren
   (till exempel en ny instans utan kontakt med servrarna, §6.8). Då gäller grenen med **senast `time`** räknat på dess senaste
   händelse, och vid lika tid den med lägst hash. Regeln är deterministisk, så alla som ser båda grenarna kommer fram till samma
   svar utan att kontot fryses. Den förlorande grenen och allt som byggde på den blir ogiltigt. Ägaren varnas, och nyckelverktyget
   erbjuder att skapa en ny instans ovanpå den gällande.

Inom en instans har valvet och den offentliga profilen var sin `version` som bara går framåt.

**Det som har sett en nyare version vägrar den gamla:**
- **Servrar** byter bara till en nyare version enligt ordningen ovan, aldrig tillbaka. När en ny `instance` kommer in återkallar de
  alla sessioner från tidigare instanser, och en primär server som inte längre är `home` tar bort sitt valv och svarar `not_home`.
- **Klienter** sparar högsta verifierade version per konto (`localStorage`, och i valvet). En klient loggar aldrig in med en äldre
  version och vägrar ett valv eller en offentlig profil från en instans som inte är den gällande.
- **Inloggningen binds till versionen** (§6.2). Servern godtar en signatur bara om versionen i den är exakt serverns gällande
  version. Har klienten sett en nyare version skickar den med de händelser som saknas, och servern kontrollerar och byter till dem
  **innan** inloggningen prövas. Har servern en nyare version får klienten den och måste först uppdatera sig.
- **Alla bär nya versioner vidare.** Loggen är offentlig, så varje klient och server som har sett en nyare version skickar den till
  de servrar den pratar med (`POST /api/id/<konto>/events`). En version behöver bara nå en part för att den parten ska sluta godta
  den gamla.

### 5.6 Fri information i identiteten (K15)
Spelaren kan spara och uppdatera egen information i identiteten, på två sätt:

| | **Offentlig profil** | **Privat information** |
|---|---|---|
| Var | Ett eget signerat dokument bredvid loggen | I valvets krypterade innehåll (§5.2) |
| Vem ser den | Alla som har loggen (sprids som loggen, §7) | Bara den som låser upp valvet |
| Exempel | Beskrivning, skeppsnamn, emblem (som data), föredraget språk, kontaktvägar, en publik nyckel för en annan tjänst | Anteckningar, kända spelare, inställningar, egna nycklar och hemligheter för andra tjänster |
| Signeras av | Den gällande instansens kontonyckel (`xid/public/v1`) | Den gällande instansens kontonyckel (valvets `sig`) |
| Uppdateras av | En inloggad, upplåst klient | En inloggad, upplåst klient (och nyckelverktyget) |
| Storlek | Högst 16 KiB | Högst 48 KiB (valvet totalt 64 KiB) |

```
OffentligProfil { v: 1, account, instance: "<hash av instans-händelsen>", version: n,
                  data: { "<nyckel>": <värde>, ... }, sig: { key: "ed25519:<kontonyckel>", sig } }
```

- **Fritt innehåll, fasta regler:** `data` är ett objekt med nycklar på högst 64 tecken (`a–z 0–9 . _ -`) och värden i kanonisk
  JSON (§3.4), utan flyttal. Nycklarna har ett namnrum per program: `xigna.` är spelets, `user.` är spelarens egna, och andra
  program som använder identiteten (§8.5) får egna prefix (`app.<namn>.`). Ett program får bara skriva i sitt eget namnrum
  och i `user.`, men kan läsa allt.
- **Uppdatering:** klienten skickar hela dokumentet med `version + 1`, signerat. `PUT /api/id/<konto>/public` på den primära
  servern, som kontrollerar signaturen, instansen och versionen och sedan sprider det. En uppdatering av den privata informationen är
  en ny `version` av valvet (`PUT /api/id/<konto>/vault`).
- **Versioner:** den offentliga profilen är giltig bara för den gällande instansen och med den högsta `version` man har sett. Vid en
  ny instans signerar nyckelverktyget om den (`restore`) eller tömmer den (`fresh`).
- **Säkerhet:** servrar och klienter visar informationen bara som **text eller data**, aldrig som HTML eller kod, och
  begränsar storleken. Den offentliga profilen är offentlig för alltid i praktiken (kopior kan finnas kvar), vilket står i klienten
  innan något sparas. Den privata informationen syns aldrig för någon server.
- Vill man att ett påstående ska gälla för all framtid och oberoende av instans kan det signeras som ett bevis (§6.9) och sparas var
  som helst.

### 5.7 Liten och stor makt (K17)
Det finns bara två maktnivåer, och gränsen mellan dem är fast:

| | **Liten makt**: lösenordet (den upplåsta kontonyckeln) | **Stor makt**: återställningsnyckeln |
|---|---|---|
| Spel | Logga in på den primära servern och spela | – |
| Information | Läsa och ändra den privata informationen och den offentliga profilen inom den gällande instansen | Tömma eller ersätta allt vid en ny instans |
| Kontot | Ladda ner kontofilen, ge bevis inom instansen (§6.9) | Allt i identitetsloggen |
| Lösenord | – (inte ens byta sitt eget) | Lägga till, spärra och byta lösenord |
| Instanser | – | Skapa en ny instans (`restore`, `fresh`), byta kontonyckel |
| Primär server | – | Välja och byta primär server |
| Roten | – | Byta återställningsnyckeln, stänga kontot (`retire`), ge bevis oberoende av instans |

- **Regeln:** allt som ändrar *vem som kan komma åt kontot*, *var det finns* eller *om det finns* är stor makt. Det kontrolleras av
  formatet och inte bara av servern: bara återställningsnyckeln kan signera händelser i loggen (§5.1), och valvets lås signeras in av
  den (§6.3). Det finns ingen väg för kontonyckeln att ge sig själv mer makt.
- **Följden:** ett stulet lösenord ger tjuven bara liten makt, och bara tills ägaren gör en ny instans. Allt tjuven har ändrat (den
  offentliga profilen och den privata informationen) försvinner med en `fresh` instans eller kan granskas vid `restore`.
- **Spelklienten har bara liten makt.** Funktioner med stor makt finns bara i nyckelverktyget (§6.5), och servrarna har inga
  vägar för stor makt som bara kräver en session. Nya funktioner ska placeras i tabellen ovan, och i tveksamma fall är de stor makt.

---

## 6. Flöden

### 6.1 Registrering (K1, K2)
Allt sker i klienten. Servern ser bara det som är publikt och det krypterade valvet.

1. Spelaren väljer **användarnamn**.
2. Spelaren väljer **världsfrö**. Servern listar sitt frö (och, med federationen, de världar som anslutna servrar kör). Kontot låses
   till fröet för alltid.
3. Spelaren väljer **lösenord** (§3.3).
4. Klienten skapar **återställningsnyckeln** och visar den **en gång**, som text och som fil att ladda ner eller skriva ut (ett
   *återställningskort*, §6.7). Spelaren skriver in två slumpade grupper för att visa att den är sparad. Den som vill kan i stället
   klistra in en nyckel som skapades i nyckelverktyget (§6.5), vilket är säkrast.
5. Klienten räknar fram födelsen (§4.1), hämtar en utmaning från servern och skapar den första instansen:
   `instance { account, home: den här servern, reason: "register" }`, ett valv med lösenordslås och återställningslås, och en tom
   offentlig profil.
6. `POST /api/id/register { log: [födelse, instans], vault, public, challenge_sig }`. Servern kontrollerar loggen (och att varje ny
   publik nyckel har signerat själv, §4.4), valvet, gränser och att handtaget är ledigt, kvitterar instansen med sin servernyckel och
   svarar med `{ account, handle, version }`.
7. Klienten loggar in direkt (§6.2).

Takt: högst 3 registreringar per IP och timme.

### 6.2 Inloggning (K6, K7, K12)
Inloggning sker **bara på den primära servern**, och där räcker handtaget och lösenordet.
```
1  klient → GET  /api/id/lookup?handle=Astra%233F9C       → { account, version, home }
2  klienten jämför versionen med sin egen (§5.5). Är den egna nyare: POST /api/id/<konto>/events först
3  klient → GET  /api/id/<konto>/vault                     → valvet (hoppas över om klienten har den gällande instansens valv)
4  klienten låser upp valvet med lösenordet                → kontonyckeln i minnet
5  klient → POST /api/auth/challenge { account }           → { nonce, server, realm, version, expires }
6  klienten signerar
     "xid/login/v1" ‖ realm ‖ server ‖ nonce ‖ account ‖ version
7  klient → POST /api/auth/login { method: "key", account, nonce, version, sig }  → { token, player_id, handle }
```
- I steg 4 kontrollerar klienten själv att valvet hör till den gällande instansen och att kontonyckeln i det är instansens.
- En server som inte är `home` svarar `not_home` med adressen till den primära. Klienten erbjuder en ny instans här (§6.8).
- `nonce` är 32 slumpade byte, gäller i 60 s och bara en gång. Är serverns version inte längre `version` när signaturen kommer
  nekas inloggningen (`stale_version`), och klienten börjar om från steg 1.
- Kontonyckeln importeras i WebCrypto som **icke exporterbar**, och de råa byten skrivs över. Den finns bara i fliken och
  försvinner när den stängs eller vid utloggning.
- Sessionstoken (`SessionStore`, som i dag) gäller bara den servern och den instansen, upphör efter 24 timmar utan aktivitet och
  återkallas vid utloggning och vid en ny instans. **Den tysta inloggningen med ett sparat namn försvinner.**
- Takt: valvet lämnas ut högst 10 gånger per konto och timme och 30 gånger per IP och timme. Utmaningar högst 10 per IP och minut.

### 6.3 Lägga till ett lösenord (K5)
I **nyckelverktyget** (§6.5) med återställningsnyckeln:
1. Ladda kontot från den primära servern (eller en kontofil) och kontrollera att det är den senaste versionen (§5.5).
2. Skriv in återställningsnyckeln. Verktyget kontrollerar att den gäller och låser upp valvet med återställningslåset.
3. Skriv in det nya lösenordet med en etikett. Verktyget lägger till ett lås, räknar upp `version` och signerar valvet med
   instansens kontonyckel (som finns i valvet).
4. `PUT /api/id/<konto>/vault` till den primära servern. Loggen ändras inte, och instansen är densamma.

Ett lösenord kan **inte** bytas med bara det gamla lösenordet (§5.7). Att byta lösenord är att lägga till ett nytt och spärra det
gamla, med återställningsnyckeln.

### 6.4 Spärra ett gammalt lösenord (K5)
Den som har ett gammalt lösenord kan ha tagit kontonyckeln och valvnyckeln. Därför blir en spärr **en ny instans**:
1. Ladda kontot och lås upp valvet med återställningsnyckeln (som i §6.3).
2. Välj låset eller låsen som ska spärras. Verktyget skapar en ny kontonyckel och en ny valvnyckel, krypterar om innehållet, slår in
   den nya valvnyckeln till de lås som är kvar och till återställningslåset, och signerar om den offentliga profilen. Det skapar
   sedan `instance { account: ny, home: samma, reason: "revoke" }`.
3. `POST /api/id/<konto>/instance` med händelsen, det nya valvet och den nya offentliga profilen. Den primära servern kvitterar,
   sparar, **återkallar alla sessioner** och sprider händelsen (§7).
4. Det gamla lösenordet fungerar inte längre: dess lås finns inte i det nya valvet, och gamla valv och kontofiler hör till en instans
   som inte gäller. Eftersom bara den primära servern tar emot inloggningar gäller spärren direkt.

### 6.5 Nyckelverktyget
Återställningsnyckeln ska **aldrig skrivas in i spelklienten**.
- `xg-tools id` (CLI): `new`, `card`, `add-password`, `revoke-password`, `restore`, `fresh`, `rotate-recovery`, `retire`,
  `inspect`, `verify`, `prove`. Det läser och skriver kontofiler och återställningskort och skickar resultatet till en server.
- `web/account.html`: samma sak som en fristående sida som bara använder `web/js/identity/`. Den kan sparas och öppnas lokalt
  (`file://`) och gör inga nätverksanrop utom när användaren själv väljer en server.
- Spelklienten länkar till verktyget och varnar: "Skriv bara in återställningsnyckeln i nyckelverktyget."

### 6.6 Ladda ner kontot (K8)
En inloggad spelare kan alltid ladda ner sitt konto, med `GET /api/account/export` (`Authorization: Bearer <token>`) eller
direkt ur klientens minne. Filen heter `Astra-3F9C.xid-account.json`:
```
{ format: "xid-account", v: 1, realm, account, handle, version,
  log: [hela identitetsloggen], public: <den offentliga profilen>, vault: <den gällande instansens valv>,
  server_data?: { server, exported_at, player: <spelarens data på servern, bara att läsa> } }
```
- Filen har **inga hemligheter i klartext**. Den är kontots säkerhetskopia, men den kan gissas offline lika bra som valvet (§10.1).
- En kontofil gäller bara så länge dess version är den senaste. Efter en ny instans är den ett historiskt dokument. Loggen i den
  duger fortfarande som bevis vid en ny instans, men valvet går inte att logga in med.
- Klienten påminner om att ladda ner en ny fil efter varje ändring.
- `server_data` är spelarens egna uppgifter. Spelets tillstånd är serverns och följer inte med kontot.

### 6.7 Återställningskortet, ny återställningsnyckel och stängning
- **Återställningskortet** (text, fil och QR-kod) innehåller återställningsnyckeln, användarnamnet, världsfröet och, efter ett byte
  av återställningsnyckel, **kedjan av `rotate_recovery`** (några hundra byte). Det är allt som behövs för att alltid kunna skapa en
  ny instans (§9.1).
- `rotate_recovery`: en ny återställningsnyckel, signerad av den gamla och den nya. Valvets återställningslås byts samtidigt, och ett
  nytt kort skrivs ut. Det gamla kortet slutar fungera.
- `retire`: kontot stängs för alltid. Servrarna behåller födelsen och händelsen så att id:t aldrig kan användas igen, tar bort valvet
  och den offentliga profilen och slutar visa användarnamnet.

### 6.8 En ny, fräsch fullständig instans (K11)
**Återställningsnyckeln kan alltid skapa en ny instans**, på vilken server som helst med samma världsfrö (också den nuvarande):

1. I nyckelverktyget: skriv in återställningskortet (nyckeln, användarnamnet och världsfröet, plus `rotate_recovery`-kedjan om
   nyckeln har bytts). Verktyget räknar fram födelsen och konto-id:t (§4.1).
2. Verktyget letar efter den senaste versionen: hos den valda servern, hos dess anslutna servrar och i en kontofil om spelaren har en.
   Det kontrollerar allt det hittar och väljer den senaste enligt §5.5.
3. Spelaren väljer innehåll:
   - **Fortsätt** (`restore`): finns ett valv från den gällande instansen låses det upp med återställningslåset. Innehållet, den
     offentliga profilen och lösenorden följer med.
   - **Fräsch** (`fresh`): ett nytt, tomt valv med återställningslåset och ett nytt lösenord som väljs nu, och en tom offentlig
     profil. Inga gamla lösenord följer med. Används när något kan ha läckt, eller när inget valv finns kvar.
4. Verktyget hämtar en utmaning från den nya primära servern och skapar `instance { account: ny, home: den servern, reason }`
   **ovanpå den senaste versionen det hittade** (eller ovanpå födelsen om det inte hittade någon).
5. `POST /api/id/<konto>/instance { log, event, vault, public, challenge_sig }`. Servern kontrollerar hela loggen, att fröet är dess
   eget och att händelsen är signerad av den återställningsnyckel som gäller. Har servern en nyare version än den verktyget byggde på
   svarar den `stale_version` med de händelser som saknas, och verktyget bygger om ovanpå dem (nyckeln finns kvar i minnet). Sedan
   kvitterar servern instansen, sparar valvet och blir primär server.
6. Instansen sprids (§7). Varje part som ser den slutar godta alla tidigare instanser. Den gamla primära servern återkallar
   sessionerna, tar bort sitt valv och svarar `not_home`.
7. Spelaren loggar in med lösenordet och laddar ner en ny kontofil.

Byggde verktyget ovanpå en äldre version för att det inte nådde den senaste (till exempel för att den gamla primära servern var nere)
uppstår en gren. Den avgörs enligt §5.5: den senare instansen vinner, vilket är det ägaren nyss gjorde.

### 6.9 Bevisa vem man är (K13, K14)
Ett bevis visar att den som svarar har den **privata nyckeln** till den publika nyckel som identiteten pekar ut just nu:

```
den som kontrollerar → utmaning: 32 slumpade byte
den som bevisar      → sig = Ed25519(kontonyckel, "xid/proof/v1" ‖ konto-id ‖ version ‖ utmaning ‖ mottagare)
den som kontrollerar → verify_log(loggen) → gällande instans → dess publika kontonyckel → verify_strict(sig)
```
- Mottagaren kontrollerar mot loggen och den senaste version den känner till (§5.5). Ett bevis från en äldre instans godtas inte.
  Eftersom utmaningen är ny och mottagaren ingår kan beviset inte spelas upp igen eller skickas vidare.
- **På samma server** intygar servern handtaget (det står i snapshots, radio och skanningar), och det gäller bara konton som har
  loggat in där.
- **Mellan servrar och spelare** räcker `GET /api/id/<konto>/log` för att kontrollera, och JS-modulen har `verifyProof`.
- **Ett påstående utan utmaning** (till exempel "det här emblemet är mitt") kan signeras som ett bevis med `utmaning` = hashen av
  påståendet. Det gäller så länge instansen gäller.
- **Med återställningsnyckeln** (`xg-tools id prove --recovery`) kan ägaren ge ett bevis som gäller oberoende av instans, till
  exempel för att visa att två konton på olika världsfrön har samma ägare. Det används sällan, eftersom nyckeln ska vara offline.
- I spelet blir det en knapp "Bevisa" i skanningsrapporten och radion (senare milstolpe), som skickar utmaningen via servern.

---

## 7. Spridning mellan servrar (K9, v0.7)

**Den kompletta identiteten sprids aldrig automatiskt** (§5.4). Det som sprids är bara den **offentliga loggen** och den
**offentliga profilen**.

### 7.1 Anslutna servrar
- Varje server har en **servernyckel** och ett servernamn. **Anslutna servrar** är servrar med **samma världsfrö** som har lagt till
  varandras publika nycklar (`--peer <url>#<publik nyckel>`).
- Servrar litar **aldrig** på varandras påståenden. De kontrollerar alltid loggen och profilen själva (§4.4, §5.5).
- Inga valv och inga lösenord passerar mellan servrar. En elak ansluten server kan inte gissa lösenord, ta över konton eller ändra
  en profil. Det enda den kan göra är att låta bli att sprida, och klienterna bär ändå nya versioner vidare (§5.5).

### 7.2 Vad som sprids
| Del | Till vem | Varför |
|---|---|---|
| Identitetsloggen | Alla anslutna servrar, och den kan läsas av alla (`GET /api/id/<konto>/log`) | Handtaget är reserverat, nya versioner gör gamla ogiltiga överallt, nya instanser och bevis fungerar |
| Offentlig profil | Alla anslutna servrar, och den kan läsas av alla | Den är offentlig med avsikt (§5.6) |
| Valvet | **Aldrig**. Bara från den primära servern till ägaren (med takt) och i kontofiler | Det kan gissas offline |
| Sessioner, `PlayerId`, spelets tillstånd | Inte alls | Det är lokalt på varje server |

### 7.3 Hur det sprids
- **Push:** en ny händelse eller profil skickas till de anslutna servrarna (`POST /api/fed/push`, signerat med servernyckeln). En ny
  `instance` skickas alltid också till den förra primära servern.
- **Pull:** var 30:e sekund hämtar varje server vilka konton som har ändrats (`GET /api/fed/heads?since=<markör>`) och sedan det
  som saknas.
- **Klienter** bär också nya versioner (§5.5).
- **Inget går bakåt** (§5.5). Grenar avgörs med samma regel överallt.
- **Handtag:** varje server för ett register över handtag till id. Krockar ger förlängda taggar (§4.3).
- Gränser: en händelse högst 4 KiB, en offentlig profil högst 16 KiB, ett valv högst 64 KiB, högst 16 lås, högst 1 000 händelser per
  konto.

---

## 8. Koppling till koden

### 8.1 Moduler: `xg-identity` och `web/js/identity/`
Identiteten är en egen modul i båda språken, och de speglar varandra (som flygmodellen, AGENTS.md regel 2):

| Rust (`crates/xg-identity`) | JS (`web/js/identity/`) | Innehåll |
|---|---|---|
| `canon.rs` | `canon.js` | kanonisk JSON (§3.4) |
| `base32.rs` | `base32.js` | Crockford base32, återställningsnyckeln och kortet (§3.5, §6.7) |
| `id.rs` | `id.js` | födelsen ur återställningsnyckeln, konto-id, handtag, förlängda taggar |
| `log.rs` | `log.js` | händelser, `verify_log` (med bevis på att nya nycklar finns), gällande instans, **ordningen av versioner** (`newer`, §5.5) |
| `vault.rs` | `vault.js` | valvet: skapa, låsa upp, lås, privat information, ny instans med eller utan innehåll |
| `public.rs` | `public.js` | den offentliga profilen: regler för nycklar och värden, signatur, version (§5.6) |
| `proof.rs` | `proof.js` | meddelandena för inloggning, kvitton och bevis (§6.2, §6.9) |
| – (crate `argon2`) | `argon2.js`, `blake2b.js` | Argon2id |
| `file.rs` | `file.js` | kontofilen och återställningskortet |

- `xg-identity` är **ren**: ingen I/O, ingen tid och ingen slump utom det som skickas in. Den beror inte på någon annan crate i
  projektet, så att servern, `xg-tools` och en framtida Bevy-klient kan använda den.
- JS-modulen gör samma kontroller som Rust, så att klienten och nyckelverktyget aldrig litar blint på en server.
- Varje ny fil läggs till i `crates/xg-server/src/assets.rs` (regel 9).

### 8.2 Servern (`crates/xg-server/src/auth/`)
Strukturen från ARCHITECTURE.md §8 behålls (regel 7). Sessionskoden och spel-loopen ändras inte:
- `LoginRequest::Key { account, nonce, version, sig }` (en ny variant i `xg-protocol`) och `KeyAuthenticator`.
- `IdentityStore` (ny trait): loggar och offentliga profiler för alla kända konton, valv bara för konton där servern är primär,
  handtagsregistret och federationens markörer. Den första implementationen är en atomisk JSON-fil `data/identities.json` via
  `xg-persist`. Den är **skild från världens sparfil**, eftersom ett konto ska överleva att världen genereras om (`GEN_VERSION`).
- `ChallengeStore`: utmaningar som gäller en gång (i minnet, 60 s).
- `SessionStore`: varje session minns sin instans och återkallas när instansen inte längre gäller.
- `AccountStore` mappar konto-id → `PlayerId` och sparas med världen. `Identity` får `account` och `handle`.
- `UsernameOnly` finns kvar bakom `--dev-auth` för tester, webbläsartester och speltest.
- Servernyckeln skapas vid första starten (`data/server_key`, rättigheter 0600).

### 8.3 HTTP
| Väg | Beskrivning |
|---|---|
| `POST /api/id/register` | Födelse + första instansen (§6.1) |
| `GET /api/id/lookup?handle=` | Handtag → konto-id, version och primär server (förlängda taggar vid krock) |
| `GET /api/id/<konto>/log` | Identitetsloggen (offentlig) |
| `POST /api/id/<konto>/events` | Nyare händelser från vem som helst. Kontrolleras och godtas bara om de är nyare (§5.5) |
| `GET /api/id/<konto>/public`, `PUT /api/id/<konto>/public` | Den offentliga profilen. Läses av alla, uppdateras på den primära servern (§5.6) |
| `GET /api/id/<konto>/vault`, `PUT /api/id/<konto>/vault` | Valvet, bara på den primära servern (§6.2, §6.3, §5.6) |
| `POST /api/id/<konto>/instance/challenge`, `POST /api/id/<konto>/instance` | Ny instans (§6.4, §6.8) |
| `POST /api/auth/challenge`, `POST /api/auth/login` | Inloggning, `method: "key"` (§6.2) |
| `GET /api/account/export` | Kontofilen för den som är inloggad (§6.6) |
| `POST /api/fed/push`, `GET /api/fed/heads` | Mellan servrar, signerat, bara loggar och offentliga profiler (§7) |

`GET /api/info` får `server_key`, `realm` och `auth_methods: ["key"]`. Nya felkoder: `handle_taken`, `not_home`,
`stale_version`, `account_retired`, `challenge_expired`, `too_large`, `unsupported_browser` (texter i alla språkkataloger,
regel 14). `Welcome` får `handle`, och `PROTOCOL_VERSION` höjs.

### 8.4 Webbklienten
- `auth.js` ersätts av ett flöde med fyra vyer: logga in (handtag + lösenord, på den primära servern), registrera (§6.1), visa
  återställningskortet, och "Mitt konto" (ladda ner kontot, redigera den offentliga profilen och den privata informationen, länk
  till nyckelverktyget, lösenordens etiketter). Svarar servern `not_home` visar klienten den primära serverns adress och en länk
  till nyckelverktyget.
- Klienten sparar loggen och högsta version per konto i `localStorage`, och valvet krypterat om spelaren vill. Kontonyckeln sparas
  aldrig.

### 8.5 Ett eget bibliotek: en global, säker identitet (K16)
Identiteten ska kunna lyftas ut ur Xigna och bli ett **eget bibliotek** som andra program och tjänster använder som en global,
säker identitet, ungefär som ett id-kort. Därför byggs den redan från början så att ingenting i den hör till spelet:

- **Inga beroenden på spelet.** `xg-identity` beror inte på någon annan crate i projektet, och `web/js/identity/` importerar inget
  utanför sin katalog. Biblioteket kan flyttas till ett eget repo (arbetsnamn `xid`, crate `xid` och ES-modulen `xid.js`) genom att
  katalogerna kopieras, och Xigna beror sedan på det som ett vanligt beroende. Formatet ändras inte.
- **Allt spelspecifikt är parametrar.** `realm` är en fri sträng som programmet väljer och godtar. Xigna använder
  `"xigna:world:<frö>"` och godtar bara sitt eget frö (K2). En global identitet använder `realm: "global"`, och ett program kan
  välja att godta den. Reglerna för användarnamn är en `UsernamePolicy` som programmet skickar in (Xignas regler är standard).
  Namnrummen i den offentliga profilen hör till respektive program (§5.6).
- **Etiketterna hör till biblioteket** (`xid/...`, §3.2), så signaturer och id:n är desamma före och efter flytten.
- **Specifikationen är det som gäller.** Formatet (kanonisk JSON, händelser, valv, bevis och versionsordning) beskrivs fristående,
  med testvektorerna som facit, så att andra språk kan implementera det och kontrolleras mot samma vektorer.
- **Servern är bara en tillämpning.** Ordet "server" i det här dokumentet är för biblioteket en *värd*: någon som har en värdnyckel,
  kvitterar instanser och kan vara `home`. Det kan vara en spelserver, en webbtjänst eller en egen identitetsvärd. Inloggningen
  (§6.2) är ett allmänt protokoll för utmaning och signatur som vilken tjänst som helst kan använda, och bevisen (§6.9) fungerar
  utan någon värd alls.
- **En global identitet och flera program:** ett konto med `realm: "global"` kan användas av flera program, och varje program har sin
  egen `PlayerId` eller motsvarande. Xigna kan senare godta globala identiteter som ett val för operatören, men gör det inte i dag (K2).
- **API:t** (samma i Rust och JS): `Identity::create`, `Identity::from_recovery`, `verify_log`, `newer`, `current_instance`,
  `Vault::unlock`, `Vault::add_lock`, `Vault::revoke`, `Vault::new_instance`, `PublicProfile::set`, `login_message`,
  `prove`, `verify_proof`, `AccountFile::export`/`import`. Allt är rena funktioner, och I/O, tid och slump skickas in.

---

## 9. Ett konto som lever för evigt (K10, K11)

### 9.1 Varför kontot inte dör
- **Kontot har en rot som spelaren äger: återställningskortet.** Ur det räknas födelsen och konto-id:t fram (§4.1), och med det kan
  en ny instans alltid skapas på en server med samma världsfrö (§6.8), även om alla servrar, kontofiler och lösenord är borta. Det
  enda som går förlorat då är valvets innehåll och den offentliga profilen.
- **Id:t hör till roten, inte till en instans.** Instanser, kontonycklar, lösenord och primära servrar byts, och id:t och handtaget är
  desamma.
- **Inget går ut.** Konton har inget slutdatum. Bara `retire` stänger dem.
- **Spelarens ansvar är tydligt:** den som behåller återställningskortet kan alltid ta tillbaka kontot. Den som tappar kortet och alla
  lösenord har förlorat kontot. Det finns ingen bakdörr, och det står i registreringen.

### 9.2 Byte av algoritmer och format
- Alla nycklar har en typtagg (`ed25519:`, `x25519:`) och alla strukturer ett `v`. Ett nytt algoritmpar (till exempel ML-DSA och
  ML-KEM mot kvantdatorer) blir nya taggar och en `rotate_recovery` eller `instance` som byter till dem. Historien är fortfarande
  giltig.
- Nya låstyper (passkey med WebAuthn PRF, §2.4) läggs till som nya `kind` i valvets lås.
- Nya Argon2-parametrar gäller nya lås. Klienten föreslår att låsa om när de ligger under golvet.
- Servrar ska alltid kunna läsa `v: 1`.

---

## 10. Kvarstående risker (medvetna val)

1. **Gissning offline mot valvet.** Den som har valvet (den primära serverns operatör, den som stjäl dess databas eller en kontofil
   med den gällande instansen) kan gissa lösenord i sin egen takt. Skydd: valvet sprids aldrig, Argon2id och krav på lösenordet.
   Senare kan den primära servern lägga till en egen hemlighet i låsen (OPAQUE eller en "peppar") utan att flyttbarheten går
   förlorad, eftersom en flytt ändå görs med återställningsnyckeln.
2. **Den primära servern ser lösenord som skrivs in i dess klient.** Webbklienten kommer från servern. Spelaren väljer själv sin
   primära server. Skydd: lösenordet ger bara spel, återställningsnyckeln används bara i nyckelverktyget, och kontot kan flyttas
   (§6.8). Senare: en signerad klient (Bevy, eller en webbklient med fast ursprung).
3. **En stulen återställningsnyckel ger tjuven kontrollen.** Grenregeln (§5.5) gör att den senaste instansen vinner, så ägaren och
   tjuven kan skapa instanser om och om igen, och ingen av dem vinner över tid. Starkare skydd (vittnen och en förhandsåtagen nästa
   nyckel enligt KERI) kan läggas till i `v: 2` utan att id:t ändras.
4. **En part som aldrig har sett den nya versionen.** En server som ingen pratar med, och som varken nås av spridningen eller av
   klienter, kan tro att en gammal instans gäller. Den kan släppa in ett gammalt lösenord bara om den var den förra primära servern,
   och kontonyckeln gäller ingen annanstans.
5. **Ägarens klocka avgör grenar.** En ny instans med en klocka som går mycket fel kan förlora mot en äldre gren. Servrar vägrar tider
   mer än 10 minuter fram i tiden, och verktyget visar alltid vilken instans som gäller efteråt.
6. **Den offentliga profilen kan inte tas tillbaka.** När den har spridits kan kopior finnas kvar, även efter en uppdatering eller
   `retire`. Klienten säger det innan något sparas.

---

## 11. Tester

| Vad | Var |
|---|---|
| Argon2id, Ed25519 (strikt), X25519 och HKDF mot RFC-vektorer | `xg-identity`, `web/test/identity.test.mjs` |
| Paritet Rust ↔ JS: kanonisk JSON, födelse ur återställningsnyckeln, id, handtag, loggar, ordning av versioner, valv, offentlig profil, inloggning, bevis | `crates/xg-identity/tests/vectors.rs` → `web/test/identity_vectors.json` (`XG_UPDATE_VECTORS=1`) |
| Förfalskning: en annan födelse med samma tagg men annat id, en födelse med någon annans publika nyckel utan dess signatur, en ändrad händelse, ett bevis från en gammal instans eller till en annan mottagare | `xg-identity`, `web/test/identity.test.mjs` |
| Loggen: fel `prev`, fel signatur, fel nyckel, fel världsfrö, tid i framtiden, efter `retire` | `xg-identity` |
| Versioner: förlängning, grenar med senare tid vinner, lika tid ger lägst hash, ingen återgång | `xg-identity`, `web/test/identity.test.mjs` |
| Valvet: lås upp med lösenord och återställningsnyckeln, nytt lås, spärr (gammalt lösenord och gammalt valv slutar fungera), fräsch instans | `xg-identity`, `web/test/identity.test.mjs` |
| Fri information: giltiga och ogiltiga nycklar, storlek, version som bara går framåt, gammal instans nekas, signeras om vid `restore` | `xg-identity`, `web/test/identity.test.mjs` |
| Servern: registrera, krockande handtag, logga in, gammal `nonce`, fel server, `not_home`, `stale_version`, klient med nyare version gör den gamla ogiltig, spärr återkallar sessioner, profil och privat information, export, takt | `xg-server/tests/identity.rs` |
| Ny instans: med och utan kontofil, bara med återställningskortet, efter `rotate_recovery`, gren när den gamla servern var nere | `xg-server/tests/identity.rs` |
| Spridning: två servrar, bara loggar och profiler (aldrig valv), inget går bakåt, krock ger förlängd tagg | `xg-server/tests/federation.rs` (v0.7) |
| Webbläsare: registrera, logga in, spara information, ladda ner kontot, ny instans på en annan server och inloggning där, den gamla servern svarar `not_home` | `web/e2e/account.mjs` |

---

## 12. Övergång från inloggning med bara användarnamn

- Kontona som finns i dag (namn → `PlayerId`) har inget bevis på vem som äger dem. Med `--claim-legacy` får **den första** som
  registrerar ett konto med samma användarnamn ta över det gamla `PlayerId` (en gång, och det loggas). Flaggan är bara till för
  övergången före den öppna alfan.
- Utan flaggan behålls de gamla kontona i sparfilen men går inte att logga in på.
- `--dev-auth` behåller dagens inloggning för tester och speltest. Webbläsartesterna kör med den, utom `web/e2e/account.mjs`.

---

## 13. Öppna frågor

- Ska ett konto kunna ha **flera primära servrar** samtidigt? I dag nej: en primär server åt gången, och flytt med en ny instans.
- Ska den offentliga loggen och profilen spridas automatiskt mellan anslutna servrar (förslaget, §7), eller bara av klienter?
- Ska ett konto kunna knytas till flera världsfrön? I dag nej (K2), men ett bevis med återställningsnyckeln (§6.9) kan visa att två
  konton har samma ägare.
- Ska Xigna godta globala identiteter (`realm: "global"`, §8.5), och när flyttas biblioteket till ett eget repo?
- Vilka nycklar under `xigna.` ska spelet själv använda i den offentliga profilen (§5.6)?
- När blir det en signerad klient som inte kommer från spelservern (§10.2)?
