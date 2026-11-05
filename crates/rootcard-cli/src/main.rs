//! The `rootcard` key tool (SPEC §18.2): the only program besides `keytool.html` that takes a recovery key ([PWR-6]).
//! It works offline with account files and recovery cards, and talks to a host only when given one ([KT-1]).

#![forbid(unsafe_code)]

use rootcard::account::{InstanceMode, new_instance, register, rotate_recovery};
use rootcard::crypto::{ed25519_sign, sha256};
use rootcard::encoding::{base64url_encode, hex_decode, hex_encode};
use rootcard::file::{account_file_name, card_text, export_account, import_account, read_card, recovery_card};
use rootcard::id::inception;
use rootcard::json::{Map, Value, canonical, parse_json, parse_limited};
use rootcard::keys::{KeyType, parse_key};
use rootcard::log::{Home, LogOrder, LogState, VerifyOptions, compare_logs, retire_event, verify_log};
use rootcard::messages::{Challenge, fetch_message};
use rootcard::proof::{ProofBy, prove, statement_challenge, verify_proof};
use rootcard::recovery::{RecoveryKeys, derive_recovery_keys, new_recovery_key};
use rootcard::vault::{Kdf, NewSlot, Secret, add_slot, check_password, unlock_vault, verify_vault};
use std::process::ExitCode;
use zeroize::Zeroizing;

const USAGE: &str = "rootcard - the key tool for rootcard identities

USAGE:
    rootcard <COMMAND> [OPTIONS]

COMMANDS (high power: they ask for the recovery card):
    new --realm R --username U [--host URL] [--label L] [--dir D]
                        Create an identity: a recovery key, the inception, and with --host a
                        registration with one password. Writes the card and the account file.
    restore --card F --host URL [--account F] [--label L]
                        A new instance at a host, carrying the data and the passwords over
    fresh --card F --host URL [--account F] [--label L]
                        A new instance with an empty vault and one new password
    reset-password --card F [--account F] [--label L]
                        A forgotten password: a new instance at the primary host with one new password
    add-password --card F [--account F] --label L
                        Add a password slot
    revoke-password --card F [--account F] --slot ID
                        Remove a password slot (a new instance at the primary host)
    rotate-recovery --card F [--account F] [--dir D]
                        Replace the recovery key; writes the new card
    retire --card F [--account F] --yes
                        Close the identity forever

    Every high-power command gathers the newest log from the card, --account F and every
    --from URL host, and stops on a fork ([KT-2]).

COMMANDS (no recovery key):
    card --card F [--json]          Print the recovery card (text, or the QR payload)
    inspect F                       Verify an account file, a card or a log and show it
    prove --account F --challenge HEX|--statement JSON --recipient R
                                    An account proof (asks for a password)
    prove --card F --challenge HEX|--statement JSON --recipient R
                                    A root proof (asks for the recovery card)
    verify --log F --proof F --challenge HEX|--statement JSON --recipient R
                                    Verify a proof
    version                         Print the tool and format versions

Passwords are read from the terminal without echo, or from the environment variable
ROOTCARD_PASSWORD when set (for scripts). Only enter your recovery key in this tool.";

type R<T> = Result<T, String>;

fn code(e: rootcard::Error) -> String {
    format!("{} ({})", describe(e), e.code())
}

fn describe(e: rootcard::Error) -> &'static str {
    use rootcard::Error::*;
    match e {
        WrongRecoveryKey => "this recovery key is not the identity's current one",
        BadChecksum => "the recovery key has a typo",
        UnlockFailed => "wrong password or recovery key",
        WeakPassword => "the password is too weak: at least 12 characters, not the username",
        Fork => "two versions of the identity's log fork; the primary host's branch must be extended",
        StaleVersion => "a newer version of the identity exists",
        NotHome => "this host is not the identity's primary host",
        AccountRetired => "the identity is retired",
        _ => "error",
    }
}

struct Args {
    rest: Vec<String>,
}

impl Args {
    fn opt(&self, name: &str) -> Option<String> {
        let i = self.rest.iter().position(|a| a == name)?;
        self.rest.get(i + 1).cloned()
    }
    fn req(&self, name: &str) -> R<String> {
        self.opt(name).ok_or_else(|| format!("missing {name}"))
    }
    fn all(&self, name: &str) -> Vec<String> {
        self.rest
            .windows(2)
            .filter(|w| w[0] == name)
            .map(|w| w[1].clone())
            .collect()
    }
    fn flag(&self, name: &str) -> bool {
        self.rest.iter().any(|a| a == name)
    }
    fn positional(&self) -> Option<String> {
        self.rest.first().filter(|a| !a.starts_with("--")).cloned()
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random(buf: &mut [u8]) {
    if getrandom::fill(buf).is_err() {
        eprintln!("the operating system's random generator failed");
        std::process::exit(70);
    }
}

fn read_json(path: &str) -> R<Value> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    parse_limited(&bytes, rootcard::file::FILE_LIMIT).map_err(|e| format!("{path}: {}", code(e)))
}

fn write_json(path: &str, v: &Value) -> R<()> {
    let mut b = canonical(v);
    b.push(b'\n');
    std::fs::write(path, b).map_err(|e| format!("{path}: {e}"))?;
    eprintln!("wrote {path}");
    Ok(())
}

fn password(prompt: &str) -> R<Zeroizing<String>> {
    if let Ok(p) = std::env::var("ROOTCARD_PASSWORD") {
        return Ok(Zeroizing::new(p));
    }
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|e| format!("reading the password: {e}"))
}

fn new_password(username: &str) -> R<Zeroizing<String>> {
    loop {
        let p = password("New password: ")?;
        if let Err(e) = check_password(&p, username) {
            if std::env::var("ROOTCARD_PASSWORD").is_ok() {
                return Err(code(e));
            }
            eprintln!("{}", code(e));
            continue;
        }
        if std::env::var("ROOTCARD_PASSWORD").is_ok() || *password("Repeat it: ")? == *p {
            return Ok(p);
        }
        eprintln!("the passwords differ");
    }
}

// --- HTTP (HOST_PROTOCOL.md) ---

/// The API root of a host: its base URL, checked ([HST-22]), and the version segment of the HTTP binding
/// (HOST_PROTOCOL.md §1.3, `v0` until 1.0.0). Base URLs (`home.url`, and `url` in signed messages) never include it.
fn api(base: &str) -> R<String> {
    rootcard::check_base_url(base).map_err(|_| {
        format!("{base}: not a host base URL (https://host[:port][/path], no trailing slash and no /v0 at the end)")
    })?;
    Ok(format!("{base}/{}", rootcard::API_VERSION))
}

struct Http(ureq::Agent);

impl Http {
    fn new() -> Self {
        let cfg = ureq::Agent::config_builder().http_status_as_error(false).build();
        Http(cfg.into())
    }

    fn call(&self, method: &str, url: &str, body: Option<&Value>) -> R<(u16, Value)> {
        if !(url.starts_with("https://") || url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost"))
        {
            return Err(format!("{url}: hosts are reached over https"));
        }
        let res = match (method, body) {
            ("GET", _) => self.0.get(url).call(),
            ("PUT", Some(b)) => self
                .0
                .put(url)
                .header("Content-Type", "application/json")
                .send(&canonical(b)[..]),
            (_, Some(b)) => self
                .0
                .post(url)
                .header("Content-Type", "application/json")
                .send(&canonical(b)[..]),
            (_, None) => self.0.post(url).send(&[][..]),
        };
        let mut res = res.map_err(|e| format!("{url}: {e}"))?;
        let status = res.status().as_u16();
        let bytes = res.body_mut().read_to_vec().map_err(|e| format!("{url}: {e}"))?;
        let v = if bytes.is_empty() {
            Value::Bool(true)
        } else {
            parse_json(&bytes).map_err(|e| format!("{url}: {}", code(e)))?
        };
        Ok((status, v))
    }

    fn ok(&self, method: &str, url: &str, body: Option<&Value>) -> R<Value> {
        let (s, v) = self.call(method, url, body)?;
        if (200..300).contains(&s) {
            Ok(v)
        } else {
            let e = v
                .as_object()
                .and_then(|m| m.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            Err(match rootcard::Error::from_code(&e) {
                Some(c) => format!("{url}: {}", code(c)),
                None => format!("{url}: HTTP {s} {e}"),
            })
        }
    }
}

fn get<'a>(v: &'a Value, k: &str) -> R<&'a Value> {
    v.as_object()
        .and_then(|m| m.get(k))
        .ok_or_else(|| format!("answer without {k}"))
}

fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k, v);
    }
    m.into()
}

// --- the identity: card, files and hosts ---

struct Identity {
    card_path: String,
    keys: RecoveryKeys,
    key: Zeroizing<[u8; 32]>,
    log: Vec<Value>,
    state: LogState,
    vault: Option<Value>,
    public: Option<Value>,
}

fn options(realm: &str) -> VerifyOptions {
    VerifyOptions::new([realm]).at(now())
}

/// Keep the newer of `log` and `candidate`; a fork stops the operation ([KT-2], [KT-7]).
fn consider(log: &mut Vec<Value>, candidate: Vec<Value>, source: &str, opts: &VerifyOptions) -> R<()> {
    verify_log(&candidate, opts).map_err(|e| format!("{source}: {}", code(e)))?;
    match compare_logs(log, &candidate).map_err(|e| format!("{source}: {}", code(e)))? {
        LogOrder::Newer => *log = candidate,
        LogOrder::Fork => {
            return Err(format!(
                "{source} holds a log that forks from the one already found (seq {} vs {}). Extend the branch the \
                 primary host holds ([KT-7]).",
                candidate.len() - 1,
                log.len() - 1
            ));
        }
        _ => {}
    }
    Ok(())
}

/// [KT-2]: the newest log from the card, the account file and the hosts; a fork stops the operation.
fn gather(args: &Args, http: &Http, extra_hosts: &[String]) -> R<Identity> {
    let card_path = args.req("--card")?;
    let card = read_card(&read_json(&card_path)?).map_err(code)?;
    let opts = options(&card.realm);
    let mut log = card.log.clone();
    let mut vault = None;
    let mut public = None;
    if let Some(path) = args.opt("--account") {
        let file = read_json(&path)?;
        let a = import_account(&file, &opts).map_err(|e| format!("{path}: {}", code(e)))?;
        if a.state.account != card.account {
            return Err(format!("{path} is another identity"));
        }
        consider(&mut log, a.log.clone(), &path, &opts)?;
        vault = a.vault.map(|(v, _)| v);
        public = a.public.map(|(p, _)| p);
    }
    let mut hosts: Vec<String> = args.all("--from");
    hosts.extend_from_slice(extra_hosts);
    if let Ok(st) = verify_log(&log, &opts)
        && let Some(i) = &st.instance
    {
        hosts.push(i.home.url.clone());
    }
    hosts.dedup();
    for h in &hosts {
        match http.call("GET", &format!("{}/id/{}/log", api(h)?, card.account), None) {
            Ok((200, v)) => {
                let events = get(&v, "events")?.as_array().cloned().unwrap_or_default();
                consider(&mut log, events, h, &opts)?;
            }
            Ok(_) => {}
            Err(e) => eprintln!("warning: {e}"),
        }
    }
    let state = verify_log(&log, &opts).map_err(code)?;
    rootcard::log::check_recovery_key(&state, &card.keys.sign_seed).map_err(code)?;
    Ok(Identity {
        card_path,
        keys: card.keys,
        key: card.key,
        log,
        state,
        vault,
        public,
    })
}

fn home_url(id: &Identity) -> R<String> {
    id.state.instance.as_ref().map(|i| i.home.url.clone()).ok_or_else(|| {
        "no instance found: give the account file (--account F) or the primary host (--from URL)".to_string()
    })
}

/// The current vault, unlocked with the recovery lock: from the account file if current, else fetched from the primary
/// host with a recovery-key fetch ([FET-1]).
fn current_vault(id: &Identity, http: &Http) -> R<(Value, rootcard::vault::Unlocked)> {
    if let Some(v) = &id.vault
        && let Ok(u) = unlock_vault(v, &id.state, &Secret::Recovery(&id.keys))
    {
        return Ok((v.clone(), u));
    }
    let base = home_url(id)?;
    let account = &id.state.account;
    let ch = http.ok(
        "POST",
        &format!("{}/id/{account}/challenge", api(&base)?),
        Some(&obj(vec![("purpose", "fetch".into())])),
    )?;
    let ch = Challenge::from_value(&ch).map_err(code)?;
    let sig = ed25519_sign(
        &id.keys.sign_seed,
        &fetch_message(account, &ch.host, "recovery", &ch.nonce, &base),
    );
    let body = obj(vec![
        ("lock", "recovery".into()),
        ("nonce", base64url_encode(&ch.nonce).into()),
        ("url", base.as_str().into()),
        ("sig", base64url_encode(&sig).into()),
    ]);
    let v = http.ok("POST", &format!("{}/id/{account}/fetch", api(&base)?), Some(&body))?;
    let vault = get(&v, "vault")?.clone();
    let u = unlock_vault(&vault, &id.state, &Secret::Recovery(&id.keys)).map_err(code)?;
    Ok((vault, u))
}

fn host_home(http: &Http, base: &str) -> R<Home> {
    let d = http.ok("GET", &format!("{}/host", api(base)?), None)?;
    let key = parse_key(get(&d, "key")?.as_str().unwrap_or(""), KeyType::Ed25519).map_err(code)?;
    Ok(Home {
        key,
        url: base.to_string(),
    })
}

fn report(state: &LogState) {
    println!("handle:   {}", state.handle);
    println!("account:  {}", state.account);
    println!("realm:    {}", state.realm);
    println!(
        "version:  seq {} hash {}",
        state.version.seq,
        base64url_encode(&state.version.hash)
    );
    match (&state.instance, state.retired) {
        (_, true) => println!("status:   retired"),
        (Some(i), _) => println!("instance: seq {} ({}) at {}", i.seq, i.reason.as_str(), i.home.url),
        (None, _) => println!("instance: none"),
    }
}

/// Submit a new instance ([HST-5]) and tell the previous primary host ([HST-15]).
fn submit_instance(
    http: &Http,
    id: &Identity,
    base: &str,
    mode: InstanceMode<'_>,
    old: Option<&rootcard::vault::Unlocked>,
) -> R<()> {
    let home = host_home(http, base)?;
    let public = id
        .public
        .as_ref()
        .and_then(|p| rootcard::profile::verify_public(p, &id.state).ok())
        .map(|p| p.data);
    let mut rnd = |b: &mut [u8]| random(b);
    let ni = new_instance(&id.state, &id.keys, old, public.as_ref(), mode, &home, now(), &mut rnd).map_err(code)?;
    let account = &id.state.account;
    let body = obj(vec![
        ("events", Value::Array(id.log.clone())),
        ("instance", Value::Object(ni.event.clone())),
        ("vault", ni.vault),
        ("public", ni.public),
    ]);
    http.ok("POST", &format!("{}/id/{account}/instance", api(base)?), Some(&body))?;
    let log = http.ok("GET", &format!("{}/id/{account}/log", api(base)?), None)?;
    let events = get(&log, "events")?.as_array().cloned().unwrap_or_default();
    let st = verify_log(&events, &options(&id.state.realm)).map_err(code)?;
    if let Some(old_home) = id.state.instance.as_ref().map(|i| i.home.url.clone())
        && old_home != base
    {
        let new = Value::Array(events[id.log.len()..].to_vec());
        if let Err(e) = http.ok(
            "POST",
            &format!("{}/id/{account}/events", api(&old_home)?),
            Some(&obj(vec![("events", new)])),
        ) {
            eprintln!("warning: could not tell the previous primary host: {e}");
        }
    }
    report(&st);
    Ok(())
}

/// Write a new identity's recovery card as `<username>-<tag>.card.json` in `dir`.
fn write_card(dir: &str, username: &str, account: &str, card: &Value) -> R<()> {
    write_json(
        &format!("{dir}/{username}-{}.card.json", rootcard::id::tag(account)),
        card,
    )
}

fn slot_label(args: &Args) -> String {
    args.opt("--label").unwrap_or_else(|| "Password".to_string())
}

fn run(cmd: &str, args: &Args) -> R<()> {
    let http = Http::new();
    match cmd {
        "new" => {
            let realm = args.req("--realm")?;
            let username = args.req("--username")?;
            let dir = args.opt("--dir").unwrap_or_else(|| ".".into());
            // A recovery key whose signing seed is usable in every browser ([RK-3], [CRY-9]).
            let rk = new_recovery_key(&realm, &username, &mut |b: &mut [u8]| random(b)).map_err(code)?;
            let (card, file, state) = match args.opt("--host") {
                Some(base) => {
                    let home = host_home(&http, &base)?;
                    let pw = new_password(&username)?;
                    let mut rnd = |b: &mut [u8]| random(b);
                    let reg = register(
                        &rk,
                        &realm,
                        &username,
                        &pw,
                        &slot_label(args),
                        &home,
                        now(),
                        Kdf::DEFAULT,
                        &mut rnd,
                    )
                    .map_err(code)?;
                    // The card is saved before anything is sent: once the host has the identity, the card is the
                    // only copy of its recovery key ([CLT-1], [KT-1]).
                    write_card(&dir, &username, &reg.account, &reg.card)?;
                    let body = obj(vec![
                        ("log", Value::Array(reg.log.clone())),
                        ("vault", reg.vault.clone()),
                        ("public", reg.public.clone()),
                    ]);
                    http.ok("POST", &format!("{}/id/register", api(&base)?), Some(&body))?;
                    let log = http.ok("GET", &format!("{}/id/{}/log", api(&base)?, reg.account), None)?;
                    let events = get(&log, "events")?.as_array().cloned().unwrap_or_default();
                    let st = verify_log(&events, &options(&realm)).map_err(code)?;
                    let file = export_account(&st, &events, Some(&reg.public), Some(&reg.vault), None);
                    (reg.card, file, st)
                }
                None => {
                    let keys = derive_recovery_keys(&rk, &realm, &username);
                    let inc = inception(&keys, &realm, &username).map_err(code)?;
                    let log = vec![Value::Object(inc)];
                    let st = verify_log(&log, &options(&realm)).map_err(code)?;
                    let card = recovery_card(&realm, &username, &st.account, &rk, None);
                    write_card(&dir, &username, &st.account, &card)?;
                    (card, export_account(&st, &log, None, None, None), st)
                }
            };
            write_json(&format!("{dir}/{}", account_file_name(&state)), &file)?;
            println!("{}", card_text(&card).map_err(code)?);
            report(&state);
            eprintln!("\nKeep the recovery card offline. It is the only way to reset a password or move the identity.");
            Ok(())
        }
        "card" => {
            let card = read_json(&args.req("--card")?)?;
            if args.flag("--json") {
                println!("{}", String::from_utf8_lossy(&canonical(&card)));
            } else {
                println!("{}", card_text(&card).map_err(code)?);
            }
            Ok(())
        }
        "inspect" => {
            let path = args.positional().or_else(|| args.opt("--file")).ok_or("missing file")?;
            let v = read_json(&path)?;
            let format = v
                .as_object()
                .and_then(|m| m.get("format"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let realms = |v: &Value| -> Vec<String> {
                let first = match v {
                    Value::Array(a) => a.first(),
                    Value::Object(m) => m.get("log").and_then(Value::as_array).and_then(|a| a.first()),
                    _ => None,
                };
                first
                    .and_then(|e| {
                        e.as_object()?
                            .get("body")?
                            .as_object()?
                            .get("realm")?
                            .as_str()
                            .map(str::to_string)
                    })
                    .into_iter()
                    .collect()
            };
            let st = match format {
                "rootcard-card" => read_card(&v).map_err(code)?.state,
                "rootcard-account" => {
                    let a = import_account(&v, &VerifyOptions::new(realms(&v)).at(now())).map_err(code)?;
                    if let Some((_, p)) = &a.public {
                        println!("profile:  rev {}, {} keys", p.rev, p.data.len());
                    }
                    if let Some((_, vi)) = &a.vault {
                        let labels: Vec<String> = vi.slots.iter().map(|s| format!("{} ({})", s.label, s.id)).collect();
                        println!("vault:    rev {}, passwords: {}", vi.rev, labels.join(", "));
                    }
                    a.state
                }
                _ => {
                    let log = v.as_array().cloned().ok_or("not an account file, a card or a log")?;
                    verify_log(&log, &VerifyOptions::new(realms(&v)).at(now())).map_err(code)?
                }
            };
            report(&st);
            Ok(())
        }
        "prove" | "verify" => {
            let challenge = match (args.opt("--challenge"), args.opt("--statement")) {
                (Some(h), _) => {
                    let b = hex_decode(&h).map_err(code)?;
                    b.try_into()
                        .map_err(|_| "the challenge is 32 bytes of hex".to_string())?
                }
                (None, Some(s)) => statement_challenge(&parse_json(s.as_bytes()).map_err(code)?).map_err(code)?,
                _ => return Err("missing --challenge or --statement".into()),
            };
            let recipient = args.req("--recipient")?;
            if cmd == "verify" {
                let log_v = read_json(&args.req("--log")?)?;
                let log = match &log_v {
                    Value::Array(a) => a.clone(),
                    Value::Object(m) => m.get("log").and_then(Value::as_array).cloned().unwrap_or_default(),
                    _ => Vec::new(),
                };
                let realm = log
                    .first()
                    .and_then(|e| {
                        e.as_object()?
                            .get("body")?
                            .as_object()?
                            .get("realm")?
                            .as_str()
                            .map(str::to_string)
                    })
                    .unwrap_or_default();
                let proof = read_json(&args.req("--proof")?)?;
                let st = verify_proof(&proof, &log, &challenge, &recipient, &options(&realm)).map_err(code)?;
                println!("valid proof by {}", st.handle);
                report(&st);
                return Ok(());
            }
            let proof = if args.opt("--card").is_some() {
                let id = gather(args, &http, &[])?;
                prove(&id.state, ProofBy::Recovery, &id.keys.sign_seed, &challenge, &recipient).map_err(code)?
            } else {
                let path = args.req("--account")?;
                let file = read_json(&path)?;
                let a = import_account(&file, &VerifyOptions::new(Vec::<String>::new()).at(now()))
                    .or_else(|_| {
                        let realm = file
                            .as_object()
                            .and_then(|m| m.get("realm"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        import_account(&file, &options(realm))
                    })
                    .map_err(code)?;
                let (vault, info) = a.vault.ok_or("the account file has no vault")?;
                let slot = args
                    .opt("--slot")
                    .unwrap_or_else(|| info.slots.first().map(|s| s.id.clone()).unwrap_or_default());
                let pw = password("Password: ")?;
                let u = unlock_vault(
                    &vault,
                    &a.state,
                    &Secret::Password {
                        lock: &slot,
                        password: &pw,
                    },
                )
                .map_err(code)?;
                prove(
                    &a.state,
                    ProofBy::Account,
                    &u.contents.account_seed,
                    &challenge,
                    &recipient,
                )
                .map_err(code)?
            };
            println!("{}", String::from_utf8_lossy(&canonical(&proof)));
            Ok(())
        }
        "restore" | "fresh" => {
            let base = args.req("--host")?;
            let id = gather(args, &http, std::slice::from_ref(&base))?;
            if cmd == "restore" {
                let (_, u) = current_vault(&id, &http)?;
                submit_instance(&http, &id, &base, InstanceMode::Restore, Some(&u))
            } else {
                let pw = new_password(&id.state.username)?;
                let label = slot_label(args);
                let slot = NewSlot {
                    label: &label,
                    password: &pw,
                    username: &id.state.username,
                    kdf: Kdf::DEFAULT,
                };
                submit_instance(&http, &id, &base, InstanceMode::Fresh(slot), None)
            }
        }
        "reset-password" | "revoke-password" => {
            let id = gather(args, &http, &[])?;
            let base = home_url(&id)?;
            let (_, u) = current_vault(&id, &http)?;
            if cmd == "reset-password" {
                let pw = new_password(&id.state.username)?;
                let label = slot_label(args);
                let slot = NewSlot {
                    label: &label,
                    password: &pw,
                    username: &id.state.username,
                    kdf: Kdf::DEFAULT,
                };
                submit_instance(&http, &id, &base, InstanceMode::Reset(slot), Some(&u))
            } else {
                let drop = args.req("--slot")?;
                if !u.info.slots.iter().any(|s| s.id == drop) {
                    return Err(format!("no password slot {drop}"));
                }
                submit_instance(&http, &id, &base, InstanceMode::Revoke(&[drop.as_str()]), Some(&u))
            }
        }
        "add-password" => {
            let id = gather(args, &http, &[])?;
            let base = home_url(&id)?;
            let (vault, u) = current_vault(&id, &http)?;
            let pw = new_password(&id.state.username)?;
            let label = args.req("--label")?;
            let mut rnd = |b: &mut [u8]| random(b);
            let slot = NewSlot {
                label: &label,
                password: &pw,
                username: &id.state.username,
                kdf: Kdf::DEFAULT,
            };
            let v = add_slot(&u, &vault, &id.keys, &slot, &mut rnd).map_err(code)?;
            let info = verify_vault(&v, &id.state).map_err(code)?;
            http.ok(
                "PUT",
                &format!("{}/id/{}/vault", api(&base)?, id.state.account),
                Some(&obj(vec![("vault", v)])),
            )?;
            for s in &info.slots {
                println!("password {} ({})", s.label, s.id);
            }
            Ok(())
        }
        "rotate-recovery" => {
            let id = gather(args, &http, &[])?;
            let base = home_url(&id)?;
            let (vault, u) = current_vault(&id, &http)?;
            let new_key =
                new_recovery_key(&id.state.realm, &id.state.username, &mut |b: &mut [u8]| random(b)).map_err(code)?;
            let mut rnd = |b: &mut [u8]| random(b);
            let rot =
                rotate_recovery(&id.state, &id.log, &id.keys, &new_key, &vault, &u, now(), &mut rnd).map_err(code)?;
            // The new card is saved and shown before the rotation is sent: once the host has the event, the old key
            // no longer signs and the new card is the only copy of the new key ([KT-5]).
            let dir = args.opt("--dir").unwrap_or_else(|| ".".into());
            let path = format!(
                "{dir}/{}-{}.card.json",
                id.state.username,
                &hex_encode(&sha256(new_key.as_ref()))[..8]
            );
            write_json(&path, &rot.card)?;
            println!("{}", card_text(&rot.card).map_err(code)?);
            let body = obj(vec![
                ("events", Value::Array(vec![rot.event.clone().into()])),
                ("vault", rot.vault),
            ]);
            if let Err(e) = http.ok(
                "POST",
                &format!("{}/id/{}/events", api(&base)?, id.state.account),
                Some(&body),
            ) {
                return Err(format!(
                    "{e}\nThe rotation may or may not have reached the primary host. Keep both cards: the new card {path} \
                     and the old card {}. To see which is current, run `rootcard prove --card {path} --from {base} \
                     --statement '\"check\"' --recipient check`: it changes nothing, and it answers \
                     wrong_recovery_key if the rotation did not arrive (then the old card is still current).",
                    id.card_path
                ));
            }
            eprintln!("The new card is {path}. Destroy the old card {}.", id.card_path);
            let _ = id.key;
            Ok(())
        }
        "retire" => {
            if !args.flag("--yes") {
                return Err("retiring closes the identity forever; add --yes to confirm".into());
            }
            let id = gather(args, &http, &[])?;
            let ev = retire_event(&id.state, &id.keys.sign_seed, now()).map_err(code)?;
            let base = home_url(&id)?;
            let body = obj(vec![("events", Value::Array(vec![ev.into()]))]);
            http.ok(
                "POST",
                &format!("{}/id/{}/events", api(&base)?, id.state.account),
                Some(&body),
            )?;
            println!("{} is retired", id.state.handle);
            Ok(())
        }
        _ => Err(format!("unknown command: {cmd}\n\n{USAGE}")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("help" | "--help" | "-h") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("version" | "--version" | "-V") => {
            println!(
                "rootcard {} (format v{})",
                env!("CARGO_PKG_VERSION"),
                rootcard::FORMAT_VERSION
            );
            ExitCode::SUCCESS
        }
        Some(cmd) => {
            let a = Args {
                rest: args[1..].to_vec(),
            };
            match run(cmd, &a) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("rootcard: {e}");
                    ExitCode::from(1)
                }
            }
        }
    }
}
