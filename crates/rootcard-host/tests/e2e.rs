//! End to end through the HTTP router with two hosts: registration, login, a session, a password change, export,
//! a move to a second host (the first answers `not_home`), a host key rotation, an address change, a race on one
//! store, and retirement. The client side uses the core with the `vault` feature, as an application client would.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rootcard::account::{InstanceMode, new_instance, register, rotate_recovery};
use rootcard::crypto::{ed25519_public, ed25519_sign};
use rootcard::encoding::{base64url_decode, base64url_encode};
use rootcard::file::import_account;
use rootcard::json::{Map, Value, canonical, parse_json};
use rootcard::keys::{KeyType, format_key};
use rootcard::log::{Home, LogState, VerifyOptions, Version, retire_event, verify_log};
use rootcard::messages::{Challenge, LoginRequest, change_message, fetch_message};
use rootcard::profile::sign_public;
use rootcard::recovery::derive_recovery_keys;
use rootcard::testing::TestRandom;
use rootcard::vault::{Kdf, Secret, change_password, derive_lock_secrets, regrant, unlock_vault, verify_vault};
use rootcard_host::http::{API_VERSION, Request, route};
use rootcard_host::peer::sign_peer_request;
use rootcard_host::store::{MemoryChallengeStore, MemoryIdentityStore, MemorySessionStore};
use rootcard_host::{Host, HostConfig, RealmConfig, UsernamePolicy};
use std::cell::RefCell;
use zeroize::Zeroizing;

type TestHost = Host<MemoryIdentityStore, MemoryChallengeStore, MemorySessionStore>;

const T0: i64 = 1_800_000_000;
const PW: &str = "correct horse battery staple";
const PW2: &str = "a new and better passphrase";

fn config(seed: [u8; 32], url: &str) -> HostConfig {
    HostConfig {
        key_seed: Zeroizing::new(seed),
        retired_keys: Vec::new(),
        urls: vec![url.to_string()],
        realms: vec![RealmConfig {
            realm: "global".into(),
            policy: UsernamePolicy::DEFAULT,
        }],
        peers: Vec::new(),
    }
}

fn host(seed: [u8; 32], url: &str) -> TestHost {
    Host::new(
        config(seed, url),
        MemoryIdentityStore::new(),
        MemoryChallengeStore::new(),
        MemorySessionStore::new(),
    )
}

thread_local! {
    static RNG: RefCell<TestRandom> = RefCell::new(TestRandom::new(b"e2e"));
}

fn fill(b: &mut [u8]) {
    RNG.with(|r| r.borrow_mut().fill(b));
}

/// Call an endpoint; `path` is relative to the API root `<base URL>/v0` (HOST_PROTOCOL.md §1.3).
fn call(h: &TestHost, method: &str, path: &str, body: Option<Value>, bearer: Option<&str>, now: i64) -> (u16, Value) {
    call_raw(h, method, &format!("/{API_VERSION}{path}"), body, bearer, now)
}

/// Call a path relative to the base URL, without adding the API version.
fn call_raw(
    h: &TestHost,
    method: &str,
    path: &str,
    body: Option<Value>,
    bearer: Option<&str>,
    now: i64,
) -> (u16, Value) {
    let req = Request {
        method: method.into(),
        path: path.into(),
        bearer: bearer.map(str::to_string),
        peer: None,
        body: body.map(|b| canonical(&b)).unwrap_or_default(),
    };
    let r = route(h, &req, now, &mut fill);
    let v = r.body.map(|b| parse_json(&b).unwrap()).unwrap_or(Value::Bool(true));
    (r.status, v)
}

fn get<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.as_object()
        .unwrap()
        .get(k)
        .unwrap_or_else(|| panic!("no {k} in {v:?}"))
}

fn err(v: &Value) -> &str {
    get(v, "error").as_str().unwrap()
}

fn obj(pairs: &[(&str, Value)]) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(*k, v.clone());
    }
    m.into()
}

fn opts() -> VerifyOptions {
    VerifyOptions::new(["global"])
}

fn fetch_log(h: &TestHost, account: &str) -> (Vec<Value>, LogState) {
    let (s, v) = call(h, "GET", &format!("/id/{account}/log"), None, None, T0);
    assert_eq!(s, 200);
    let events = get(&v, "events").as_array().unwrap().clone();
    let st = verify_log(&events, &opts()).unwrap();
    (events, st)
}

/// A password login ([LGN-1]): lock hints, fetch with the lock's auth key, unlock, login. Returns the token.
fn login(h: &TestHost, account: &str, url: &str, password: &str, now: i64) -> Result<String, (u16, String)> {
    let (_, st) = fetch_log(h, account);
    let (s, hints) = call(h, "GET", &format!("/id/{account}/locks"), None, None, now);
    if s != 200 {
        return Err((s, err(&hints).to_string()));
    }
    let hint = &get(&hints, "locks").as_array().unwrap()[0];
    let lock = get(hint, "id").as_str().unwrap().to_string();
    let kdf = get(hint, "kdf");
    let salt: [u8; 16] = base64url_decode(get(kdf, "salt").as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let k = Kdf {
        m: get(kdf, "m").as_int().unwrap() as u32,
        t: get(kdf, "t").as_int().unwrap() as u32,
        p: 1,
    };
    let secrets = derive_lock_secrets(account, &lock, password, &k, &salt).unwrap();
    let (_, ch) = call(
        h,
        "POST",
        &format!("/id/{account}/challenge"),
        Some(obj(&[("purpose", "fetch".into())])),
        None,
        now,
    );
    let ch = Challenge::from_value(&ch).unwrap();
    let sig = ed25519_sign(
        &secrets.auth_seed,
        &fetch_message(account, &ch.host, &lock, &ch.nonce, url),
    );
    let body = obj(&[
        ("lock", lock.as_str().into()),
        ("nonce", base64url_encode(&ch.nonce).into()),
        ("url", url.into()),
        ("sig", base64url_encode(&sig).into()),
    ]);
    let (s, v) = call(h, "POST", &format!("/id/{account}/fetch"), Some(body), None, now);
    if s != 200 {
        return Err((s, err(&v).to_string()));
    }
    let vault = get(&v, "vault").clone();
    let u = unlock_vault(&vault, &st, &Secret::Password { lock: &lock, password })
        .map_err(|e| (0, e.code().to_string()))?;
    let (_, ch) = call(
        h,
        "POST",
        &format!("/id/{account}/challenge"),
        Some(obj(&[("purpose", "login".into())])),
        None,
        now,
    );
    let ch = Challenge::from_value(&ch).unwrap();
    let inst = st.instance.clone().unwrap();
    let req = LoginRequest::sign(
        account,
        "global",
        &inst.home.key,
        &st.version,
        &ch,
        url,
        &lock,
        &u.contents.account_seed,
        &u.lock_seed,
    )
    .unwrap();
    let mut body = req.to_value().as_object().unwrap().clone();
    body.remove("account");
    let (s, v) = call(h, "POST", &format!("/id/{account}/login"), Some(body.into()), None, now);
    if s != 200 {
        return Err((s, err(&v).to_string()));
    }
    Ok(get(&v, "token").as_str().unwrap().to_string())
}

#[test]
fn endpoints_live_under_the_api_version() {
    let a = host([1; 32], "https://a.example");
    assert_eq!(API_VERSION, "v0");
    let (s, desc) = call_raw(&a, "GET", "/v0/host", None, None, T0);
    assert_eq!(s, 200);
    assert!(desc.as_object().unwrap().get("key").is_some());
    for path in ["/host", "/v1/host", "/v00/host", "/V0/host", "/host/v0", "/v0"] {
        let (s, v) = call_raw(&a, "GET", path, None, None, T0);
        assert_eq!(s, 404, "{path}");
        assert_eq!(err(&v), "unknown_account", "{path}");
    }
}

#[test]
fn host_addresses_are_base_urls_without_a_version() {
    assert!(config([1; 32], "https://a.example").check().is_ok());
    assert!(config([1; 32], "https://example.com/rootcard").check().is_ok());
    for bad in [
        "https://a.example/v0",
        "https://a.example/rootcard/v1",
        "https://a.example/",
        "http://a.example",
    ] {
        assert_eq!(config([1; 32], bad).check(), Err(rootcard::Error::BadField), "{bad}");
    }
    let mut none = config([1; 32], "https://a.example");
    none.urls.clear();
    assert!(none.check().is_err());
}

#[test]
fn peer_requests_sign_the_versioned_path() {
    let (sa, sb) = ([1u8; 32], [2u8; 32]);
    let mut cfg = config(sb, "https://b.example");
    cfg.peers = vec![ed25519_public(&sa)];
    let b = Host::new(
        cfg,
        MemoryIdentityStore::new(),
        MemoryChallengeStore::new(),
        MemorySessionStore::new(),
    );
    let pb = ed25519_public(&sb);
    let send = |signed: &str, sent: &str| {
        let req = Request {
            method: "GET".into(),
            path: sent.into(),
            peer: Some(sign_peer_request(&sa, "GET", signed, T0, &pb, b"")),
            ..Request::default()
        };
        route(&b, &req, T0, &mut fill).status
    };
    let path = format!("/{API_VERSION}/peer/changes?since=0");
    assert_eq!(send(&path, &path), 200);
    // A signature over the unversioned path does not authorize the versioned request.
    assert_eq!(send("/peer/changes?since=0", &path), 401);
}

#[test]
fn two_hosts_end_to_end() {
    let a = host([0xa1; 32], "https://a.example");
    let b = host([0xb2; 32], "https://b.example");

    // Registration at A ([CLT-1], [HST-3]).
    let (_, desc) = call(&a, "GET", "/host", None, None, T0);
    let a_key = rootcard::keys::parse_key(get(&desc, "key").as_str().unwrap(), KeyType::Ed25519).unwrap();
    let mut rng = TestRandom::new(b"client");
    let rk = rng.bytes::<32>();
    let mut random = |x: &mut [u8]| rng.fill(x);
    let reg = register(
        &rk,
        "global",
        "Astra",
        PW,
        "Laptop",
        &Home {
            key: a_key,
            url: "https://a.example".into(),
        },
        T0,
        Kdf::MIN,
        &mut random,
    )
    .unwrap();
    let body = obj(&[
        ("log", Value::Array(reg.log.clone())),
        ("vault", reg.vault.clone()),
        ("public", reg.public.clone()),
    ]);
    let (s, first) = call(&a, "POST", "/id/register", Some(body.clone()), None, T0);
    assert_eq!(s, 201, "{first:?}");
    // [HST-20] a retry gets the same answer, receipt included.
    let (s, again) = call(&a, "POST", "/id/register", Some(body), None, T0 + 5);
    assert_eq!((s, &again), (201, &first));
    let account = reg.account.clone();
    let (log1, st1) = fetch_log(&a, &account);
    assert_eq!(log1.len(), 2);
    // [HST-6] a registration outside the receipt window fails.
    let mut rng2 = TestRandom::new(b"client-2");
    let rk2 = rng2.bytes::<32>();
    let mut random2 = |x: &mut [u8]| rng2.fill(x);
    let late = register(
        &rk2,
        "global",
        "Bodil",
        PW,
        "Laptop",
        &Home {
            key: a_key,
            url: "https://a.example".into(),
        },
        T0,
        Kdf::MIN,
        &mut random2,
    )
    .unwrap();
    let body = obj(&[("log", Value::Array(late.log.clone())), ("vault", late.vault.clone())]);
    let (s, v) = call(&a, "POST", "/id/register", Some(body.clone()), None, T0 + 601);
    assert_eq!((s, err(&v)), (400, "bad_time"));
    // A registration naming another host.
    let (s, v) = call(&b, "POST", "/id/register", Some(body), None, T0);
    assert_eq!((s, err(&v)), (400, "wrong_host"));

    // Lookup by handle.
    let (s, v) = call(
        &a,
        "GET",
        &format!("/id/lookup?handle=Astra%23{}", &account[..4]),
        None,
        None,
        T0,
    );
    assert_eq!((s, get(&v, "account").as_str().unwrap()), (200, account.as_str()));

    // Login ([LGN-1]) and a session ([HST-10]).
    let token = login(&a, &account, "https://a.example", PW, T0 + 10).unwrap();
    assert_eq!(
        login(&a, &account, "https://a.example", "wrong password!!", T0 + 10)
            .unwrap_err()
            .1,
        "bad_signature"
    );
    // [LGN-4] the address the client uses must be the host's.
    assert_eq!(
        login(&a, &account, "https://evil.example", PW, T0 + 10).unwrap_err().1,
        "wrong_host"
    );
    let (s, v) = call(&a, "GET", "/session/vault", None, Some(&token), T0 + 20);
    assert_eq!(s, 200);
    let vault = get(&v, "vault").clone();
    assert_eq!(call(&a, "GET", "/session/vault", None, Some("AAAA"), T0 + 20).0, 401);

    // [DAT-3] a profile update with the session.
    let keys = derive_recovery_keys(&rk, "global", "Astra");
    let u = unlock_vault(&vault, &st1, &Secret::Recovery(&keys)).unwrap();
    let inst = base64url_encode(&st1.instance.as_ref().unwrap().hash);
    let p2 = sign_public(
        &account,
        &inst,
        2,
        &Map::new().with("user.name", "Astra"),
        &u.contents.account_seed,
    )
    .unwrap();
    let (s, _) = call(
        &a,
        "PUT",
        "/session/public",
        Some(obj(&[("public", p2.clone())])),
        Some(&token),
        T0 + 30,
    );
    assert_eq!(s, 200);
    let (s, v) = call(
        &a,
        "PUT",
        "/session/public",
        Some(obj(&[("public", p2)])),
        Some(&token),
        T0 + 30,
    );
    assert_eq!((s, err(&v)), (409, "stale_rev"));

    // [HST-19] two requests race on one store: exactly one profile update with rev 3 wins.
    let racers: Vec<Value> = ["one", "two"]
        .iter()
        .map(|n| {
            sign_public(
                &account,
                &inst,
                3,
                &Map::new().with("user.name", *n),
                &u.contents.account_seed,
            )
            .unwrap()
        })
        .collect();
    let results: Vec<u16> = std::thread::scope(|sc| {
        let hs: Vec<_> = racers
            .iter()
            .map(|p| {
                let (a, token) = (&a, &token);
                sc.spawn(move || {
                    call(
                        a,
                        "PUT",
                        "/session/public",
                        Some(obj(&[("public", p.clone())])),
                        Some(token),
                        T0 + 40,
                    )
                    .0
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(results.iter().filter(|s| **s == 200).count(), 1, "{results:?}");

    // [CHG-1], [CHG-2] a password change with the old password.
    let slot = verify_vault(&vault, &st1).unwrap().slots[0].id.clone();
    let up = unlock_vault(
        &vault,
        &st1,
        &Secret::Password {
            lock: &slot,
            password: PW,
        },
    )
    .unwrap();
    let mut random = |x: &mut [u8]| rng.fill(x);
    let (v2, new_hash) = change_password(&up, &vault, &slot, PW2, &Kdf::MIN, &mut random).unwrap();
    let (_, ch) = call(
        &a,
        "POST",
        &format!("/id/{account}/challenge"),
        Some(obj(&[("purpose", "change".into())])),
        None,
        T0 + 50,
    );
    let ch = Challenge::from_value(&ch).unwrap();
    let proof = ed25519_sign(
        &up.lock_seed,
        &change_message(&account, &ch.host, &slot, &new_hash, &ch.nonce, "https://a.example"),
    );
    let body = obj(&[
        ("lock", slot.as_str().into()),
        ("nonce", base64url_encode(&ch.nonce).into()),
        ("url", "https://a.example".into()),
        ("proof", base64url_encode(&proof).into()),
        ("vault", v2.clone()),
    ]);
    let (s, v) = call(
        &a,
        "POST",
        "/session/password",
        Some(body.clone()),
        Some(&token),
        T0 + 50,
    );
    assert_eq!(s, 200, "{v:?}");
    // [CHL-2] the nonce is used up.
    let (s, v) = call(&a, "POST", "/session/password", Some(body), Some(&token), T0 + 51);
    assert_eq!((s, err(&v)), (401, "challenge_unknown"));
    // [LGN-5] the old password stops working at once; the new one logs in.
    assert_eq!(
        login(&a, &account, "https://a.example", PW, T0 + 60).unwrap_err().1,
        "bad_signature"
    );
    login(&a, &account, "https://a.example", PW2, T0 + 60).unwrap();
    // [CHL-2] an expired challenge.
    let (_, ch) = call(
        &a,
        "POST",
        &format!("/id/{account}/challenge"),
        Some(obj(&[("purpose", "fetch".into())])),
        None,
        T0,
    );
    let ch = Challenge::from_value(&ch).unwrap();
    let body = obj(&[
        ("lock", "recovery".into()),
        ("nonce", base64url_encode(&ch.nonce).into()),
        ("url", "https://a.example".into()),
        ("sig", base64url_encode(&[0u8; 64]).into()),
    ]);
    let (s, v) = call(&a, "POST", &format!("/id/{account}/fetch"), Some(body), None, T0 + 61);
    assert_eq!((s, err(&v)), (401, "challenge_expired"));

    // [FIL-2], [FIL-3] export.
    let (s, file) = call(&a, "GET", "/session/export", None, Some(&token), T0 + 70);
    assert_eq!(s, 200);
    let imported = import_account(&file, &opts()).unwrap();
    assert_eq!(imported.state, st1);

    // [KT-3] move to B with the recovery key: fetch the vault with the recovery lock at A, mint a restore at B.
    let (_, ch) = call(
        &a,
        "POST",
        &format!("/id/{account}/challenge"),
        Some(obj(&[("purpose", "fetch".into())])),
        None,
        T0 + 80,
    );
    let ch = Challenge::from_value(&ch).unwrap();
    let sig = ed25519_sign(
        &keys.sign_seed,
        &fetch_message(&account, &ch.host, "recovery", &ch.nonce, "https://a.example"),
    );
    let body = obj(&[
        ("lock", "recovery".into()),
        ("nonce", base64url_encode(&ch.nonce).into()),
        ("url", "https://a.example".into()),
        ("sig", base64url_encode(&sig).into()),
    ]);
    let (s, v) = call(&a, "POST", &format!("/id/{account}/fetch"), Some(body), None, T0 + 80);
    assert_eq!(s, 200);
    let current = get(&v, "vault").clone();
    let ur = unlock_vault(&current, &st1, &Secret::Recovery(&keys)).unwrap();
    let (_, bdesc) = call(&b, "GET", "/host", None, None, T0);
    let b_key = rootcard::keys::parse_key(get(&bdesc, "key").as_str().unwrap(), KeyType::Ed25519).unwrap();
    let mut random = |x: &mut [u8]| rng.fill(x);
    let ni = new_instance(
        &st1,
        &keys,
        Some(&ur),
        None,
        InstanceMode::Restore,
        &Home {
            key: b_key,
            url: "https://b.example".into(),
        },
        T0 + 90,
        &mut random,
    )
    .unwrap();
    let body = obj(&[
        ("events", Value::Array(log1.clone())),
        ("instance", Value::Object(ni.event.clone())),
        ("vault", ni.vault.clone()),
        ("public", ni.public.clone()),
    ]);
    let (s, v) = call(
        &b,
        "POST",
        &format!("/id/{account}/instance"),
        Some(body.clone()),
        None,
        T0 + 90,
    );
    assert_eq!(s, 201, "{v:?}");
    let (s, again) = call(
        &b,
        "POST",
        &format!("/id/{account}/instance"),
        Some(body),
        None,
        T0 + 95,
    );
    assert_eq!((s, &again), (201, &v), "[HST-20]");
    let (log2, st2) = fetch_log(&b, &account);
    // B pushes the instance to A ([HST-15]); A adopts it and is no longer home ([HST-7]).
    let (s, _) = call(
        &a,
        "POST",
        &format!("/id/{account}/events"),
        Some(obj(&[("events", Value::Array(log2[2..].to_vec()))])),
        None,
        T0 + 100,
    );
    assert_eq!(s, 200);
    let (s, v) = call(&a, "GET", &format!("/id/{account}/locks"), None, None, T0 + 100);
    assert_eq!((s, err(&v)), (409, "not_home"));
    assert_eq!(get(get(&v, "home"), "url").as_str(), Some("https://b.example"));
    // [HST-11] the session of the old instance is gone.
    assert_eq!(call(&a, "GET", "/session/vault", None, Some(&token), T0 + 100).0, 401);
    // An older log is refused ([VER-4]).
    let (s, v) = call(
        &b,
        "POST",
        &format!("/id/{account}/events"),
        Some(obj(&[("events", Value::Array(log1[1..].to_vec()))])),
        None,
        T0 + 100,
    );
    assert_eq!((s, err(&v)), (409, "stale_version"));
    // The password carried over: login at B.
    login(&b, &account, "https://b.example", PW2, T0 + 110).unwrap();

    // [HST-17] B rotates its host key and [HST-18] changes its address; existing identities keep working.
    let Host {
        store,
        challenges,
        sessions,
        ..
    } = b;
    let mut cfg = config([0xb3; 32], "https://id.b.example");
    cfg.retired_keys = vec![b_key];
    let b2 = Host::new(cfg, store, challenges, sessions);
    login(&b2, &account, "https://id.b.example", PW2, T0 + 120).unwrap();
    assert_eq!(
        login(&b2, &account, "https://b.example", PW2, T0 + 120).unwrap_err().1,
        "wrong_host"
    );

    // [KT-6] retire: every host answers account_retired.
    let ret = retire_event(&st2, &keys.sign_seed, T0 + 200).unwrap();
    let (s, _) = call(
        &b2,
        "POST",
        &format!("/id/{account}/events"),
        Some(obj(&[("events", Value::Array(vec![ret.clone().into()]))])),
        None,
        T0 + 200,
    );
    assert_eq!(s, 200);
    let (s, v) = call(&b2, "GET", &format!("/id/{account}/locks"), None, None, T0 + 200);
    assert_eq!((s, err(&v)), (410, "account_retired"));
    let _ = (
        ed25519_public(&[1; 32]),
        format_key(KeyType::Ed25519, &[0; 32]),
        Version { seq: 0, hash: [0; 32] },
    );
}

/// Regression (0.2.0): `POST /id/{account}/events` with a rotation and the new vault answered success without storing
/// the vault when the rotation was already stored (it arrived first from someone else, [HST-14]). The stored vault then
/// no longer verified against the new recovery key and nobody could log in.
#[test]
fn a_rotation_that_arrived_first_still_gets_its_vault() {
    let a = host([0xa3; 32], "https://a.example");
    let (_, desc) = call(&a, "GET", "/host", None, None, T0);
    let a_key = rootcard::keys::parse_key(get(&desc, "key").as_str().unwrap(), KeyType::Ed25519).unwrap();
    let mut rng = TestRandom::new(b"rotation");
    let rk = rng.bytes::<32>();
    let new_rk = rng.bytes::<32>();
    let mut random = |x: &mut [u8]| rng.fill(x);
    let home = Home {
        key: a_key,
        url: "https://a.example".into(),
    };
    let reg = register(&rk, "global", "Astra", PW, "Laptop", &home, T0, Kdf::MIN, &mut random).unwrap();
    let body = obj(&[
        ("log", Value::Array(reg.log.clone())),
        ("vault", reg.vault.clone()),
        ("public", reg.public.clone()),
    ]);
    assert_eq!(call(&a, "POST", "/id/register", Some(body), None, T0).0, 201);
    let account = reg.account.clone();
    let (log, st) = fetch_log(&a, &account);
    let keys = derive_recovery_keys(&rk, "global", "Astra");
    let u = unlock_vault(&reg.vault, &st, &Secret::Recovery(&keys)).unwrap();
    let rot = rotate_recovery(&st, &log, &keys, &new_rk, &reg.vault, &u, T0 + 10, &mut random).unwrap();
    let event: Value = rot.event.clone().into();

    // The rotation arrives alone first: the stored vault no longer verifies, so logins fail.
    let alone = obj(&[("events", Value::Array(vec![event.clone()]))]);
    assert_eq!(
        call(&a, "POST", &format!("/id/{account}/events"), Some(alone), None, T0 + 20).0,
        200
    );
    assert!(login(&a, &account, "https://a.example", PW, T0 + 20).is_err());

    // A vault whose new grant is signed by the rotated-out key is still refused.
    let stale_grant = regrant(&u, &reg.vault, &keys, &mut random).unwrap();
    let with_old = obj(&[("events", Value::Array(vec![event.clone()])), ("vault", stale_grant)]);
    let (s, v) = call(
        &a,
        "POST",
        &format!("/id/{account}/events"),
        Some(with_old),
        None,
        T0 + 25,
    );
    assert_eq!(s, 400, "{v:?}");

    // The owner's submission of the rotation with its vault stores the vault, and a retry gets the same answer.
    let with_vault = obj(&[("events", Value::Array(vec![event])), ("vault", rot.vault.clone())]);
    let (s, first) = call(
        &a,
        "POST",
        &format!("/id/{account}/events"),
        Some(with_vault.clone()),
        None,
        T0 + 30,
    );
    assert_eq!(s, 200, "{first:?}");
    let (s, again) = call(
        &a,
        "POST",
        &format!("/id/{account}/events"),
        Some(with_vault),
        None,
        T0 + 31,
    );
    assert_eq!((s, &again), (200, &first));
    assert!(login(&a, &account, "https://a.example", PW, T0 + 40).is_ok());
}
