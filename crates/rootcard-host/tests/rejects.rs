//! Reject cases of the host rules, through the HTTP router: every refusal a host must give, with its code and status
//! (HOST_PROTOCOL.md §1.1). The happy paths are in `e2e.rs`; this file proves that each rule is enforced.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;
use common::*;

use rootcard::account::{InstanceMode, new_instance, register, rotate_recovery};
use rootcard::crypto::ed25519_sign;
use rootcard::encoding::base64url_encode;
use rootcard::json::{Map, Value};
use rootcard::log::{Reason, event_hash, pending_instance, retire_event, rotate_recovery_event, verify_log};
use rootcard::messages::{Challenge, change_message};
use rootcard::recovery::derive_recovery_keys;
use rootcard::testing::TestRandom;
use rootcard::vault::{
    Contents, InstanceVault, Kdf, NewSlot, Secret, add_slot, change_password, instance_vault, unlock_vault,
    update_contents, verify_vault,
};
use rootcard_host::SESSION_IDLE;
use zeroize::Zeroizing;

const A: &str = "https://a.example";

/// The lock with id `lock` in a vault's lock list.
fn lock_of(vault: &Value, lock: &str) -> Value {
    get(get(vault, "locks"), "list")
        .as_array()
        .unwrap()
        .iter()
        .find(|l| get(l, "id").as_str() == Some(lock))
        .unwrap()
        .clone()
}

fn challenge(h: &TestHost, account: &str, purpose: &str, now: i64) -> Challenge {
    let (s, v) = call(
        h,
        "POST",
        &format!("/id/{account}/challenge"),
        Some(obj(&[("purpose", purpose.into())])),
        None,
        now,
    );
    assert_eq!(s, 200, "{v:?}");
    Challenge::from_value(&v).unwrap()
}

/// The status and the error code of an answer (an empty code for a success).
fn status_err(r: (u16, Value)) -> (u16, String) {
    let code =
        r.1.as_object()
            .and_then(|m| m.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
    (r.0, code)
}

// ---------------------------------------------------------------------------------------------------------------------
// Registration ([HST-3]): each check, in order.

#[test]
fn registration_rejects() {
    let a = host([0xa1; 32], A);
    let home = home_of(&a, A);
    let mut rng = TestRandom::new(b"rejects-register");
    let rk = rng.bytes::<32>();
    let mut random = |x: &mut [u8]| rng.fill(x);
    let send = |log: &[Value], vault: &Value| {
        let body = obj(&[("log", Value::Array(log.to_vec())), ("vault", vault.clone())]);
        status_err(call(&a, "POST", "/id/register", Some(body), None, T0))
    };

    // A realm the host does not serve → realm_not_accepted (403).
    let other = register(&rk, "other", "Astra", PW, "Laptop", &home, T0, Kdf::MIN, &mut random).unwrap();
    assert_eq!(send(&other.log, &other.vault), (403, "realm_not_accepted".into()));

    // A username the realm's policy refuses (it must begin with a letter) → username_policy.
    let digit = register(&rk, "global", "9lives", PW, "Laptop", &home, T0, Kdf::MIN, &mut random).unwrap();
    assert_eq!(send(&digit.log, &digit.vault), (400, "username_policy".into()));

    // A vault without a password slot → bad_locks: a registration must leave the owner a way to log in.
    let keys = derive_recovery_keys(&rk, "global", "Astra");
    let inc: Value = rootcard::id::inception(&keys, "global", "Astra").unwrap().into();
    let st0 = verify_log(std::slice::from_ref(&inc), &opts()).unwrap();
    let seed = Zeroizing::new(rng.bytes::<32>());
    let pending = pending_instance(&st0, &keys.sign_seed, &seed, &home, Reason::Register, T0).unwrap();
    let instance = base64url_encode(&event_hash(&pending));
    let mut random = |x: &mut [u8]| rng.fill(x);
    let vault = instance_vault(
        InstanceVault {
            account: &st0.account,
            instance: &instance,
            recovery: &keys,
            contents: Contents {
                account_seed: seed,
                data: Map::new(),
                known: None,
            },
            keep: Vec::new(),
            add: None,
        },
        &mut random,
    )
    .unwrap();
    assert_eq!(send(&[inc, pending.into()], &vault), (400, "bad_locks".into()));

    // A vault of another identity → its own code, nothing stored.
    let ok = register(&rk, "global", "Astra", PW, "Laptop", &home, T0, Kdf::MIN, &mut random).unwrap();
    let (s, _) = send(&ok.log, &digit.vault);
    assert_eq!(s, 400);
    assert_eq!(
        call(&a, "GET", &format!("/id/{}/log", ok.account), None, None, T0).0,
        404
    );
    assert_eq!(send(&ok.log, &ok.vault).0, 201);
}

// ---------------------------------------------------------------------------------------------------------------------
// Logs from anyone ([HST-14], [VER-2], [VER-3]) and retries ([HST-20]).

#[test]
fn events_rejects() {
    let a = host([0xa2; 32], A);
    let mut rng = TestRandom::new(b"rejects-events");
    let (reg, rk) = register_at(&a, A, "Astra", &mut rng);
    let account = reg.account.clone();
    let (log, st) = fetch_log(&a, &account);
    let keys = derive_recovery_keys(&rk, "global", "Astra");
    let events = |evs: Vec<Value>, now: i64| {
        status_err(call(
            &a,
            "POST",
            &format!("/id/{account}/events"),
            Some(obj(&[("events", Value::Array(evs))])),
            None,
            now,
        ))
    };

    // A vault sent with the stored log (a retry without a rotation) needs a session or a new grant → unauthorized.
    let u = unlock_vault(&reg.vault, &st, &Secret::Recovery(&keys)).unwrap();
    let mut c = u.contents.clone();
    c.data = Map::new().with("user.motto", "no session");
    let mut random = |x: &mut [u8]| rng.fill(x);
    let data = update_contents(&u, &reg.vault, &c, &mut random).unwrap();
    let (s, v) = call(
        &a,
        "POST",
        &format!("/id/{account}/events"),
        Some(obj(&[("events", Value::Array(log.clone())), ("vault", data)])),
        None,
        T0,
    );
    assert_eq!((s, err(&v)), (401, "unauthorized"));

    // An older log (a prefix of the stored one) → stale_version with the host's version.
    let (s, v) = call(
        &a,
        "POST",
        &format!("/id/{account}/events"),
        Some(obj(&[("events", Value::Array(log[..1].to_vec()))])),
        None,
        T0,
    );
    assert_eq!((s, err(&v)), (409, "stale_version"));
    assert_eq!(get(&v, "version"), &st.version.to_value());

    // Events after a gap (the host lacks the event before them) → stale_version.
    let new_rk = rng.bytes::<32>();
    let new_keys = derive_recovery_keys(&new_rk, "global", "Astra");
    let rot: Value = rotate_recovery_event(&st, &keys.sign_seed, &new_keys.sign_seed, T0 + 10)
        .unwrap()
        .into();
    let st2 = rootcard::log::extend_log(&st, std::slice::from_ref(&rot), &opts()).unwrap();
    let retire: Value = retire_event(&st2, &new_keys.sign_seed, T0 + 20).unwrap().into();
    assert_eq!(events(vec![retire.clone()], T0 + 30), (409, "stale_version".into()));

    // A valid diverging log (the recovery key signs another event at seq 1) → fork, with the host's version.
    let st0 = verify_log(&log[..1], &opts()).unwrap();
    let fork: Value = retire_event(&st0, &keys.sign_seed, T0 + 10).unwrap().into();
    assert_eq!(events(vec![fork.clone()], T0 + 30), (409, "fork".into()));
    // The same divergence with a broken signature is garbage, not a fork: it is verified first.
    let mut garbage = fork.as_object().unwrap().clone();
    garbage.insert("time", Value::Int(T0 + 11));
    assert_eq!(events(vec![garbage.into()], T0 + 30), (400, "bad_signature".into()));
    // An event whose `prev` is not in the stored log (here: another identity's) cannot be verified without the events
    // before it, which the host does not have → stale_version with the host's version, so that the sender fetches the
    // log and compares. Nothing is stored.
    let mut other = TestRandom::new(b"rejects-events-other");
    let other_keys = derive_recovery_keys(&other.bytes::<32>(), "global", "Astra");
    let foreign: Value = retire_event(
        &verify_log(
            &[rootcard::id::inception(&other_keys, "global", "Astra").unwrap().into()],
            &opts(),
        )
        .unwrap(),
        &other_keys.sign_seed,
        T0,
    )
    .unwrap()
    .into();
    assert_eq!(events(vec![foreign], T0 + 30), (409, "stale_version".into()));

    // A new event is adopted; sending exactly the same again is a retry with the same answer ([HST-20]).
    let first = call(
        &a,
        "POST",
        &format!("/id/{account}/events"),
        Some(obj(&[("events", Value::Array(vec![rot.clone()]))])),
        None,
        T0 + 30,
    );
    assert_eq!(first.0, 200, "{:?}", first.1);
    let again = call(
        &a,
        "POST",
        &format!("/id/{account}/events"),
        Some(obj(&[("events", Value::Array(vec![rot]))])),
        None,
        T0 + 31,
    );
    assert_eq!(again, first);
    // An event more than 600 s in the future is refused ([HST-6], T24).
    let late = retire_event(&st2, &new_keys.sign_seed, T0 + 31 + 601).unwrap();
    let (s, _) = events(vec![late.into()], T0 + 31);
    assert_eq!(s, 400);
}

#[test]
fn instance_rejects_and_retries() {
    let a = host([0xa3; 32], A);
    let mut rng = TestRandom::new(b"rejects-instance");
    let (reg, rk) = register_at(&a, A, "Astra", &mut rng);
    let account = reg.account.clone();
    let (log, st) = fetch_log(&a, &account);
    let keys = derive_recovery_keys(&rk, "global", "Astra");
    let u = unlock_vault(&reg.vault, &st, &Secret::Recovery(&keys)).unwrap();
    let home = home_of(&a, A);
    let mut random = |x: &mut [u8]| rng.fill(x);
    let ni = new_instance(
        &st,
        &keys,
        Some(&u),
        None,
        InstanceMode::Restore,
        &home,
        T0 + 10,
        &mut random,
    )
    .unwrap();
    let body = |events: &[Value], ni: &rootcard::account::NewInstance| {
        obj(&[
            ("events", Value::Array(events.to_vec())),
            ("instance", Value::Object(ni.event.clone())),
            ("vault", ni.vault.clone()),
            ("public", ni.public.clone()),
        ])
    };
    let path = format!("/id/{account}/instance");

    // A pending instance after events the host does not have, without them → stale_version.
    let new_rk = rng.bytes::<32>();
    let mut random = |x: &mut [u8]| rng.fill(x);
    let rot = rotate_recovery(&st, &log, &keys, &new_rk, &reg.vault, &u, T0 + 5, &mut random).unwrap();
    let rot_event: Value = rot.event.clone().into();
    let st_rot = rootcard::log::extend_log(&st, std::slice::from_ref(&rot_event), &opts()).unwrap();
    let new_keys = derive_recovery_keys(&new_rk, "global", "Astra");
    let u_rot = unlock_vault(&rot.vault, &st_rot, &Secret::Recovery(&new_keys)).unwrap();
    let ahead = new_instance(
        &st_rot,
        &new_keys,
        Some(&u_rot),
        None,
        InstanceMode::Restore,
        &home,
        T0 + 10,
        &mut random,
    )
    .unwrap();
    let (s, v) = call(&a, "POST", &path, Some(body(&[], &ahead)), None, T0 + 10);
    assert_eq!((s, err(&v)), (409, "stale_version"));

    // The instance is receipted; the same request again is a retry with the same receipt ([HST-20]).
    let first = call(&a, "POST", &path, Some(body(&log, &ni)), None, T0 + 10);
    assert_eq!(first.0, 201, "{:?}", first.1);
    let again = call(&a, "POST", &path, Some(body(&log, &ni)), None, T0 + 20);
    assert_eq!(again, first);

    // Another pending instance on the same previous version is a valid diverging log → fork.
    let mut random = |x: &mut [u8]| rng.fill(x);
    let other = new_instance(
        &st,
        &keys,
        Some(&u),
        None,
        InstanceMode::Restore,
        &home,
        T0 + 30,
        &mut random,
    )
    .unwrap();
    let (s, v) = call(&a, "POST", &path, Some(body(&log, &other)), None, T0 + 30);
    assert_eq!((s, err(&v)), (409, "fork"));

    // A pending instance outside the receipt window → bad_time ([HST-6]). The current vault is the restore's.
    let (_, st3) = fetch_log(&a, &account);
    let u3 = unlock_vault(&ni.vault, &st3, &Secret::Recovery(&keys)).unwrap();
    let mut random = |x: &mut [u8]| rng.fill(x);
    let late = new_instance(
        &st3,
        &keys,
        Some(&u3),
        None,
        InstanceMode::Restore,
        &home,
        T0 + 50,
        &mut random,
    )
    .unwrap();
    let (s, v) = call(&a, "POST", &path, Some(body(&[], &late)), None, T0 + 50 + 601);
    assert_eq!((s, err(&v)), (400, "bad_time"));
}

// ---------------------------------------------------------------------------------------------------------------------
// Sessions ([HST-11]), vault replacement ([HST-12]) and password changes ([CHG-2]).

#[test]
fn session_and_vault_rejects() {
    let a = host([0xa4; 32], A);
    let mut rng = TestRandom::new(b"rejects-session");
    let (reg, rk) = register_at(&a, A, "Astra", &mut rng);
    let keys = derive_recovery_keys(&rk, "global", "Astra");
    let account = reg.account.clone();
    let (_, st) = fetch_log(&a, &account);
    let slot = verify_vault(&reg.vault, &st).unwrap().slots[0].id.clone();
    let up = unlock_vault(
        &reg.vault,
        &st,
        &Secret::Password {
            lock: &slot,
            password: PW,
        },
    )
    .unwrap();

    // No session, or a token that is not one → unauthorized.
    assert_eq!(
        status_err(call(&a, "GET", "/session/vault", None, None, T0)),
        (401, "unauthorized".into())
    );
    let fake = base64url_encode(&[7u8; 32]);
    assert_eq!(
        status_err(call(&a, "GET", "/session/vault", None, Some(&fake), T0)),
        (401, "unauthorized".into())
    );

    let token = login(&a, &account, A, PW, T0).unwrap();
    let put_session = |vault: &Value, now: i64| {
        status_err(call(
            &a,
            "PUT",
            "/session/vault",
            Some(obj(&[("vault", vault.clone())])),
            Some(&token),
            now,
        ))
    };

    // [HST-12] case 1: a session may replace the data, not the locks. A password change sent as a plain vault
    // replacement (without the old password's proof) → unauthorized.
    let mut random = |x: &mut [u8]| rng.fill(x);
    let (changed, new_hash) = change_password(&up, &reg.vault, &slot, PW2, "Astra", &Kdf::MIN, &mut random).unwrap();
    assert_eq!(put_session(&changed, T0 + 10), (401, "unauthorized".into()));
    // Without a session, even a data update is refused (case 3 needs a new grant).
    let mut c = up.contents.clone();
    c.data = Map::new().with("user.motto", "hello");
    let data = update_contents(&up, &reg.vault, &c, &mut random).unwrap();
    assert_eq!(
        status_err(call(
            &a,
            "PUT",
            &format!("/id/{account}/vault"),
            Some(obj(&[("vault", data.clone())])),
            None,
            T0 + 10
        )),
        (401, "unauthorized".into())
    );

    // [CHG-2] a password change: each check in order.
    let change = |vault: &Value, lock: &str, proof: &[u8], ch: &Challenge, url: &str, bearer: Option<&str>| {
        let body = obj(&[
            ("lock", lock.into()),
            ("nonce", base64url_encode(&ch.nonce).into()),
            ("url", url.into()),
            ("proof", base64url_encode(proof).into()),
            ("vault", vault.clone()),
        ]);
        status_err(call(&a, "POST", "/session/password", Some(body), bearer, T0 + 20))
    };
    let ch = challenge(&a, &account, "change", T0 + 20);
    let good = ed25519_sign(
        &up.lock_seed,
        &change_message(&account, &ch.host, &slot, &new_hash, &ch.nonce, A),
    );
    // A stolen session without the password cannot change it.
    assert_eq!(
        change(&changed, &slot, &good, &ch, A, None),
        (401, "unauthorized".into())
    );
    let thief = ed25519_sign(
        &[9u8; 32],
        &change_message(&account, &ch.host, &slot, &new_hash, &ch.nonce, A),
    );
    assert_eq!(
        change(&changed, &slot, &thief, &ch, A, Some(&token)),
        (400, "bad_signature".into())
    );
    // Each failed attempt used the nonce up; the rest take a fresh challenge each.
    let ch = challenge(&a, &account, "change", T0 + 20);
    let sign = |ch: &Challenge, url: &str| {
        ed25519_sign(
            &up.lock_seed,
            &change_message(&account, &ch.host, &slot, &new_hash, &ch.nonce, url),
        )
    };
    assert_eq!(
        change(
            &changed,
            &slot,
            &sign(&ch, "https://evil.example"),
            &ch,
            "https://evil.example",
            Some(&token)
        ),
        (400, "wrong_host".into())
    );
    let ch = challenge(&a, &account, "change", T0 + 20);
    assert_eq!(
        change(&changed, "AAAAAAAAAAA", &sign(&ch, A), &ch, A, Some(&token)),
        (400, "bad_locks".into())
    );
    let ch = challenge(&a, &account, "login", T0 + 20);
    assert_eq!(
        change(&changed, &slot, &sign(&ch, A), &ch, A, Some(&token)),
        (401, "challenge_unknown".into())
    );
    // A valid proof for the slot, but the vault also changes the grant (a slot added) → stale_locks. (A data change
    // cannot be told apart: the contents are encrypted, and `ct` changes with every replacement.)
    let mut random = |x: &mut [u8]| rng.fill(x);
    let u_rec = unlock_vault(&reg.vault, &st, &Secret::Recovery(&keys)).unwrap();
    let granted = add_slot(
        &u_rec,
        &reg.vault,
        &keys,
        &NewSlot {
            label: "Phone",
            password: "phone passphrase 123",
            username: "Astra",
            kdf: Kdf::MIN,
        },
        &mut random,
    )
    .unwrap();
    let old_hash = rootcard::crypto::sha256(&rootcard::json::canonical(&lock_of(&reg.vault, &slot)));
    let ch = challenge(&a, &account, "change", T0 + 20);
    let proof = ed25519_sign(
        &up.lock_seed,
        &change_message(&account, &ch.host, &slot, &old_hash, &ch.nonce, A),
    );
    assert_eq!(
        change(&granted, &slot, &proof, &ch, A, Some(&token)),
        (409, "stale_locks".into())
    );
    // The honest change succeeds.
    let ch = challenge(&a, &account, "change", T0 + 20);
    let (s, _) = change(&changed, &slot, &sign(&ch, A), &ch, A, Some(&token));
    assert_eq!(s, 200);

    // [HST-11] a session ends after 24 h without use, and never becomes valid again.
    let token = login(&a, &account, A, PW2, T0 + 100).unwrap();
    assert_eq!(
        call(&a, "GET", "/session/vault", None, Some(&token), T0 + 100 + SESSION_IDLE).0,
        200
    );
    let idle = T0 + 100 + 2 * SESSION_IDLE + 1;
    assert_eq!(
        status_err(call(&a, "GET", "/session/vault", None, Some(&token), idle)),
        (401, "unauthorized".into())
    );
    assert_eq!(call(&a, "GET", "/session/vault", None, Some(&token), idle + 1).0, 401);
    // Logout ends a session at once.
    let token = login(&a, &account, A, PW2, idle).unwrap();
    assert_eq!(call(&a, "POST", "/session/logout", None, Some(&token), idle).0 / 100, 2);
    assert_eq!(call(&a, "GET", "/session/vault", None, Some(&token), idle).0, 401);
}
