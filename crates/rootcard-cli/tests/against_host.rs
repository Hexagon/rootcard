//! The key tool end to end against a host: `new --host`, `rotate-recovery` and `restore`, each checked against what
//! the host then stores. The host is `rootcard_host::http::route` behind a minimal HTTP/1.1 server on a loopback port
//! in the test process (the same wiring as the crate's development host example).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use rootcard::json::{Value, parse_json};
use rootcard_host::http::{API_VERSION, MAX_BODY, Request, route, well_known};
use rootcard_host::store::{MemoryChallengeStore, MemoryIdentityStore, MemorySessionStore};
use rootcard_host::{Host, HostConfig, RealmConfig, UsernamePolicy};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery staple";

type TestHost = Host<MemoryIdentityStore, MemoryChallengeStore, MemorySessionStore>;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Start a host on a free loopback port, at the base URL `<origin>/rootcard`, with the host pointer ([HST-23]) at
/// `<origin>/.well-known/rootcard`. Returns it (for direct reads), the origin and the base URL. The server thread ends
/// with the test process.
fn start_host() -> (Arc<TestHost>, String, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let url = format!("{origin}/rootcard");
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let config = HostConfig {
        key_seed: Zeroizing::new(seed),
        retired_keys: Vec::new(),
        urls: vec![url.clone()],
        realms: vec![RealmConfig {
            realm: "global".into(),
            policy: UsernamePolicy::DEFAULT,
        }],
        peers: Vec::new(),
    };
    config.check().unwrap();
    let host = Arc::new(Host::new(
        config,
        MemoryIdentityStore::new(),
        MemoryChallengeStore::new(),
        MemorySessionStore::new(),
    ));
    let served = Arc::clone(&host);
    let served_origin = origin.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let full = parts.next().unwrap_or("/").to_string();
            let pointer = method == "GET" && full == rootcard::WELL_KNOWN_PATH;
            let mut req = Request {
                method,
                path: full.strip_prefix("/rootcard").unwrap_or("/").to_string(),
                ..Request::default()
            };
            let mut length = 0usize;
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).is_err() || h.trim().is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    match k.trim().to_ascii_lowercase().as_str() {
                        "content-length" => length = v.trim().parse().unwrap_or(0),
                        "authorization" => req.bearer = v.trim().strip_prefix("Bearer ").map(str::to_string),
                        _ => {}
                    }
                }
            }
            let mut body = vec![0u8; length.min(MAX_BODY)];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            req.body = body;
            let res = if pointer {
                well_known(&served.config, &served_origin)
            } else {
                route(&*served, &req, now(), &mut |b| getrandom::fill(b).unwrap())
            };
            let body = res.body.unwrap_or_default();
            let mut head = format!(
                "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n",
                res.status,
                body.len()
            );
            for (k, v) in res.headers {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    (host, origin, url)
}

/// A GET through the router, as a client would see it.
fn get(host: &TestHost, path: &str) -> (u16, Value) {
    let req = Request {
        method: "GET".into(),
        path: format!("/{API_VERSION}{path}"),
        ..Request::default()
    };
    let res = route(host, &req, now(), &mut |b| getrandom::fill(b).unwrap());
    (res.status, parse_json(&res.body.unwrap_or_default()).unwrap())
}

/// The `home.url` of every instance the host stores for `account`.
fn home_urls(host: &TestHost, account: &str) -> Vec<String> {
    let (_, v) = get(host, &format!("/id/{account}/log"));
    field(&v, "events")
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| {
            let home = field(e, "body").as_object()?.get("home")?.as_object()?.get("url")?;
            Some(home.as_str()?.to_string())
        })
        .collect()
}

/// The kinds of the events the host stores for `account`, and the instance reasons.
fn stored_kinds(host: &TestHost, account: &str) -> Vec<String> {
    let (s, v) = get(host, &format!("/id/{account}/log"));
    assert_eq!(s, 200, "{v:?}");
    field(&v, "events")
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let kind = field(e, "kind").as_str().unwrap().to_string();
            match field(e, "body")
                .as_object()
                .and_then(|b| b.get("reason"))
                .and_then(Value::as_str)
            {
                Some(r) => format!("{kind}:{r}"),
                None => kind,
            }
        })
        .collect()
}

fn rootcard(args: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_rootcard"))
        .args(args)
        .env("ROOTCARD_PASSWORD", PASSWORD)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "rootcard {args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rootcard-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The one file in `dir` whose name ends with `suffix`.
fn one(dir: &Path, suffix: &str) -> PathBuf {
    let found: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(suffix))
        .collect();
    assert_eq!(found.len(), 1, "{found:?}");
    found[0].clone()
}

fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.as_object()
        .unwrap()
        .get(k)
        .unwrap_or_else(|| panic!("no {k} in {v:?}"))
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn new_rotate_and_restore_against_a_host() {
    let (host, origin, url) = start_host();
    let dir = scratch("e2e");

    // `new --host`: registration at the host ([CLT-1], [HST-3]); the card and the account file are written. The bare
    // origin is resolved through the host pointer ([HST-23]), and the instance records the base URL it names.
    rootcard(&[
        "new",
        "--realm",
        "global",
        "--username",
        "Astra",
        "--host",
        &origin,
        "--dir",
        s(&dir),
    ]);
    let card = one(&dir, ".card.json");
    let file = one(&dir, ".rootcard.json");
    let file_json = parse_json(&std::fs::read(&file).unwrap()).unwrap();
    let account = field(&file_json, "account").as_str().unwrap().to_string();
    assert_eq!(stored_kinds(&host, &account), ["incept", "instance:register"]);
    assert_eq!(home_urls(&host, &account), [url.as_str()]);
    assert_eq!(get(&host, &format!("/id/{account}/locks")).0, 200);

    // `rotate-recovery` ([KT-5]): the host adopts the rotation together with the new vault, so the identity still
    // has working locks, and only the new card proves.
    let rotated = dir.join("rotated");
    std::fs::create_dir_all(&rotated).unwrap();
    rootcard(&[
        "rotate-recovery",
        "--card",
        s(&card),
        "--from",
        &origin,
        "--dir",
        s(&rotated),
    ]);
    let new_card = one(&rotated, ".card.json");
    assert_eq!(
        stored_kinds(&host, &account),
        ["incept", "instance:register", "rotate_recovery"]
    );
    let (status, locks) = get(&host, &format!("/id/{account}/locks"));
    assert_eq!(status, 200, "the stored vault verifies after the rotation: {locks:?}");
    let prove = |card: &Path| {
        Command::new(env!("CARGO_BIN_EXE_rootcard"))
            .args([
                "prove",
                "--card",
                s(card),
                "--from",
                &url,
                "--statement",
                "\"check\"",
                "--recipient",
                "check",
            ])
            .output()
            .unwrap()
    };
    assert!(prove(&new_card).status.success());
    let old = prove(&card);
    assert!(!old.status.success());
    assert!(String::from_utf8_lossy(&old.stderr).contains("wrong_recovery_key"));

    // `restore` ([KT-3]): a new instance at the same host with the new card; the password slot is carried over.
    rootcard(&["restore", "--card", s(&new_card), "--host", &url]);
    assert_eq!(
        stored_kinds(&host, &account),
        ["incept", "instance:register", "rotate_recovery", "instance:restore"]
    );
    let (status, locks) = get(&host, &format!("/id/{account}/locks"));
    assert_eq!(status, 200, "{locks:?}");
    assert_eq!(field(&locks, "locks").as_array().unwrap().len(), 1);
    assert_eq!(home_urls(&host, &account), [url.as_str(), url.as_str()]);
}
