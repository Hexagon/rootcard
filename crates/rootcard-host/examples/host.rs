//! A development host on the standard library: HTTP/1.1 on a loopback address, in-memory storage, one realm.
//! Not for production (no TLS, no persistence, no rate limits); it shows how [`rootcard_host::http::route`] is wired.
//!
//! ```text
//! ROOTCARD_HOST_SEED=<64 hex> ROOTCARD_HOST_PORT=8787 cargo run -p rootcard-host --example host
//! ```
//!
//! `ROOTCARD_HOST_URL` sets the base URL (default `http://127.0.0.1:<port>`); it may have a path, such as
//! `http://127.0.0.1:8787/rootcard`, and then the endpoints are at `http://127.0.0.1:8787/rootcard/v0/…`.
//! The host pointer `http://127.0.0.1:8787/.well-known/rootcard` ([HST-23]) names that base URL, so the key tool also
//! accepts the bare origin (`--host http://127.0.0.1:8787`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rootcard::encoding::hex_decode;
use rootcard_host::http::{Request, route, well_known};
use rootcard_host::peer::PeerHeaders;
use rootcard_host::store::{MemoryChallengeStore, MemoryIdentityStore, MemorySessionStore};
use rootcard_host::{Host, HostConfig, RealmConfig, UsernamePolicy};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use zeroize::Zeroizing;

fn main() {
    let port = std::env::var("ROOTCARD_HOST_PORT").unwrap_or_else(|_| "8787".into());
    let url = std::env::var("ROOTCARD_HOST_URL").unwrap_or_else(|_| format!("http://127.0.0.1:{port}"));
    let realm = std::env::var("ROOTCARD_HOST_REALM").unwrap_or_else(|_| "global".into());
    let seed: [u8; 32] = match std::env::var("ROOTCARD_HOST_SEED") {
        Ok(h) => hex_decode(&h).expect("seed hex").try_into().expect("32 bytes"),
        Err(_) => {
            let mut s = [0u8; 32];
            getrandom::fill(&mut s).expect("random");
            s
        }
    };
    let config = HostConfig {
        key_seed: Zeroizing::new(seed),
        retired_keys: Vec::new(),
        urls: vec![url.clone()],
        realms: vec![RealmConfig {
            realm,
            policy: UsernamePolicy::DEFAULT,
        }],
        peers: Vec::new(),
    };
    config
        .check()
        .expect("ROOTCARD_HOST_URL is a base URL without an API version ([HST-22])");
    // The path part of the base URL (`/rootcard` in `http://127.0.0.1:8787/rootcard`): requests arrive with it, and the
    // router expects paths relative to the base URL (`/v0/host`).
    let base_path = url.splitn(4, '/').nth(3).map(|p| format!("/{p}")).unwrap_or_default();
    let origin = url[..url.len() - base_path.len()].to_string();
    let host = Host::new(
        config,
        MemoryIdentityStore::new(),
        MemoryChallengeStore::new(),
        MemorySessionStore::new(),
    );
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).expect("bind");
    eprintln!("rootcard development host at {url}");
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (method, path) = (
            parts.next().unwrap_or("").to_string(),
            parts.next().unwrap_or("/").to_string(),
        );
        let mut length = 0usize;
        // The host pointer ([HST-23]) is at the root of the origin, outside the base URL, so it is routed here.
        let pointer = method == "GET" && path == rootcard::WELL_KNOWN_PATH;
        let path = match path.strip_prefix(base_path.as_str()) {
            Some(rest) if rest.starts_with('/') || rest.starts_with('?') => rest.to_string(),
            _ if base_path.is_empty() => path,
            _ => String::from("/"),
        };
        let mut req = Request {
            method,
            path,
            ..Request::default()
        };
        let mut peer = (None, None, None);
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).is_err() || h.trim().is_empty() {
                break;
            }
            let (k, v) = h
                .split_once(':')
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                .unwrap_or_default();
            match k.as_str() {
                "content-length" => length = v.parse().unwrap_or(0),
                "authorization" => req.bearer = v.strip_prefix("Bearer ").map(str::to_string),
                "rootcard-peer-key" => peer.0 = Some(v),
                "rootcard-peer-time" => peer.1 = v.parse().ok(),
                "rootcard-peer-sig" => peer.2 = Some(v),
                _ => {}
            }
        }
        if let (Some(key), Some(time), Some(sig)) = peer {
            req.peer = Some(PeerHeaders { key, time, sig });
        }
        if length > rootcard_host::http::MAX_BODY {
            let _ =
                stream.write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            continue;
        }
        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_err() {
            continue;
        }
        req.body = body;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let res = if pointer {
            well_known(&host.config, &origin)
        } else {
            route(&host, &req, now, &mut |b| getrandom::fill(b).expect("random"))
        };
        let body = res.body.unwrap_or_default();
        let mut head = format!(
            "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
            res.status,
            body.len()
        );
        if !body.is_empty() {
            head.push_str("Content-Type: application/json\r\n");
        }
        for (k, v) in res.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(&body);
    }
}
