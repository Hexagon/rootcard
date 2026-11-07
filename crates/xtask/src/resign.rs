//! The log re-signer: makes a mutated log consistent enough to reach the checks behind the signatures. Used by the
//! `log_signed` fuzz target (fuzz/README.md, which includes this file by path) and by the differential test of the JS
//! core against the Rust core (`cargo run -p xtask -- differential`).

use rootcard::crypto::{ed25519_public, ed25519_sign, sha256};
use rootcard::encoding::base64url_encode;
use rootcard::id::account_id;
use rootcard::json::{Map, Value};
use rootcard::keys::{KeyType, format_key, parse_key};
use rootcard::log::{event_hash, event_message, receipt_message};

/// Bit 0 of the control byte: recompute `account` from the inception.
pub const FIX_ACCOUNT: u8 = 1;
/// Bit 1: recompute `prev` from the event before.
pub const FIX_PREV: u8 = 2;
/// Bit 2: recompute every signature.
pub const FIX_SIGS: u8 = 4;

/// The fixed seeds keys are mapped to. Eight are enough to express reuse and distinctness.
fn pool_seed(i: usize) -> [u8; 32] {
    let mut s = sha256(format!("rootcard fuzz key {i}").as_bytes());
    // Keep the seeds usable in every implementation ([CRY-9]); the fuzzer is not after WebKit's zero bytes here.
    s[0] |= 1;
    s[31] |= 1;
    s
}

/// A key mapper: every distinct Ed25519 key in the input maps to the same pool key every time, so equal keys stay equal
/// (key reuse, signer order) and different keys stay different while the pool lasts.
struct Keys {
    seen: Vec<String>,
    seeds: Vec<[u8; 32]>,
}

impl Keys {
    fn new() -> Self {
        Keys {
            seen: Vec::new(),
            seeds: (0..8).map(pool_seed).collect(),
        }
    }

    /// The pool index of `key`, or `None` for a string that is not an Ed25519 key.
    fn index(&mut self, key: &str) -> Option<usize> {
        parse_key(key, KeyType::Ed25519).ok()?;
        let i = match self.seen.iter().position(|k| k == key) {
            Some(i) => i,
            None => {
                self.seen.push(key.to_string());
                self.seen.len() - 1
            }
        };
        Some(i % self.seeds.len())
    }

    fn public(&self, i: usize) -> String {
        format_key(KeyType::Ed25519, &ed25519_public(&self.seeds[i]))
    }

    fn map(&mut self, v: &Value) -> Value {
        match v {
            Value::String(s) => match self.index(s) {
                Some(i) => Value::String(self.public(i)),
                None => v.clone(),
            },
            Value::Array(a) => Value::Array(a.iter().map(|x| self.map(x)).collect()),
            Value::Object(m) => {
                let mut out = Map::new();
                for (k, x) in m.iter() {
                    out.insert(k, self.map(x));
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }
}

/// Make a fuzzed log consistent enough to reach the checks after the signatures: every key inside `body` and every
/// signer is mapped to a pool key, and then, as `control` asks, `account` and `prev` are recomputed and every signature
/// is made again with the pool seed of its signer (a receipt when the signer is the event's `home.key`, an owner
/// signature otherwise, in the fuzzed order). Members the fuzzer removed stay removed, and non-objects stay as they
/// are, so the schema checks are still reached.
pub fn resign(events: &[Value], control: u8) -> Vec<Value> {
    let mut keys = Keys::new();
    let mut out: Vec<Value> = Vec::with_capacity(events.len());
    let mut account: Option<String> = None;
    for (i, e) in events.iter().enumerate() {
        let Some(m) = e.as_object() else {
            out.push(e.clone());
            continue;
        };
        let mut m = m.clone();
        if let Some(body) = m.get("body") {
            let body = keys.map(body);
            m.insert("body", body);
        }
        if control & FIX_ACCOUNT != 0
            && i > 0
            && m.get("account").is_some()
            && let Some(a) = &account
        {
            m.insert("account", Value::String(a.clone()));
        }
        if control & FIX_PREV != 0
            && m.get("prev").is_some()
            && let Some(prev) = out.last().and_then(Value::as_object)
        {
            m.insert("prev", Value::String(base64url_encode(&event_hash(prev))));
        }
        if let Some(Value::Array(sigs)) = m.get("sigs").cloned() {
            let home = m
                .get("body")
                .and_then(Value::as_object)
                .and_then(|b| b.get("home"))
                .and_then(Value::as_object)
                .and_then(|h| h.get("key"))
                .and_then(Value::as_str)
                .map(str::to_string);
            m.insert("sigs", Value::Array(Vec::new()));
            let mut made = Vec::with_capacity(sigs.len());
            for s in &sigs {
                let Some(sm) = s.as_object() else {
                    made.push(s.clone());
                    continue;
                };
                let mut sm = sm.clone();
                let signer = sm.get("key").and_then(Value::as_str).and_then(|k| keys.index(k));
                if let Some(j) = signer {
                    let public = keys.public(j);
                    sm.insert("key", Value::String(public.clone()));
                    if control & FIX_SIGS != 0 && sm.get("sig").is_some() {
                        let message = if home.as_deref() == Some(public.as_str()) {
                            receipt_message(&m)
                        } else {
                            event_message(&m)
                        };
                        let sig = ed25519_sign(&keys.seeds[j], &message);
                        sm.insert("sig", Value::String(base64url_encode(&sig)));
                    }
                }
                made.push(Value::Object(sm));
            }
            m.insert("sigs", Value::Array(made));
        }
        if i == 0 {
            account = Some(account_id(&m));
        }
        out.push(Value::Object(m));
    }
    out
}
