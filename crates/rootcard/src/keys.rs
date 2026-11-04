//! Keys and signatures in JSON (SPEC §3.3), and the schema helpers every structure uses ([CJ-11]–[CJ-13]).

use crate::crypto::ed25519_point_ok;
use crate::encoding::{base64url_decode, base64url_encode};
use crate::error::{Error, Result};
use crate::json::{Map, Value};

/// A key type tag ([KEY-1]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// `ed25519`
    Ed25519,
    /// `x25519`
    X25519,
}

impl KeyType {
    /// The type tag.
    pub fn tag(self) -> &'static str {
        match self {
            KeyType::Ed25519 => "ed25519",
            KeyType::X25519 => "x25519",
        }
    }
}

/// `"<type>:" + b64u(raw)` ([KEY-1]).
pub fn format_key(t: KeyType, raw: &[u8; 32]) -> String {
    format!("{}:{}", t.tag(), base64url_encode(raw))
}

/// Parse a key string of the required type ([KEY-1]–[KEY-3]). → `bad_key`
pub fn parse_key(s: &str, t: KeyType) -> Result<[u8; 32]> {
    let (tag, payload) = s.split_once(':').ok_or(Error::BadKey)?;
    if tag != t.tag() {
        return Err(Error::BadKey);
    }
    let raw: [u8; 32] = base64url_decode(payload)
        .map_err(|_| Error::BadKey)?
        .try_into()
        .map_err(|_| Error::BadKey)?;
    if t == KeyType::Ed25519 && !ed25519_point_ok(&raw) {
        return Err(Error::BadKey);
    }
    Ok(raw)
}

/// Schema helpers over a parsed object. Every failure is `bad_field` unless stated otherwise.
pub(crate) mod schema {
    use super::*;

    pub fn obj(v: &Value) -> Result<&Map> {
        v.as_object().ok_or(Error::BadField)
    }

    /// [CJ-12]: `v` is present and an integer (`bad_field`), and `1` (`unsupported_version`).
    pub fn version(m: &Map) -> Result<()> {
        match m.get("v") {
            Some(Value::Int(1)) => Ok(()),
            Some(Value::Int(_)) => Err(Error::UnsupportedVersion),
            _ => Err(Error::BadField),
        }
    }

    /// Exactly the required members and possibly some of the optional ones ([CJ-11]).
    pub fn members(m: &Map, required: &[&str], optional: &[&str]) -> Result<()> {
        if required.iter().any(|k| m.get(k).is_none()) {
            return Err(Error::BadField);
        }
        if m.keys().any(|k| !required.contains(&k) && !optional.contains(&k)) {
            return Err(Error::BadField);
        }
        Ok(())
    }

    pub fn get<'a>(m: &'a Map, k: &str) -> Result<&'a Value> {
        m.get(k).ok_or(Error::BadField)
    }

    pub fn string<'a>(m: &'a Map, k: &str) -> Result<&'a str> {
        get(m, k)?.as_str().ok_or(Error::BadField)
    }

    pub fn int(m: &Map, k: &str) -> Result<i64> {
        get(m, k)?.as_int().ok_or(Error::BadField)
    }

    /// An integer in `lo ..= hi`.
    pub fn int_in(m: &Map, k: &str, lo: i64, hi: i64) -> Result<i64> {
        let i = int(m, k)?;
        if (lo..=hi).contains(&i) {
            Ok(i)
        } else {
            Err(Error::BadField)
        }
    }

    pub fn object<'a>(m: &'a Map, k: &str) -> Result<&'a Map> {
        get(m, k)?.as_object().ok_or(Error::BadField)
    }

    pub fn array<'a>(m: &'a Map, k: &str) -> Result<&'a Vec<Value>> {
        get(m, k)?.as_array().ok_or(Error::BadField)
    }

    /// A base64url string of exactly `N` bytes ([B64-3], [CJ-13]).
    pub fn bytes<const N: usize>(m: &Map, k: &str) -> Result<[u8; N]> {
        let v = base64url_decode(string(m, k)?).map_err(|_| Error::BadField)?;
        v.try_into().map_err(|_| Error::BadField)
    }

    /// A key string: a member that is not a string is `bad_field`, a bad key is `bad_key` ([CJ-13]).
    pub fn key(m: &Map, k: &str, t: KeyType) -> Result<[u8; 32]> {
        parse_key(string(m, k)?, t)
    }

    /// A 64-byte signature ([KEY-4]).
    pub fn sig(m: &Map, k: &str) -> Result<[u8; 64]> {
        bytes::<64>(m, k)
    }

    /// An account id in strict form ([ID-3]).
    pub fn account(m: &Map, k: &str) -> Result<String> {
        let s = string(m, k)?;
        crate::id::check_account_id(s)?;
        Ok(s.to_string())
    }

    /// A version `{ seq, hash }` ([VER-1]).
    pub fn version_ref(v: &Value) -> Result<crate::log::Version> {
        let m = obj(v)?;
        members(m, &["seq", "hash"], &[])?;
        Ok(crate::log::Version {
            seq: int_in(m, "seq", 0, crate::log::MAX_EVENTS as i64 - 1)? as u32,
            hash: bytes::<32>(m, "hash")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let raw = crate::crypto::ed25519_public(&[7; 32]);
        let s = format_key(KeyType::Ed25519, &raw);
        assert_eq!(parse_key(&s, KeyType::Ed25519), Ok(raw));
        assert_eq!(parse_key(&s, KeyType::X25519), Err(Error::BadKey));
        assert_eq!(parse_key("ed25519:AA", KeyType::Ed25519), Err(Error::BadKey));
        assert_eq!(
            parse_key(&format_key(KeyType::Ed25519, &[0; 32]), KeyType::Ed25519),
            Err(Error::BadKey)
        );
        assert_eq!(parse_key("rsa:AAAA", KeyType::Ed25519), Err(Error::BadKey));
    }
}
