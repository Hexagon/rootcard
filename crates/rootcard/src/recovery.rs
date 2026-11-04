//! The recovery key (SPEC §6): written form, parsing and the derived key pairs.

use crate::crypto::{ed25519_public, frame, frame_map, hkdf, sha256};
use crate::encoding::{B32, base32_decode, base32_encode, base32_normalize};
use crate::error::{Error, Result};
use crate::json::Map;
use crate::label;
use zeroize::Zeroizing;

fn checksum(key: &[u8; 32]) -> String {
    let h = sha256(&frame(&label("recovery/check", 1), key));
    base32_encode(&h)[..4].to_string()
}

/// The written form `RCR-XXXX-…-CCCC` ([RK-1]).
pub fn format_recovery_key(key: &[u8; 32]) -> String {
    let mut body = base32_encode(key);
    body.push_str(&checksum(key));
    let groups: Vec<&str> = (0..14).map(|i| &body[i * 4..i * 4 + 4]).collect();
    format!("RCR-{}", groups.join("-"))
}

/// Parse a typed recovery key ([RK-2]). → `bad_base32`, `bad_checksum`
pub fn parse_recovery_key(text: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut s: Zeroizing<String> = Zeroizing::new(text.chars().filter(|c| *c != '-' && *c != ' ').collect());
    if s.chars().count() == 59 && s.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("RCR")) {
        s = Zeroizing::new(s[3..].to_string());
    }
    if s.len() != 56 || !s.is_ascii() {
        return Err(Error::BadBase32);
    }
    let n = Zeroizing::new(base32_normalize(&s));
    if !n.bytes().all(|c| B32.contains(&c)) {
        return Err(Error::BadBase32);
    }
    let raw = Zeroizing::new(base32_decode(&n[..52], 32)?);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&raw);
    if n[52..] != checksum(&key) {
        return Err(Error::BadChecksum);
    }
    Ok(key)
}

/// The two key pairs of an identity derived from its recovery key ([RK-4]).
pub struct RecoveryKeys {
    /// The Ed25519 seed of the recovery signing key.
    pub sign_seed: Zeroizing<[u8; 32]>,
    /// The X25519 secret of the recovery lock key.
    pub box_secret: Zeroizing<[u8; 32]>,
}

impl RecoveryKeys {
    /// The public recovery signing key.
    pub fn sign_public(&self) -> [u8; 32] {
        ed25519_public(&self.sign_seed)
    }

    /// The public recovery lock key.
    #[cfg(feature = "vault")]
    pub fn box_public(&self) -> [u8; 32] {
        crate::crypto::x25519_public(&self.box_secret)
    }
}

/// Derive an identity's recovery keys from the recovery key, its realm and its username ([RK-4]).
pub fn derive_recovery_keys(rk: &[u8; 32], realm: &str, username: &str) -> RecoveryKeys {
    let ctx = Map::new().with("realm", realm).with("username", username);
    RecoveryKeys {
        sign_seed: hkdf(rk, &[], &frame_map(&label("recovery/sign", 1), &ctx)),
        box_secret: hkdf(rk, &[], &frame_map(&label("recovery/box", 1), &ctx)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_rejects() {
        let k = [0x5au8; 32];
        let w = format_recovery_key(&k);
        assert_eq!(w.len(), 73);
        assert_eq!(*parse_recovery_key(&w).unwrap(), k);
        assert_eq!(*parse_recovery_key(&w.to_lowercase().replace('-', " ")).unwrap(), k);
        assert_eq!(*parse_recovery_key(&w[4..]).unwrap(), k);
        let mut bad = w.clone();
        bad.replace_range(72..73, if &w[72..] == "0" { "1" } else { "0" });
        assert_eq!(parse_recovery_key(&bad).map(|_| ()), Err(Error::BadChecksum));
        assert_eq!(parse_recovery_key("RCR-0000").map(|_| ()), Err(Error::BadBase32));
        let mut u = w.clone();
        u.replace_range(4..5, "U");
        assert_eq!(parse_recovery_key(&u).map(|_| ()), Err(Error::BadBase32));
    }
}
