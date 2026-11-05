//! # rootcard
//!
//! A portable, self-certifying identity for online logins. This crate is the core: formats, verification, the vault and
//! proofs. It is pure: it does no I/O, reads no clock and draws no randomness itself. Time and random bytes are passed in
//! ([IMP-1]).
//!
//! The normative format is `spec/SPEC.md` in the repository, and `spec/vectors/` holds the shared test vectors that this
//! crate and the npm package must both reproduce. Rule identifiers such as `[LOG-12]` refer to that specification.
//!
//! The `vault` feature (on by default) adds password and vault cryptography: X25519, AES-256-GCM, Argon2id and Unicode
//! normalization. Hosts and relying parties build without it (`default-features = false`).
//!
//! Status: `0.x`. Nothing here is stable before `1.0.0`.

#![forbid(unsafe_code)]

#[cfg(feature = "vault")]
pub mod account;
pub mod binding;
pub mod crypto;
pub mod encoding;
pub mod error;
pub mod file;
pub mod id;
pub mod json;
pub mod keys;
pub mod log;
pub mod messages;
pub mod profile;
pub mod proof;
pub mod recovery;
pub mod testing;
pub mod vault;

pub use binding::{API_VERSION, check_base_url};
pub use error::{Error, Result};
pub use json::{Map, Value, canonical, parse_json};

/// Version of the wire and storage format described by the specification.
pub const FORMAT_VERSION: u32 = 1;

/// Prefix of every domain-separation label (`rootcard/<purpose>/v<n>`).
pub const LABEL_PREFIX: &str = "rootcard/";

/// Build a domain-separation label for `purpose` at format version `version`, e.g. `rootcard/id/v1`.
pub fn label(purpose: &str, version: u32) -> String {
    format!("{LABEL_PREFIX}{purpose}/v{version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_prefixed_and_versioned() {
        assert_eq!(label("id", FORMAT_VERSION), "rootcard/id/v1");
        assert!(label("event", 2).starts_with(LABEL_PREFIX));
    }
}
