//! # rootcard
//!
//! A portable, self-certifying identity for online logins. This crate is the core: formats, verification, the vault and
//! proofs. It is pure: it does no I/O, reads no clock and draws no randomness itself. Time and random bytes are passed in.
//!
//! The normative format is `spec/SPEC.md` in the repository, and `spec/vectors/` holds the shared test vectors that this
//! crate and the npm package must both reproduce.
//!
//! Status: skeleton (phase 0). Nothing here is stable.

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
