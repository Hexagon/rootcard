//! # rootcard-host
//!
//! Host-side helpers for [`rootcard`] identities: single-use login challenges, an identity store trait and request
//! handlers that are independent of any HTTP framework.
//!
//! Status: skeleton (phase 0). The real API arrives in phase 5 of the plan.

/// The format version this host crate speaks, re-exported from the core.
pub const FORMAT_VERSION: u32 = rootcard::FORMAT_VERSION;

#[cfg(test)]
mod tests {
    #[test]
    fn speaks_the_core_format() {
        assert_eq!(super::FORMAT_VERSION, rootcard::FORMAT_VERSION);
    }
}
