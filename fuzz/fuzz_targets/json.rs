//! Canonical JSON (SPEC §2): the parser never panics, and what it accepts serializes to a canonical form that parses
//! back to the same value and serializes to the same bytes ([CJ-1]–[CJ-9]).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rootcard::json::{canonical, parse_json, parse_limited};

fuzz_target!(|data: &[u8]| {
    let _ = parse_limited(data, 64);
    let Ok(v) = parse_json(data) else { return };
    let bytes = canonical(&v);
    let again = parse_json(&bytes);
    assert_eq!(
        again.as_ref(),
        Ok(&v),
        "canonical output does not parse back to the same value"
    );
    assert_eq!(canonical(&v), bytes, "canonical output is not stable");
    assert!(v.validate().is_ok(), "a parsed value fails validation");
});
