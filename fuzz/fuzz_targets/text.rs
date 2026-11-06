//! Text formats: the encodings (SPEC §3) and the parsers and checks of names, keys, handles and addresses. None of them
//! panics; decoders that accept round-trip through their encoders.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rootcard::encoding::{
    base32_decode, base32_decode_lenient, base32_encode, base32_normalize, base64url_decode, base64url_encode,
    hex_decode, hex_encode,
};
use rootcard::id::{check_account_id, check_realm, check_username, default_username_policy, parse_handle};
use rootcard::keys::{KeyType, format_key, parse_key};
use rootcard::log::check_url;
use rootcard::profile::{check_app_name, check_data_key};
use rootcard::recovery::{format_recovery_key, parse_recovery_key};
use rootcard::vault::check_label;
use rootcard::{check_base_url, is_origin};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    if let Ok(b) = base64url_decode(s) {
        assert_eq!(base64url_encode(&b), s, "base64url is not canonical");
    }
    if let Ok(b) = hex_decode(s) {
        assert_eq!(hex_encode(&b), s.to_ascii_lowercase(), "hex round trip");
    }
    for len in [2usize, 16, 32] {
        if let Ok(b) = base32_decode(s, len) {
            assert_eq!(b.len(), len);
            assert_eq!(base32_encode(&b), s, "base32 is not canonical");
            assert_eq!(
                base32_decode_lenient(s, len).as_ref(),
                Ok(&b),
                "lenient decoding rejects strict input"
            );
        }
        if let Ok(b) = base32_decode_lenient(s, len) {
            assert_eq!(
                base32_decode_lenient(&base32_normalize(s), len).as_ref(),
                Ok(&b),
                "normalizing twice"
            );
        }
    }
    if let Ok(k) = parse_recovery_key(s) {
        assert_eq!(
            parse_recovery_key(&format_recovery_key(&k)).as_deref(),
            Ok(&*k),
            "recovery key round trip"
        );
    }
    for t in [KeyType::Ed25519, KeyType::X25519] {
        if let Ok(k) = parse_key(s, t) {
            assert_eq!(format_key(t, &k), s, "key format is not canonical");
        }
    }
    let _ = parse_handle(s);
    let _ = check_account_id(s);
    let _ = check_realm(s);
    if check_username(s).is_ok() {
        let _ = default_username_policy(s);
    }
    let _ = check_url(s);
    if is_origin(s) {
        assert!(check_base_url(s).is_ok(), "an origin that is not a base URL");
    }
    let _ = check_data_key(s);
    let _ = check_app_name(s);
    let _ = check_label(s);
});
