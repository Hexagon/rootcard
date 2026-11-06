//! The signed documents and the files a user hands to a tool: the first byte chooses the verifier, the rest is the JSON
//! document. The logs, challenges and recipients they are checked against come from the shared vectors, so a mutated
//! valid document reaches every check up to its signature. None of them panics.
//!
//! 0 `verify_public` ([PRO-*]), 1 `verify_vault` ([VLT-*], [LCK-*]), 2 `vault_change` ([CHG-*]), 3 `import_account`
//! ([FIL-*]), 4 `read_card` and `card_text`, 5 `verify_proof` ([PRF-*]), 6 `well_known_base` ([HST-23]),
//! 7 statements, challenges, login requests and vault contents ([VLT-7]).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rootcard::encoding::hex_decode;
use rootcard::file::{card_text, import_account, read_card};
use rootcard::json::{Value, parse_json};
use rootcard::log::{LogState, VerifyOptions, verify_log};
use rootcard::messages::{Challenge, LoginRequest};
use rootcard::profile::verify_public;
use rootcard::proof::{statement_challenge, verify_proof};
use rootcard::vault::{Contents, vault_change, verify_vault};
use rootcard::well_known_base;
use rootcard_fuzz::{accepted, input_array, input_str};
use std::sync::OnceLock;

fn options() -> VerifyOptions {
    VerifyOptions::new(["global", "example"])
}

fn state_of(op: &str, name: &str) -> Option<LogState> {
    verify_log(input_array(accepted(op)?, name), &options()).ok()
}

fn profile_state() -> Option<&'static LogState> {
    static S: OnceLock<Option<LogState>> = OnceLock::new();
    S.get_or_init(|| state_of("verify_public", "events")).as_ref()
}

fn vault_state() -> Option<&'static LogState> {
    static S: OnceLock<Option<LogState>> = OnceLock::new();
    S.get_or_init(|| state_of("verify_vault", "events")).as_ref()
}

fn valid_vault() -> Option<&'static Value> {
    accepted("verify_vault")?.input.get("vault")
}

fuzz_target!(|data: &[u8]| {
    let Some((&op, json)) = data.split_first() else { return };
    let Ok(doc) = parse_json(json) else { return };
    match op % 8 {
        0 => {
            if let Some(state) = profile_state() {
                let _ = verify_public(&doc, state);
            }
        }
        1 => {
            if let Some(state) = vault_state() {
                let _ = verify_vault(&doc, state);
            }
        }
        2 => {
            if let Value::Array(pair) = &doc
                && let [old, new] = pair.as_slice()
            {
                let _ = vault_change(old, new);
            }
            if let Some(valid) = valid_vault() {
                let _ = vault_change(valid, &doc);
                let _ = vault_change(&doc, valid);
            }
        }
        3 => {
            let _ = import_account(&doc, &options());
        }
        4 => {
            if read_card(&doc).is_ok() {
                let _ = card_text(&doc);
            }
        }
        5 => {
            let Some(v) = accepted("verify_proof") else { return };
            let challenge = hex_decode(input_str(v, "challenge"))
                .ok()
                .and_then(|c| <[u8; 32]>::try_from(c).ok());
            if let Some(challenge) = challenge {
                let _ = verify_proof(
                    &doc,
                    input_array(v, "log"),
                    &challenge,
                    input_str(v, "recipient"),
                    &options(),
                );
            }
        }
        6 => {
            for origin in [
                "https://example.com",
                "http://localhost:8080",
                "https://example.com:8443",
            ] {
                if let Ok(base) = well_known_base(origin, &doc) {
                    // The same origin; the host compared without regard to ASCII case, as [HST-23] says.
                    let head = base.get(..origin.len()).unwrap_or("");
                    let same = head.eq_ignore_ascii_case(origin)
                        && (base.len() == origin.len() || base[origin.len()..].starts_with('/'));
                    assert!(same, "a host pointer resolved to another origin: {origin} -> {base}");
                    assert!(
                        rootcard::check_base_url(&base).is_ok(),
                        "a host pointer resolved to a bad base URL"
                    );
                }
            }
        }
        _ => {
            let _ = statement_challenge(&doc);
            let _ = Challenge::from_value(&doc);
            let _ = LoginRequest::from_value(&doc);
            if let Ok(c) = Contents::from_bytes(json) {
                let again = Contents::from_value(&c.to_value());
                assert!(again.is_ok(), "vault contents do not survive their own serialization");
            }
        }
    }
});
