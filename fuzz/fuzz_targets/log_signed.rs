//! Log verification behind the signatures: the first byte chooses what the re-signer recomputes (`account`, `prev`,
//! signatures; see `rootcard_fuzz::resign`), the rest is a JSON array of events. Signed with keys the fuzz crate knows,
//! the events reach the checks on kinds, sequence, keys, reasons, receipts, rotations and retirement.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rootcard::json::parse_json;
use rootcard::log::{VerifyOptions, verify_log};
use rootcard_fuzz::resign;

fuzz_target!(|data: &[u8]| {
    let Some((&control, json)) = data.split_first() else {
        return;
    };
    let Ok(v) = parse_json(json) else { return };
    let Some(events) = v.as_array() else { return };
    let events = resign(events, control);
    let options = VerifyOptions::new(["global", "example"]);
    if let Ok(state) = verify_log(&events, &options) {
        rootcard_fuzz::check_accepted(&events, &state, &options);
    }
});
