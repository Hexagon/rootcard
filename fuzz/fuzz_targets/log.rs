//! Log verification ([LOG-*], [VER-*]) on any JSON: `verify_log`, `verify_pending`, `compare_logs` and
//! `LogState::from_value` never panic, and an accepted log keeps the invariants of `rootcard_fuzz::check_accepted`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rootcard::json::parse_json;
use rootcard::log::{LogState, VerifyOptions, compare_logs, verify_log, verify_pending};

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse_json(data) else { return };
    let _ = LogState::from_value(&v);
    let Some(events) = v.as_array() else { return };
    // Two logs in one input: the first half against the whole.
    let _ = compare_logs(&events[..events.len() / 2], events);
    let options = VerifyOptions::new(["global", "example"]);
    let Ok(state) = verify_log(events, &options) else {
        return;
    };
    rootcard_fuzz::check_accepted(events, &state, &options);
    if let Some(last) = events.last() {
        let _ = verify_pending(&state, last, state.time);
    }
});
