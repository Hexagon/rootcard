//! Log verification ([LOG-*], [VER-*]) on any JSON: `verify_log`, `verify_pending`, `compare_logs` and
//! `LogState::from_value` never panic, and an accepted log keeps the invariants of `rootcard_fuzz::check_accepted`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rootcard::json::{Value, parse_json};
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
    // The last event as a pending one ([LOG-9]) on the state before it.
    if let Some((last, before)) = events.split_last()
        && let Ok(prior) = verify_log(before, &options)
    {
        let _ = verify_pending(&prior, last, state.time);
        // Without its receipt, a completed instance is a valid pending one.
        if let Some(m) = last.as_object()
            && let Some(Value::Array(sigs)) = m.get("sigs")
            && let Some((_, owners)) = sigs.split_last()
        {
            let mut pending = m.clone();
            pending.insert("sigs", Value::Array(owners.to_vec()));
            let _ = verify_pending(&prior, &Value::Object(pending), state.time);
        }
    }
});
