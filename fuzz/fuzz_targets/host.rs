//! The host's HTTP router (`rootcard_host::http::route`, HOST_PROTOCOL.md) with its in-memory stores: up to 16 requests
//! per input, separated by `\n\0\n`, each a line `METHOD PATH [bearer=<token>] [peer=<key>,<time>,<sig>]` and a body
//! (see `rootcard_fuzz::parse_request`). The host keeps its state across the requests of one input, so a pushed log
//! can be looked up, challenged and logged in to. The router never panics, answers every request with a status of
//! HOST_PROTOCOL.md, and every body it sends is canonical JSON.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rootcard::json::{canonical, parse_json};
use rootcard_fuzz::{Counter, HOST_NOW, fuzz_host, requests};
use rootcard_host::http::{MAX_BODY, route};

fuzz_target!(|data: &[u8]| {
    let h = fuzz_host();
    let mut random = Counter::new();
    for (i, req) in requests(data).into_iter().enumerate() {
        if req.body.len() > MAX_BODY {
            continue;
        }
        let now = HOST_NOW + 10 * i as i64;
        let res = route(&h, &req, now, &mut |b| random.fill(b));
        assert!(
            [200, 201, 204, 400, 401, 403, 404, 409, 410, 413, 429].contains(&res.status),
            "unexpected status {} for {} {}",
            res.status,
            req.method,
            req.path
        );
        if let Some(body) = &res.body {
            let v = parse_json(body);
            assert!(v.is_ok(), "the router sent a body that does not parse");
            if let Ok(v) = v {
                assert_eq!(&canonical(&v), body, "the router sent a body that is not canonical");
            }
        }
    }
});
