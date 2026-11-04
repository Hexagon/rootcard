//! The recommended HTTP binding (docs/HOST_PROTOCOL.md) as a framework-independent router: a request in, a response
//! out. An application wires [`route`] into its HTTP server; `examples/host` does it with the standard library.

use crate::peer::{PeerHeaders, verify_peer_request};
use crate::store::{ChallengeStore, IdentityStore, SessionStore};
use crate::{Host, HostError, HostResult};
use rootcard::Error;
use rootcard::json::{Map, Value, canonical, parse_json};
use rootcard::messages::Purpose;

/// The largest request body, checked before parsing (HOST_PROTOCOL.md §1).
pub const MAX_BODY: usize = 6 * 1024 * 1024;

/// An HTTP request.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// `GET`, `POST`, `PUT`, `OPTIONS`.
    pub method: String,
    /// The path relative to the base URL, with the query (`/id/lookup?handle=…`).
    pub path: String,
    /// The bearer token of `Authorization: Bearer <token>`, if any.
    pub bearer: Option<String>,
    /// The peer headers, if any.
    pub peer: Option<PeerHeaders>,
    /// The body.
    pub body: Vec<u8>,
}

/// An HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The JSON body (canonical), if any.
    pub body: Option<Vec<u8>>,
    /// Extra headers (`Cache-Control`, `Content-Disposition`, CORS).
    pub headers: Vec<(String, String)>,
}

impl Response {
    fn json(status: u16, v: &Value) -> Response {
        Response {
            status,
            body: Some(canonical(v)),
            headers: Vec::new(),
        }
    }

    fn no_store(mut self) -> Response {
        self.headers.push(("Cache-Control".into(), "no-store".into()));
        self
    }

    fn cors(mut self, peer: bool) -> Response {
        if !peer {
            self.headers.push(("Access-Control-Allow-Origin".into(), "*".into()));
            self.headers.push((
                "Access-Control-Allow-Headers".into(),
                "Authorization, Content-Type".into(),
            ));
            self.headers
                .push(("Access-Control-Allow-Methods".into(), "GET, POST, PUT, OPTIONS".into()));
        }
        self
    }
}

fn error(e: &HostError) -> Response {
    Response::json(e.status(), &e.to_value())
}

fn decode_component(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query(q: &str, name: &str) -> Option<String> {
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == name).then(|| decode_component(v))
    })
}

fn body(req: &Request) -> HostResult<Value> {
    if req.body.len() > MAX_BODY {
        return Err(Error::TooLarge.into());
    }
    Ok(parse_json(&req.body)?)
}

/// Route a request to the handlers of `host`. `now` is the host's clock ([HST-21]); `random` fills buffers from a
/// secure generator (challenge nonces and session tokens).
pub fn route<S: IdentityStore, C: ChallengeStore, T: SessionStore>(
    host: &Host<S, C, T>,
    req: &Request,
    now: i64,
    random: &mut dyn FnMut(&mut [u8]),
) -> Response {
    let (path, q) = req.path.split_once('?').unwrap_or((req.path.as_str(), ""));
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let is_peer = parts.first() == Some(&"peer");
    if req.method == "OPTIONS" {
        return Response {
            status: 204,
            body: None,
            headers: Vec::new(),
        }
        .cors(is_peer);
    }
    let bearer = || {
        req.bearer
            .as_deref()
            .ok_or_else(|| HostError::from(Error::Unauthorized))
    };
    let mut draw = || {
        let mut b = [0u8; 32];
        random(&mut b);
        b
    };
    let ok = |v: HostResult<Value>| v.map(|v| Response::json(200, &v));
    let result: HostResult<Response> = match (req.method.as_str(), parts.as_slice()) {
        ("GET", ["host"]) => Ok(Response::json(200, &host.descriptor())),
        ("GET", ["id", "lookup"]) => match query(q, "handle") {
            Some(h) => ok(host.lookup(query(q, "realm").as_deref(), &h)),
            None => Err(Error::BadHandle.into()),
        },
        ("POST", ["id", "register"]) => body(req)
            .and_then(|b| host.register(&b, now))
            .map(|v| Response::json(201, &v)),
        ("GET", ["id", a, "log"]) => {
            let from = query(q, "from").and_then(|f| f.parse::<usize>().ok()).unwrap_or(0);
            ok(host.log(a, from))
        }
        ("GET", ["id", a, "public"]) => ok(host.public(a)),
        ("POST", ["id", a, "events"]) => body(req).and_then(|b| ok(host.events(a, &b, now))),
        ("POST", ["id", a, "instance"]) => body(req)
            .and_then(|b| host.instance(a, &b, now))
            .map(|v| Response::json(201, &v)),
        ("GET", ["id", a, "locks"]) => ok(host.locks(a)).map(Response::no_store),
        ("POST", ["id", a, "challenge"]) => body(req)
            .and_then(|b| {
                let p = b
                    .as_object()
                    .and_then(|m| m.get("purpose"))
                    .and_then(Value::as_str)
                    .ok_or(Error::BadField)?;
                Ok(Purpose::parse(p)?)
            })
            .and_then(|p| ok(host.challenge(a, p, now, draw())))
            .map(Response::no_store),
        ("POST", ["id", a, "fetch"]) => body(req)
            .and_then(|b| ok(host.fetch(a, &b, now)))
            .map(Response::no_store),
        ("PUT", ["id", a, "vault"]) => body(req).and_then(|b| ok(host.put_vault(a, &b))),
        ("POST", ["id", a, "login"]) => body(req)
            .and_then(|b| ok(host.login(a, &b, now, draw())))
            .map(Response::no_store),
        ("POST", ["session", "logout"]) => bearer().and_then(|t| host.logout(t)).map(|_| Response {
            status: 204,
            body: None,
            headers: Vec::new(),
        }),
        ("GET", ["session", "vault"]) => bearer()
            .and_then(|t| ok(host.session_vault(t, now)))
            .map(Response::no_store),
        ("PUT", ["session", "vault"]) => {
            bearer().and_then(|t| body(req).and_then(|b| ok(host.session_put_vault(t, &b, now))))
        }
        ("POST", ["session", "password"]) => {
            bearer().and_then(|t| body(req).and_then(|b| ok(host.session_password(t, &b, now))))
        }
        ("PUT", ["session", "public"]) => {
            bearer().and_then(|t| body(req).and_then(|b| ok(host.session_put_public(t, &b, now))))
        }
        ("GET", ["session", "export"]) => bearer().and_then(|t| host.session_export(t, now)).map(|(name, file)| {
            let mut r = Response::json(200, &file).no_store();
            r.headers
                .push(("Content-Disposition".into(), format!("attachment; filename=\"{name}\"")));
            r
        }),
        (m @ ("GET" | "POST"), ["peer", what]) => {
            let headers = req.peer.as_ref().ok_or_else(|| HostError::from(Error::Unauthorized));
            headers
                .and_then(|h| {
                    verify_peer_request(h, &host.config.peers, &host.config.key(), m, &req.path, &req.body, now)
                        .map_err(HostError::from)
                })
                .and_then(|_| match (m, *what) {
                    ("POST", "push") => body(req).and_then(|b| ok(host.peer_push(&b, now))),
                    ("GET", "changes") => {
                        let since = query(q, "since").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                        ok(host.peer_changes(since))
                    }
                    _ => Err(not_found()),
                })
        }
        _ => Err(not_found()),
    };
    match result {
        Ok(r) => r.cors(is_peer),
        Err(e) => error(&e).cors(is_peer),
    }
}

fn not_found() -> HostError {
    HostError {
        error: Error::UnknownAccount,
        extra: Map::new().with("message", "no such endpoint"),
        storage: None,
    }
}
