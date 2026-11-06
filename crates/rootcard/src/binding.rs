//! The HTTP binding's version and base URLs (HOST_PROTOCOL.md §1, §1.3; SPEC [HST-22]). The core makes no requests;
//! these let hosts, clients and the key tool agree on where endpoints live.

use crate::json::Value;
use crate::keys::schema;
use crate::log::check_url;
use crate::{Error, Result};

/// The version segment of the HTTP binding: every endpoint is under `<base URL>/v0` until 1.0.0, then under `/v1`.
/// It is never part of a base URL, `home.url` or anything signed.
pub const API_VERSION: &str = "v0";

/// Check a base URL ([HST-22]): `https://` and a host, an optional port and an optional path without a trailing
/// slash, query, fragment or user info; plain `http://` only for `localhost`, `127.0.0.1` and `[::1]`; and its last path
/// segment is not an API version segment (`v` followed by digits). → `bad_field`
pub fn check_base_url(url: &str) -> Result<()> {
    check_url(url)?;
    let rest = if let Some(r) = url.strip_prefix("https://") {
        r
    } else if let Some(r) = url.strip_prefix("http://") {
        let host = authority_host(r);
        if !["localhost", "127.0.0.1", "[::1]"].contains(&host) {
            return Err(Error::BadField);
        }
        r
    } else {
        return Err(Error::BadField);
    };
    if rest.contains(['?', '#', '@', '\\']) {
        return Err(Error::BadField);
    }
    let (authority, path) = rest.split_once('/').map_or((rest, None), |(a, p)| (a, Some(p)));
    if authority_host(authority).is_empty() || !authority.bytes().all(authority_byte) {
        return Err(Error::BadField);
    }
    if let Some(path) = path {
        let segments: Vec<&str> = path.split('/').collect();
        if segments.iter().any(|s| !is_path_segment(s)) {
            return Err(Error::BadField);
        }
        if segments.last().is_some_and(|s| is_version_segment(s)) {
            return Err(Error::BadField);
        }
    }
    Ok(())
}

/// The well-known path of a host pointer ([HST-23], RFC 8615), at the root of an origin. It carries no API version: the
/// pointer lists the versions the host serves.
pub const WELL_KNOWN_PATH: &str = "/.well-known/rootcard";

/// The largest host pointer a client reads, in bytes ([HST-23]); pass it to [`crate::json::parse_limited`].
pub const WELL_KNOWN_LIMIT: usize = 4096;

/// The most API versions a host pointer may list ([HST-23]).
pub const MAX_WELL_KNOWN_APIS: usize = 16;

/// Whether a base URL ([HST-22]) is an origin: a base URL without a path. Only an origin is resolved through
/// [`WELL_KNOWN_PATH`] ([HST-23]); an address with a path is already a base URL.
pub fn is_origin(url: &str) -> bool {
    check_base_url(url).is_ok() && !url.split_once("://").is_some_and(|(_, rest)| rest.contains('/'))
}

/// Resolve a host pointer ([HST-23]): the document served at `<origin>/.well-known/rootcard`, which names the host's
/// base URL on that origin. `origin` is the address the client fetched it from, as the user typed it, never a value
/// received. Checks, in order: `origin` is an origin ([`is_origin`]) → `bad_field`; the schema
/// `{ "v": 1, "base", "api" }` ([CJ-11], [CJ-12]) → `bad_field`, `unsupported_version`; `base` is a base URL
/// ([HST-22]) and `api` is 1 to 16 distinct API version segments → `bad_field`; `base` is on `origin` (the same scheme,
/// host and port, the host compared without regard to ASCII case) → `wrong_host`; `api` lists [`API_VERSION`] →
/// `unsupported_version`. Returns `base`, the address to use and to put into an instance's `home.url`.
pub fn well_known_base(origin: &str, document: &Value) -> Result<String> {
    if !is_origin(origin) {
        return Err(Error::BadField);
    }
    let m = schema::obj(document)?;
    schema::version(m)?;
    schema::members(m, &["v", "base", "api"], &[])?;
    let base = schema::string(m, "base")?;
    check_base_url(base)?;
    let api = schema::array(m, "api")?;
    if api.is_empty() || api.len() > MAX_WELL_KNOWN_APIS {
        return Err(Error::BadField);
    }
    let mut versions: Vec<&str> = Vec::with_capacity(api.len());
    for v in api {
        let v = v.as_str().ok_or(Error::BadField)?;
        if !is_version_segment(v) || versions.contains(&v) {
            return Err(Error::BadField);
        }
        versions.push(v);
    }
    let base_origin = base.find("://").map_or(base, |i| {
        let start = i + 3;
        base[start..].find('/').map_or(base, |j| &base[..start + j])
    });
    if !base_origin.eq_ignore_ascii_case(origin) {
        return Err(Error::WrongHost);
    }
    if !versions.contains(&API_VERSION) {
        return Err(Error::UnsupportedVersion);
    }
    Ok(base.to_string())
}

/// Whether a base URL path segment is allowed ([HST-22]): non-empty, only unreserved characters (no percent-encoding),
/// and not a dot segment.
fn is_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// Whether a path segment has the form of an API version (`v0`, `V12`).
pub fn is_version_segment(segment: &str) -> bool {
    let b = segment.as_bytes();
    b.len() >= 2 && (b[0] == b'v' || b[0] == b'V') && b[1..].iter().all(u8::is_ascii_digit)
}

fn authority_host(rest: &str) -> &str {
    let authority = rest.split('/').next().unwrap_or("");
    if authority.starts_with('[') {
        authority.find(']').map_or("", |i| &authority[..=i])
    } else {
        authority.split(':').next().unwrap_or("")
    }
}

fn authority_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse_json;

    fn doc(s: &str) -> Value {
        parse_json(s.as_bytes()).unwrap()
    }

    #[test]
    fn origins() {
        assert!(is_origin("https://example.com"));
        assert!(is_origin("http://127.0.0.1:8787"));
        assert!(!is_origin("https://example.com/rootcard"));
        assert!(!is_origin("https://example.com/"));
        assert!(!is_origin("example.com"));
    }

    #[test]
    fn well_known() {
        let ok = |o: &str, d: &str| well_known_base(o, &doc(d));
        assert_eq!(
            ok(
                "https://example.com",
                r#"{"v":1,"base":"https://example.com/rootcard","api":["v0"]}"#
            ),
            Ok("https://example.com/rootcard".into())
        );
        assert_eq!(
            ok(
                "https://Example.COM",
                r#"{"v":1,"base":"https://example.com","api":["v1","v0"]}"#
            ),
            Ok("https://example.com".into())
        );
        for (o, d, e) in [
            (
                "https://example.com/x",
                r#"{"v":1,"base":"https://example.com/x","api":["v0"]}"#,
                Error::BadField,
            ),
            (
                "https://example.com",
                r#"{"v":2,"base":"https://example.com/x","api":["v0"]}"#,
                Error::UnsupportedVersion,
            ),
            (
                "https://example.com",
                r#"{"v":1,"base":"https://example.com/x"}"#,
                Error::BadField,
            ),
            (
                "https://example.com",
                r#"{"v":1,"base":"https://example.com/x","api":["v0"],"x":1}"#,
                Error::BadField,
            ),
            (
                "https://example.com",
                r#"{"v":1,"base":"https://example.com/v0","api":["v0"]}"#,
                Error::BadField,
            ),
            (
                "https://example.com",
                r#"{"v":1,"base":"https://example.com/x","api":[]}"#,
                Error::BadField,
            ),
            (
                "https://example.com",
                r#"{"v":1,"base":"https://example.com/x","api":["v0","v0"]}"#,
                Error::BadField,
            ),
            (
                "https://example.com",
                r#"{"v":1,"base":"https://example.com/x","api":["0"]}"#,
                Error::BadField,
            ),
            (
                "https://example.com",
                r#"{"v":1,"base":"https://evil.example/x","api":["v0"]}"#,
                Error::WrongHost,
            ),
            (
                "https://example.com",
                r#"{"v":1,"base":"https://example.com:8443/x","api":["v0"]}"#,
                Error::WrongHost,
            ),
            (
                "https://example.com",
                r#"{"v":1,"base":"https://example.com.evil/x","api":["v0"]}"#,
                Error::WrongHost,
            ),
            (
                "https://example.com",
                r#"{"v":1,"base":"https://example.com/x","api":["v1"]}"#,
                Error::UnsupportedVersion,
            ),
        ] {
            assert_eq!(ok(o, d), Err(e), "{o} {d}");
        }
    }

    #[test]
    fn base_urls() {
        for ok in [
            "https://id.example.com",
            "https://example.com/rootcard",
            "https://api.example.com:8443/auth/rootcard",
            "https://example.com/v0x",
            "https://example.com/v",
            "http://127.0.0.1:8787",
            "http://localhost:8787/rootcard",
            "http://[::1]:8787",
        ] {
            assert_eq!(check_base_url(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "id.example.com",
            "ftp://example.com",
            "http://example.com",
            "http://localhost.example.com",
            "https://",
            "https://example.com/",
            "https://example.com//rootcard",
            "https://example.com/v0",
            "https://example.com/rootcard/V12",
            "https://example.com/rootcard?x=1",
            "https://example.com#top",
            "https://user@example.com",
            "https://exa mple.com",
        ] {
            assert_eq!(check_base_url(bad), Err(Error::BadField), "{bad}");
        }
    }
}
